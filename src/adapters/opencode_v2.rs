//! OpenCode 2.x projected transcripts. Native table ownership is chosen by opencode.rs.
use std::collections::{HashMap, HashSet};

use rusqlite::{Connection, params_from_iter};
use serde_json::Value;
use tracing::warn;

use super::{RawMessage, RawSessionEvent, RawUsageEvent, Role, ScanOptions};

#[derive(Default)]
pub(super) struct SessionData {
    pub messages: HashMap<String, Vec<RawMessage>>,
    pub usage: HashMap<String, Vec<RawUsageEvent>>,
    pub events: HashMap<String, Vec<RawSessionEvent>>,
}

pub(super) fn load_chunk(
    conn: &Connection,
    session_ids: &[String],
    include_events: bool,
    directories: &HashMap<String, String>,
    legacy_tails: &HashMap<String, i64>,
) -> anyhow::Result<SessionData> {
    let placeholders = std::iter::repeat_n("?", session_ids.len()).collect::<Vec<_>>().join(", ");
    let mut stmt = conn.prepare(&format!(
        "SELECT session_id, id, type, data, time_created FROM session_message
         WHERE session_id IN ({placeholders}) ORDER BY session_id, seq, id"
    ))?;
    let rows = stmt.query_map(params_from_iter(session_ids.iter()), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            super::sqlite_millis(row, 4)?,
        ))
    })?;
    let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    let mut cwd: HashMap<String, Option<String>> =
        directories.iter().map(|(sid, dir)| (sid.clone(), Some(dir.clone()))).collect();
    // The stored session directory is the final location. Recover the earlier
    // location from the first switch before attributing historical file paths.
    let mut first_switch = HashSet::new();
    for (sid, _, kind, encoded, _) in &rows {
        if kind == "location-switched" && first_switch.insert(sid.clone()) {
            let previous = serde_json::from_str::<Value>(encoded).ok().and_then(|value| {
                value
                    .pointer("/previous/location/directory")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
            cwd.insert(sid.clone(), previous);
        }
    }
    let mut result = SessionData::default();
    for row in rows {
        let (sid, id, kind, encoded, timestamp) = row;
        // A location switch only updates the cwd map, so it must run even when
        // it sits inside the copied prefix: post-upgrade tool events keep the
        // directory the copy recorded.
        if kind == "location-switched" {
            if let Ok(data) = serde_json::from_str::<Value>(&encoded) {
                cwd.insert(
                    sid,
                    data.pointer("/location/directory").and_then(Value::as_str).map(str::to_string),
                );
            }
            continue;
        }
        // In a mixed-schema session the V2 copy duplicates legacy history and
        // can lose tokens and patch events; only accept rows that continue it.
        if let Some(tail) = legacy_tails.get(&sid)
            && timestamp.is_none_or(|ts| ts <= *tail)
        {
            continue;
        }
        let data: Value = match serde_json::from_str(&encoded) {
            Ok(value) => value,
            Err(error) => {
                warn!(message_id = %id, %error, "skipping malformed OpenCode v2 message");
                continue;
            }
        };
        let messages = result.messages.entry(sid.clone()).or_default();
        for text in visible_text(&kind, &data) {
            messages.push(RawMessage {
                role: if kind == "user" { Role::User } else { Role::Assistant },
                content: text.to_string(),
                timestamp,
            });
        }
        if kind != "assistant" && kind != "compaction" {
            continue;
        }
        if data.get("tokens").is_some_and(Value::is_object) {
            let normalized = serde_json::json!({
                "tokens": data["tokens"],
                "modelID": data.pointer("/model/id"),
                "providerID": data.pointer("/model/providerID"),
            });
            let usage = result.usage.entry(sid.clone()).or_default();
            if let Some(event) = super::parse_usage_event(
                &id,
                &normalized.to_string(),
                timestamp.unwrap_or(0),
                usage.len() as u32,
            ) {
                usage.push(event);
            }
        }
        if include_events && kind == "assistant" {
            let directory = cwd.get(&sid).and_then(|value| value.as_deref());
            let events = result.events.entry(sid).or_default();
            for (index, tool) in data
                .get("content")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
                .filter(|(_, item)| item.get("type").and_then(Value::as_str) == Some("tool"))
            {
                let Some(mut state) = tool.get("state").and_then(Value::as_object).cloned() else {
                    warn!(message_id = %id, "skipping OpenCode v2 tool without state");
                    continue;
                };
                if let Some(content) = state.get("content").and_then(Value::as_array) {
                    let output = content
                        .iter()
                        .filter(|item| item.get("type").and_then(Value::as_str) == Some("text"))
                        .filter_map(|item| item.get("text").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join("\n");
                    state.insert("output".to_string(), Value::String(output));
                }
                let part = serde_json::json!({
                    "type":"tool", "tool":tool.get("name"), "callID":tool.get("id"), "state":state,
                });
                // Include the message identity: tool-call IDs are not session-global.
                let part_id = format!("v2:{id}:{index}");
                events.extend(super::parse_part_events(
                    &part_id,
                    &part.to_string(),
                    timestamp,
                    events.len() as u32,
                    conn.path().filter(|path| !path.is_empty()),
                    &id,
                    directory,
                    ScanOptions::OPENCODE_NATIVE,
                ));
            }
        }
    }
    Ok(result)
}

fn visible_text<'a>(kind: &str, data: &'a Value) -> Vec<&'a str> {
    let texts = match kind {
        "user" => data.get("text").and_then(Value::as_str).into_iter().collect(),
        "assistant" => data
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|item| item.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|item| item.get("text").and_then(Value::as_str))
            .collect(),
        _ => Vec::new(),
    };
    texts.into_iter().filter(|text: &&str| !text.trim().is_empty()).collect()
}

pub(super) fn message_counts(
    conn: &Connection,
    session_ids: &[String],
    legacy_tails: &HashMap<String, i64>,
) -> anyhow::Result<HashMap<String, u32>> {
    // Use the same text projection as the loader, including malformed-message handling.
    let placeholders = std::iter::repeat_n("?", session_ids.len()).collect::<Vec<_>>().join(", ");
    let mut stmt = conn.prepare(&format!(
        "SELECT session_id, type, data, time_created FROM session_message
         WHERE session_id IN ({placeholders}) AND type IN ('user', 'assistant')"
    ))?;
    let rows = stmt.query_map(params_from_iter(session_ids.iter()), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            super::sqlite_millis(row, 3)?,
        ))
    })?;
    let mut counts = HashMap::new();
    for row in rows {
        let (sid, kind, encoded, timestamp) = row?;
        if let Some(tail) = legacy_tails.get(&sid)
            && timestamp.is_none_or(|ts| ts <= *tail)
        {
            continue;
        }
        if let Ok(data) = serde_json::from_str::<Value>(&encoded) {
            *counts.entry(sid).or_insert(0) += visible_text(&kind, &data).len() as u32;
        }
    }
    Ok(counts)
}
