use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde_json::Value;
use tracing::{debug, warn};

use crate::adapters::events::{self, EventContext};
use crate::adapters::json_util::json_i64;
use crate::adapters::opencode;
use crate::adapters::{
    AdapterSyncContext, InventoryIssue, RawMessage, RawSession, ReconcilePlan, ResumeCommand,
    SourceAdapter, SyncScanOutput, SyncScanResult,
};
use crate::types::{
    FileEvidence, FileOperation, ParentLink, ParentRelation, RawSessionEvent, RawUsageEvent, Role,
    ThreadRole,
};

const USAGE_PARSER_VERSION: u32 = 1;
const EVENT_PARSER_VERSION: u32 = 1;
const METADATA_PARSER_VERSION: u32 = 1;
const MS_THRESHOLD: i64 = 1_000_000_000_000;

pub(crate) struct DevinAdapter;

struct SessionRow {
    id: String,
    working_directory: String,
    title: Option<String>,
    model: Option<String>,
    backend_type: Option<String>,
    created_at: i64,
    last_activity_at: i64,
    hidden: i64,
}

struct MessageNode {
    node_id: i64,
    parent_node_id: Option<i64>,
    chat_message: String,
    dedupe_key: String,
    created_at: i64,
}

#[derive(Default)]
struct ParsedNodes {
    messages: Vec<RawMessage>,
    usage_events: Vec<RawUsageEvent>,
    events: Vec<RawSessionEvent>,
}

impl SourceAdapter for DevinAdapter {
    fn id(&self) -> &str {
        "devin"
    }

    fn label(&self) -> &str {
        "DV"
    }

    fn usage_parser_version(&self) -> Option<u32> {
        Some(USAGE_PARSER_VERSION)
    }

    fn resume_command(&self, source_id: &str) -> Option<ResumeCommand> {
        let session_id = source_id.split(':').next().unwrap_or(source_id);
        Some(ResumeCommand::new("devin", &["--resume", session_id]))
    }

    fn start_command(&self, prompt: String) -> Option<ResumeCommand> {
        Some(ResumeCommand { program: "devin".to_string(), args: vec!["--".to_string(), prompt] })
    }

    fn scan(&self) -> anyhow::Result<Vec<RawSession>> {
        Ok(scan_devin(resolve_db_path().as_deref(), None, None, true, false)?.scan.sessions)
    }

    fn scan_for_sync_output(
        &self,
        context: &AdapterSyncContext,
        since_ts: Option<i64>,
        include_events: bool,
        force: bool,
    ) -> anyhow::Result<Option<SyncScanOutput>> {
        Ok(Some(scan_devin(
            resolve_db_path().as_deref(),
            Some(context),
            since_ts,
            include_events,
            force,
        )?))
    }
}

fn resolve_db_path() -> Option<PathBuf> {
    resolve_db_path_from(std::env::var("XDG_DATA_HOME").ok(), dirs::home_dir())
}

fn resolve_db_path_from(xdg_data_home: Option<String>, home: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(xdg) = xdg_data_home.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(xdg).join("devin").join("cli").join("sessions.db"));
    }
    Some(home?.join(".local/share/devin/cli/sessions.db"))
}

fn has_table(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |row| row.get::<_, i64>(0),
    )
    .is_ok()
}

fn unavailable_scan(context: Option<&AdapterSyncContext>) -> SyncScanOutput {
    let scan = SyncScanResult::default();
    if context.is_some_and(AdapterSyncContext::has_existing_sessions) {
        return SyncScanOutput {
            scan,
            reconcile: Some(ReconcilePlan::UnavailableInventory(Vec::new())),
        };
    }
    SyncScanOutput { scan, reconcile: None }
}

fn load_live_ids(
    conn: &Connection,
    db_path: &Path,
) -> anyhow::Result<(HashSet<String>, Vec<InventoryIssue>)> {
    let mut live = HashSet::new();
    let mut issues = Vec::new();
    let mut stmt = conn.prepare("SELECT id FROM sessions WHERE hidden = 0")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    for row in rows {
        match row {
            Ok(id) => {
                live.insert(id);
            }
            Err(_) => issues.push(InventoryIssue {
                path: db_path.to_path_buf(),
                category: std::io::ErrorKind::InvalidData,
            }),
        }
    }
    if has_table(conn, "subagent_heads") {
        let mut stmt = conn.prepare(
            "SELECT sh.session_id || ':' || sh.agent_id
             FROM subagent_heads sh
             JOIN sessions s ON s.id = sh.session_id
             WHERE s.hidden = 0",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            match row {
                Ok(id) => {
                    live.insert(id);
                }
                Err(_) => issues.push(InventoryIssue {
                    path: db_path.to_path_buf(),
                    category: std::io::ErrorKind::InvalidData,
                }),
            }
        }
    }
    Ok((live, issues))
}

fn scan_devin(
    db_path: Option<&Path>,
    context: Option<&AdapterSyncContext>,
    since_ts: Option<i64>,
    include_events: bool,
    force: bool,
) -> anyhow::Result<SyncScanOutput> {
    let Some(db_path) = db_path else {
        return Ok(unavailable_scan(context));
    };
    let Some(conn) = opencode::open_readonly(db_path)? else {
        return Ok(unavailable_scan(context));
    };
    if !has_table(&conn, "sessions") || !has_table(&conn, "message_nodes") {
        debug!("Devin sessions.db missing required tables, skipping");
        return Ok(unavailable_scan(context));
    }

    let incremental = if force { None } else { context };
    let since_ts = if force { None } else { since_ts };
    let existing = incremental.map(AdapterSyncContext::session_meta);
    let usage_state = incremental.map(AdapterSyncContext::usage_state);
    let event_state = incremental.map(AdapterSyncContext::event_state);
    let metadata_state = incremental.map(AdapterSyncContext::metadata_state);
    let target = context.and_then(AdapterSyncContext::target_source_id);
    let target_session = target.map(|id| id.split(':').next().unwrap_or(id));

    let mut stats = crate::adapters::SyncScanStats::default();
    let mut sessions = Vec::new();

    let (live, inventory_issues) = match load_live_ids(&conn, db_path) {
        Ok(result) => result,
        Err(err) => {
            warn!("failed to inventory Devin sessions at {}: {err}", db_path.display());
            return Ok(unavailable_scan(context));
        }
    };
    let rows = match load_session_rows(&conn, target_session) {
        Ok(rows) => rows,
        Err(err) => {
            warn!("failed to read Devin sessions from {}: {err}", db_path.display());
            return Ok(unavailable_scan(context));
        }
    };

    for row in rows {
        stats.candidates += 1;
        if row.hidden != 0 {
            stats.filtered_sessions += 1;
            continue;
        }
        let started_at = seconds_to_ms(row.created_at);
        let updated_at = seconds_to_ms(row.last_activity_at);
        if since_ts.is_some_and(|cutoff| updated_at < cutoff) {
            stats.filtered_sessions += 1;
            continue;
        }
        if existing.is_some_and(|existing| {
            existing.get(&row.id).is_some_and(|old| {
                old.updated_at == Some(updated_at)
                    && crate::adapters::sync_state::session_state_is_current(
                        USAGE_PARSER_VERSION,
                        EVENT_PARSER_VERSION,
                        usage_state.and_then(|state| state.get(&row.id).copied()),
                        event_state.and_then(|state| state.get(&row.id).copied()),
                        Some(updated_at),
                        include_events,
                    )
                    && crate::adapters::sync_state::parser_state_is_current(
                        METADATA_PARSER_VERSION,
                        metadata_state.and_then(|state| state.get(&row.id).copied()),
                        Some(updated_at),
                    )
            })
        }) {
            stats.skipped_sessions += 1;
            continue;
        }
        match scan_session(&conn, &row, db_path, target, started_at, updated_at, include_events) {
            Ok(parsed) if !parsed.is_empty() => {
                stats.parsed += 1;
                sessions.extend(parsed);
            }
            Ok(_) => stats.filtered_sessions += 1,
            Err(err) => warn!("failed to parse Devin session {}: {err}", row.id),
        }
    }

    let reconcile = if inventory_issues.is_empty() {
        Some(ReconcilePlan::CompleteLiveSet(live))
    } else {
        Some(ReconcilePlan::PartialInventory(inventory_issues))
    };
    Ok(SyncScanOutput {
        scan: SyncScanResult { sessions, stats, observations: Vec::new() },
        reconcile,
    })
}

fn load_session_rows(conn: &Connection, target: Option<&str>) -> anyhow::Result<Vec<SessionRow>> {
    let mut stmt = conn.prepare(
        "SELECT s.id, s.working_directory, s.title, s.model, s.backend_type,
                s.created_at, s.hidden,
                MAX(
                    s.last_activity_at,
                    COALESCE(
                        (SELECT MAX(m.created_at) FROM message_nodes m WHERE m.session_id = s.id),
                        s.last_activity_at
                    )
                )
         FROM sessions s WHERE (?1 IS NULL OR s.id = ?1)",
    )?;
    let rows = stmt.query_map([target], |row| {
        Ok(SessionRow {
            id: row.get(0)?,
            working_directory: row.get(1)?,
            title: row.get(2)?,
            model: row.get(3)?,
            backend_type: row.get(4)?,
            created_at: row.get(5)?,
            hidden: row.get(6)?,
            last_activity_at: row.get(7)?,
        })
    })?;
    let mut sessions = Vec::new();
    for row in rows {
        match row {
            Ok(session) => sessions.push(session),
            Err(err) => warn!("skipping malformed Devin session row: {err}"),
        }
    }
    Ok(sessions)
}

fn load_message_nodes(conn: &Connection, session_id: &str) -> anyhow::Result<Vec<MessageNode>> {
    let mut stmt = conn.prepare(
        "SELECT node_id, parent_node_id, chat_message, created_at,
                COALESCE(
                    CASE WHEN json_valid(chat_message)
                        THEN NULLIF(json_extract(chat_message, '$.message_id'), '')
                    END,
                    'node:' || node_id
                )
         FROM message_nodes
         WHERE session_id = ?1
         ORDER BY node_id ASC",
    )?;
    let rows = stmt.query_map(rusqlite::params![session_id], |row| {
        Ok(MessageNode {
            node_id: row.get(0)?,
            parent_node_id: row.get(1)?,
            chat_message: row.get(2)?,
            created_at: row.get(3)?,
            dedupe_key: row.get(4)?,
        })
    })?;
    let mut nodes = Vec::new();
    for row in rows {
        match row {
            Ok(node) => nodes.push(node),
            Err(err) => warn!("skipping malformed Devin message node: {err}"),
        }
    }
    Ok(nodes)
}

fn load_subagent_heads(conn: &Connection, session_id: &str) -> Vec<(String, i64)> {
    let Ok(mut stmt) =
        conn.prepare("SELECT agent_id, chain_node_id FROM subagent_heads WHERE session_id = ?1")
    else {
        return Vec::new();
    };
    let rows = stmt.query_map(rusqlite::params![session_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    });
    match rows {
        Ok(rows) => rows.flatten().collect(),
        Err(err) => {
            warn!("failed to read Devin subagent heads for {session_id}: {err}");
            Vec::new()
        }
    }
}

fn chain_nodes(parents: &HashMap<i64, Option<i64>>, head: i64) -> HashSet<i64> {
    let mut set = HashSet::new();
    let mut current = Some(head);
    while let Some(id) = current {
        if !set.insert(id) {
            break;
        }
        current = parents.get(&id).copied().flatten();
    }
    set
}

fn scan_session(
    conn: &Connection,
    session: &SessionRow,
    db_path: &Path,
    target: Option<&str>,
    started_at: i64,
    updated_at: i64,
    include_events: bool,
) -> anyhow::Result<Vec<RawSession>> {
    let nodes = load_message_nodes(conn, &session.id)?;
    if nodes.is_empty() {
        return Ok(Vec::new());
    }
    let parents: HashMap<i64, Option<i64>> =
        nodes.iter().map(|node| (node.node_id, node.parent_node_id)).collect();
    let subagent_heads = load_subagent_heads(conn, &session.id);
    let subagent_sets: Vec<(String, HashSet<i64>)> = subagent_heads
        .iter()
        .map(|(agent_id, head)| (agent_id.clone(), chain_nodes(&parents, *head)))
        .collect();
    let subagent_node_ids: HashSet<i64> =
        subagent_sets.iter().flat_map(|(_, set)| set.iter().copied()).collect();

    let mut sessions = Vec::new();
    if target.is_none_or(|target| target == session.id) {
        let main_nodes: Vec<&MessageNode> =
            nodes.iter().filter(|node| !subagent_node_ids.contains(&node.node_id)).collect();
        if let Some(raw) = build_session(
            session,
            session.id.clone(),
            db_path,
            started_at,
            updated_at,
            &main_nodes,
            include_events,
        ) {
            sessions.push(raw);
        }
    }
    for (agent_id, set) in &subagent_sets {
        let source_id = format!("{}:{agent_id}", session.id);
        if target.is_some_and(|target| target != source_id) {
            continue;
        }
        let sub_nodes: Vec<&MessageNode> =
            nodes.iter().filter(|node| set.contains(&node.node_id)).collect();
        let sub_started_at =
            sub_nodes.first().map(|node| seconds_to_ms(node.created_at)).unwrap_or(started_at);
        if let Some(mut raw) = build_session(
            session,
            source_id,
            db_path,
            sub_started_at,
            updated_at,
            &sub_nodes,
            include_events,
        ) {
            raw.custom_title = None;
            raw.thread_role = Some(ThreadRole::Subagent);
            raw.parent_links = vec![ParentLink {
                relation: ParentRelation::Spawn,
                source: "devin".to_string(),
                source_id: session.id.clone(),
            }];
            sessions.push(raw);
        }
    }
    Ok(sessions)
}

fn build_session(
    session: &SessionRow,
    source_id: String,
    db_path: &Path,
    started_at: i64,
    updated_at: i64,
    nodes: &[&MessageNode],
    include_events: bool,
) -> Option<RawSession> {
    let directory = session.working_directory.trim();
    let parsed = parse_nodes(nodes, session, directory, db_path, include_events);
    if parsed.messages.is_empty() && parsed.usage_events.is_empty() && parsed.events.is_empty() {
        return None;
    }
    let mut raw = RawSession::search_only(
        source_id,
        (!directory.is_empty()).then(|| directory.to_string()),
        started_at,
        Some(updated_at),
        None,
        parsed.messages,
    )
    .with_usage(parsed.usage_events, USAGE_PARSER_VERSION);
    raw.custom_title = session
        .title
        .as_deref()
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .map(str::to_string);
    raw.duration_minutes =
        u32::try_from((session.last_activity_at - session.created_at).max(0) / 60).ok();
    raw.metadata_parser_version = Some(METADATA_PARSER_VERSION);
    raw.source_file_path = db_path.to_str().map(str::to_string);
    Some(if include_events { raw.with_events(parsed.events, EVENT_PARSER_VERSION) } else { raw })
}

fn parse_nodes(
    nodes: &[&MessageNode],
    session: &SessionRow,
    directory: &str,
    db_path: &Path,
    include_events: bool,
) -> ParsedNodes {
    let mut parsed = ParsedNodes::default();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut call_names: HashMap<String, String> = HashMap::new();
    for node in nodes {
        if !seen.insert(node.dedupe_key.as_str()) {
            continue;
        }
        let message: Value = match serde_json::from_str(&node.chat_message) {
            Ok(message) => message,
            Err(err) => {
                warn!("skipping malformed Devin message node {}: {err}", node.node_id);
                continue;
            }
        };
        let timestamp = seconds_to_ms(node.created_at);
        let role = message.get("role").and_then(Value::as_str).unwrap_or("");
        let content = message.get("content").and_then(Value::as_str).unwrap_or("");
        match role {
            "user" => {
                if message.pointer("/metadata/is_user_input").and_then(Value::as_bool) == Some(true)
                    && !content.trim().is_empty()
                {
                    parsed.messages.push(RawMessage {
                        role: Role::User,
                        content: content.to_string(),
                        timestamp: Some(timestamp),
                    });
                }
            }
            "assistant" => {
                let mut message_seq = None;
                if !content.trim().is_empty() {
                    parsed.messages.push(RawMessage {
                        role: Role::Assistant,
                        content: content.to_string(),
                        timestamp: Some(timestamp),
                    });
                    message_seq = Some(parsed.messages.len() as u32 - 1);
                }
                let message_seq = message_seq
                    .or_else(|| parsed.messages.len().checked_sub(1).map(|seq| seq as u32));
                if include_events
                    && let Some(tool_calls) = message.get("tool_calls").and_then(Value::as_array)
                {
                    for (index, call) in tool_calls.iter().enumerate() {
                        let Some(name) =
                            call.get("name").and_then(Value::as_str).filter(|n| !n.is_empty())
                        else {
                            continue;
                        };
                        let context = EventContext {
                            event_seq: parsed.events.len() as u32,
                            timestamp: Some(timestamp),
                            source_path: db_path.to_str().map(str::to_string),
                            source_event_id: Some(format!(
                                "nodes:{}:tool_calls:{index}",
                                node.node_id
                            )),
                            message_seq,
                            parser_version: EVENT_PARSER_VERSION,
                        };
                        if let Some(event) = parse_tool_call(call, name, context, directory) {
                            if let Some(id) =
                                call.get("id").and_then(Value::as_str).filter(|id| !id.is_empty())
                            {
                                call_names.insert(id.to_string(), name.to_string());
                            }
                            parsed.events.push(event);
                        }
                    }
                }
                if let Some(usage) = usage_event(
                    &node.dedupe_key,
                    parsed.usage_events.len() as u32,
                    timestamp,
                    message_seq,
                    &message,
                    session,
                    db_path,
                ) {
                    parsed.usage_events.push(usage);
                }
            }
            "tool" if include_events => {
                let call_id =
                    message.get("tool_call_id").and_then(Value::as_str).filter(|id| !id.is_empty());
                let context = EventContext {
                    event_seq: parsed.events.len() as u32,
                    timestamp: Some(timestamp),
                    source_path: db_path.to_str().map(str::to_string),
                    source_event_id: Some(format!("nodes:{}", node.node_id)),
                    message_seq: parsed.messages.len().checked_sub(1).map(|seq| seq as u32),
                    parser_version: EVENT_PARSER_VERSION,
                };
                let name = call_id.and_then(|id| call_names.get(id).cloned());
                let summary = (!content.trim().is_empty()).then(|| content.to_string());
                let mut event = events::tool_result_event(context, name, summary);
                event.tool_call_id = call_id.map(str::to_string);
                event.status = message
                    .get("metadata")
                    .and_then(|meta| meta.get("extensions"))
                    .and_then(|ext| ext.get("chisel/tool_result_meta"))
                    .and_then(|meta| meta.get("success"))
                    .and_then(Value::as_bool)
                    .map(|success| if success { "success" } else { "error" }.to_string());
                parsed.events.push(event);
            }
            _ => {}
        }
    }
    parsed
}

fn parse_tool_call(
    call: &Value,
    name: &str,
    context: EventContext,
    directory: &str,
) -> Option<RawSessionEvent> {
    let args = call.get("arguments");
    let mut event = events::tool_call_event(context, name.to_string(), args);
    event.tool_call_id =
        call.get("id").and_then(Value::as_str).filter(|id| !id.is_empty()).map(str::to_string);
    let file_arg = match name {
        "notebook_edit" => "notebook_path",
        _ => "file_path",
    };
    let operation = match name {
        "read" => Some(FileOperation::Read),
        "write" | "edit" | "notebook_edit" => Some(FileOperation::Write),
        _ => None,
    };
    if let Some(operation) = operation
        && let Some(path) = args
            .and_then(|args| args.get(file_arg))
            .and_then(Value::as_str)
            .filter(|path| !path.trim().is_empty())
    {
        event.kind =
            if operation == FileOperation::Read { "file_read" } else { "file_write" }.to_string();
        event.target = Some(path.to_string());
        event.files.push(FileEvidence::call(
            path.to_string(),
            operation,
            Some(directory.to_string()),
        ));
    } else if name == "exec" {
        event.kind = "command".to_string();
        event.target = args
            .and_then(|args| args.get("command"))
            .and_then(Value::as_str)
            .filter(|command| !command.trim().is_empty())
            .map(str::to_string);
        if let Some(command) = event.target.as_deref() {
            let cwd = args
                .and_then(|args| args.get("workdir").or_else(|| args.get("cwd")))
                .and_then(Value::as_str)
                .filter(|path| Path::new(path).is_absolute())
                .or(Some(directory).filter(|dir| Path::new(dir).is_absolute()));
            let (files, status) = events::shell_file_evidence(command, cwd);
            event.files = files;
            event.command_evidence_status = Some(status);
        }
    }
    Some(event)
}

fn usage_event(
    key: &str,
    event_seq: u32,
    timestamp: i64,
    message_seq: Option<u32>,
    message: &Value,
    session: &SessionRow,
    db_path: &Path,
) -> Option<RawUsageEvent> {
    let metrics = message.pointer("/metadata/metrics")?;
    let input_tokens = json_i64(metrics.get("input_tokens")).unwrap_or(0).max(0);
    let output_tokens = json_i64(metrics.get("output_tokens")).unwrap_or(0).max(0);
    let cache_read_tokens = json_i64(metrics.get("cache_read_tokens")).unwrap_or(0).max(0);
    let cache_write_tokens = json_i64(metrics.get("cache_creation_tokens")).unwrap_or(0).max(0);
    if input_tokens + output_tokens + cache_read_tokens + cache_write_tokens == 0 {
        return None;
    }
    let mut event = RawUsageEvent::observed(
        format!("message:{key}"),
        event_seq,
        timestamp,
        USAGE_PARSER_VERSION,
    );
    event.message_seq = message_seq;
    event.model = session
        .model
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .unwrap_or("unknown")
        .to_string();
    event.provider = session
        .backend_type
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or("devin")
        .to_string();
    event.input_tokens = input_tokens;
    event.output_tokens = output_tokens;
    event.cache_read_tokens = cache_read_tokens;
    event.cache_write_tokens = cache_write_tokens;
    event.source_path = db_path.to_str().map(str::to_string);
    event.raw_usage_json = Some(metrics.to_string());
    Some(event)
}

fn seconds_to_ms(timestamp: i64) -> i64 {
    if timestamp.abs() >= MS_THRESHOLD { timestamp } else { timestamp.saturating_mul(1000) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::test_support::{
        seed_empty_event_state, seed_empty_metadata_state, seed_empty_usage_state,
        store as setup_store,
    };
    use crate::types::Session;

    fn make_session(source_id: &str, updated_at: Option<i64>, message_count: u32) -> Session {
        Session {
            source: "devin".to_string(),
            source_id: source_id.to_string(),
            title: "existing".to_string(),
            directory: Some("/repo".to_string()),
            started_at: 100,
            updated_at,
            message_count,
            ..crate::types::test_support::session(&format!("local-{source_id}"))
        }
    }

    fn setup_devin_db(dir: &Path) -> Connection {
        std::fs::create_dir_all(dir).unwrap();
        let conn = Connection::open(dir.join("sessions.db")).unwrap();
        conn.execute_batch(
            "
            CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                working_directory TEXT NOT NULL,
                backend_type TEXT NOT NULL,
                model TEXT NOT NULL,
                agent_mode TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_activity_at INTEGER NOT NULL,
                title TEXT,
                main_chain_id INTEGER,
                hidden INTEGER NOT NULL DEFAULT 0,
                metadata TEXT
            );
            CREATE TABLE message_nodes (
                row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                node_id INTEGER NOT NULL,
                parent_node_id INTEGER,
                chat_message TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                metadata TEXT,
                UNIQUE(session_id, node_id)
            );
            CREATE TABLE subagent_heads (
                session_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                chain_node_id INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (session_id, agent_id)
            );
            ",
        )
        .unwrap();
        conn
    }

    fn insert_session(conn: &Connection, id: &str, hidden: i64) {
        conn.execute(
            "INSERT INTO sessions
             (id, working_directory, backend_type, model, agent_mode, created_at,
              last_activity_at, title, hidden)
             VALUES (?1, '/repo', 'windsurf', 'swe-2-max', 'bypass', 1788279318,
                     1788279401, 'seed title', ?2)",
            rusqlite::params![id, hidden],
        )
        .unwrap();
    }

    fn insert_node(
        conn: &Connection,
        session_id: &str,
        node_id: i64,
        parent_node_id: Option<i64>,
        chat_message: &Value,
        created_at: i64,
    ) {
        conn.execute(
            "INSERT INTO message_nodes
             (session_id, node_id, parent_node_id, chat_message, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                session_id,
                node_id,
                parent_node_id,
                chat_message.to_string(),
                created_at
            ],
        )
        .unwrap();
    }

    fn user_message(id: &str, content: &str) -> Value {
        serde_json::json!({
            "message_id": id,
            "role": "user",
            "content": content,
            "metadata": {"is_user_input": true},
        })
    }

    fn scan_path(path: &Path) -> SyncScanOutput {
        scan_devin(Some(path), None, None, true, false).unwrap()
    }

    #[test]
    fn resume_uses_official_flag_and_strips_subagent_suffix() {
        let command = DevinAdapter.resume_command("oxidized-sardine").unwrap();
        assert_eq!(command.program, "devin");
        assert_eq!(command.args, vec!["--resume", "oxidized-sardine"]);
        let sub = DevinAdapter.resume_command("oxidized-sardine:agent-1").unwrap();
        assert_eq!(sub.args, vec!["--resume", "oxidized-sardine"]);
    }

    #[test]
    fn start_command_uses_dash_dash_separator() {
        let command = DevinAdapter.start_command("fix the tests".to_string()).unwrap();
        assert_eq!(command.program, "devin");
        assert_eq!(command.args, vec!["--", "fix the tests"]);
    }

    #[test]
    fn db_path_prefers_xdg_then_home() {
        let home = tempfile::tempdir().unwrap();
        let resolved = resolve_db_path_from(None, Some(home.path().to_path_buf())).unwrap();
        assert_eq!(resolved, home.path().join(".local/share/devin/cli/sessions.db"));
        let resolved =
            resolve_db_path_from(Some("/tmp/xdg".to_string()), Some(PathBuf::from("/unused")))
                .unwrap();
        assert_eq!(resolved, PathBuf::from("/tmp/xdg/devin/cli/sessions.db"));
    }

    #[test]
    fn seconds_are_converted_to_milliseconds() {
        assert_eq!(seconds_to_ms(1788279318), 1_788_279_318_000);
        assert_eq!(seconds_to_ms(1_788_279_318_000), 1_788_279_318_000);
    }

    #[test]
    fn scan_dedupes_replayed_context_and_filters_internal_prompts() {
        let root = tempfile::tempdir().unwrap();
        let conn = setup_devin_db(root.path());
        insert_session(&conn, "ses-1", 0);
        let user = user_message("u1", "fix the tests");
        let assistant = serde_json::json!({
            "message_id": "a1",
            "role": "assistant",
            "content": "done",
            "metadata": {"metrics": {"input_tokens": 10, "output_tokens": 5}},
        });
        let internal = serde_json::json!({
            "message_id": "i1",
            "role": "user",
            "content": "Conversation to summarize: ...",
        });
        insert_node(&conn, "ses-1", 0, None, &user, 1788279318);
        insert_node(&conn, "ses-1", 1, Some(0), &assistant, 1788279320);
        insert_node(&conn, "ses-1", 2, Some(1), &internal, 1788279321);
        // Rebuilt tree for the next turn replays the same message ids.
        insert_node(&conn, "ses-1", 10, None, &user, 1788279390);
        insert_node(&conn, "ses-1", 11, Some(10), &assistant, 1788279391);
        insert_node(&conn, "ses-1", 12, Some(11), &user_message("u2", "now lint it"), 1788279400);
        // A malformed node is skipped, not fatal.
        conn.execute(
            "INSERT INTO message_nodes
             (session_id, node_id, parent_node_id, chat_message, created_at)
             VALUES ('ses-1', 13, 12, 'not json', 1788279401)",
            [],
        )
        .unwrap();
        drop(conn);

        let result = scan_path(&root.path().join("sessions.db"));
        assert_eq!(result.scan.sessions.len(), 1);
        let raw = &result.scan.sessions[0];
        assert_eq!(raw.source_id, "ses-1");
        assert_eq!(raw.custom_title.as_deref(), Some("seed title"));
        assert_eq!(raw.directory.as_deref(), Some("/repo"));
        assert_eq!(raw.started_at, 1_788_279_318_000);
        assert_eq!(raw.updated_at, Some(1_788_279_401_000));
        let contents: Vec<_> =
            raw.messages.iter().map(|m| (m.role.as_str(), m.content.as_str())).collect();
        assert_eq!(
            contents,
            [("user", "fix the tests"), ("assistant", "done"), ("user", "now lint it")]
        );
        assert_eq!(raw.usage_events.len(), 1);
        assert_eq!(raw.usage_events[0].input_tokens, 10);
        assert_eq!(raw.usage_events[0].output_tokens, 5);
        assert_eq!(raw.usage_events[0].model, "swe-2-max");
        assert_eq!(raw.usage_events[0].provider, "windsurf");
        assert!(matches!(
            result.reconcile,
            Some(ReconcilePlan::CompleteLiveSet(ref live)) if live.contains("ses-1")
        ));
    }

    #[test]
    fn scan_emits_tool_events_and_file_evidence() {
        let root = tempfile::tempdir().unwrap();
        let conn = setup_devin_db(root.path());
        insert_session(&conn, "ses-1", 0);
        let call = serde_json::json!({
            "message_id": "a1",
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "call-1",
                "name": "edit",
                "arguments": {"file_path": "/repo/a.rs", "old_string": "x", "new_string": "y"},
                "kind": "function"
            }, {
                "id": "call-2",
                "name": "exec",
                "arguments": {"command": "git restore -- src/lib.rs", "workdir": "/repo/sub"},
                "kind": "function"
            }],
        });
        let result_msg = serde_json::json!({
            "message_id": "t1",
            "role": "tool",
            "content": "applied",
            "tool_call_id": "call-1",
            "metadata": {"extensions": {"chisel/tool_result_meta": {"success": false}}},
        });
        insert_node(&conn, "ses-1", 0, None, &call, 1788279320);
        insert_node(&conn, "ses-1", 1, Some(0), &result_msg, 1788279325);
        drop(conn);

        let result = scan_path(&root.path().join("sessions.db"));
        let raw = &result.scan.sessions[0];
        assert_eq!(raw.events.len(), 3);
        assert_eq!(raw.events[0].kind, "file_write");
        assert_eq!(raw.events[0].target.as_deref(), Some("/repo/a.rs"));
        assert_eq!(raw.events[0].files[0].operation, FileOperation::Write);
        assert_eq!(raw.events[1].kind, "command");
        assert_eq!(raw.events[1].target.as_deref(), Some("git restore -- src/lib.rs"));
        assert_eq!(raw.events[1].files[0].path, "src/lib.rs");
        assert_eq!(raw.events[1].files[0].cwd.as_deref(), Some("/repo/sub"));
        assert_eq!(raw.events[2].kind, "tool_result");
        assert_eq!(raw.events[2].name.as_deref(), Some("edit"));
        assert_eq!(raw.events[2].tool_call_id.as_deref(), Some("call-1"));
        assert_eq!(raw.events[2].status.as_deref(), Some("error"));
    }

    #[test]
    fn hidden_and_empty_sessions_are_skipped_and_tombstoned() {
        let root = tempfile::tempdir().unwrap();
        let conn = setup_devin_db(root.path());
        insert_session(&conn, "hidden", 1);
        insert_session(&conn, "empty", 0);
        insert_node(
            &conn,
            "empty",
            0,
            None,
            &serde_json::json!({"message_id": "s1", "role": "system", "content": "prompt"}),
            1788279318,
        );
        drop(conn);

        let result = scan_path(&root.path().join("sessions.db"));
        assert!(result.scan.sessions.is_empty());
        assert_eq!(result.scan.stats.candidates, 2);
        assert_eq!(result.scan.stats.filtered_sessions, 2);
        assert!(matches!(
            result.reconcile,
            Some(ReconcilePlan::CompleteLiveSet(ref live)) if live.contains("empty") && !live.contains("hidden")
        ));
    }

    #[test]
    fn subagent_chains_become_linked_sessions() {
        let root = tempfile::tempdir().unwrap();
        let conn = setup_devin_db(root.path());
        insert_session(&conn, "ses-1", 0);
        insert_node(&conn, "ses-1", 0, None, &user_message("u1", "run the subagent"), 1788279318);
        insert_node(
            &conn,
            "ses-1",
            5,
            None,
            &serde_json::json!({"message_id": "ss1", "role": "system", "content": "subagent prompt"}),
            1788279330,
        );
        insert_node(
            &conn,
            "ses-1",
            6,
            Some(5),
            &user_message("su1", "explore the code"),
            1788279331,
        );
        conn.execute(
            "INSERT INTO subagent_heads (session_id, agent_id, chain_node_id, updated_at)
             VALUES ('ses-1', 'explore-1', 6, 1788279331)",
            [],
        )
        .unwrap();
        drop(conn);

        let result = scan_path(&root.path().join("sessions.db"));
        assert_eq!(result.scan.sessions.len(), 2);
        let main = result.scan.sessions.iter().find(|s| s.source_id == "ses-1").unwrap();
        assert_eq!(main.messages.len(), 1);
        assert_eq!(main.messages[0].content, "run the subagent");
        let sub = result.scan.sessions.iter().find(|s| s.source_id == "ses-1:explore-1").unwrap();
        assert_eq!(sub.thread_role, Some(ThreadRole::Subagent));
        assert_eq!(sub.parent_links[0].source_id, "ses-1");
        assert_eq!(sub.messages.len(), 1);
        assert_eq!(sub.messages[0].content, "explore the code");
        assert!(matches!(
            result.reconcile,
            Some(ReconcilePlan::CompleteLiveSet(ref live))
                if live.contains("ses-1") && live.contains("ses-1:explore-1")
        ));
    }

    #[test]
    fn targeted_refresh_reaches_subagent_sessions() {
        let root = tempfile::tempdir().unwrap();
        let conn = setup_devin_db(root.path());
        insert_session(&conn, "ses-1", 0);
        insert_node(&conn, "ses-1", 0, None, &user_message("u1", "main"), 1788279318);
        insert_node(&conn, "ses-1", 5, None, &user_message("su1", "sub task"), 1788279331);
        conn.execute(
            "INSERT INTO subagent_heads (session_id, agent_id, chain_node_id, updated_at)
             VALUES ('ses-1', 'explore-1', 5, 1788279331)",
            [],
        )
        .unwrap();
        drop(conn);

        for (target, expected) in [
            ("ses-1", vec!["ses-1"]),
            ("ses-1:explore-1", vec!["ses-1:explore-1"]),
            ("missing", vec![]),
        ] {
            let context = AdapterSyncContext::empty_for_test("devin").restricted_to(target);
            let result = scan_devin(
                Some(&root.path().join("sessions.db")),
                Some(&context),
                None,
                true,
                false,
            )
            .unwrap();
            let ids: Vec<_> = result.scan.sessions.iter().map(|s| s.source_id.as_str()).collect();
            assert_eq!(ids, expected, "target {target}");
        }
    }

    #[test]
    fn incremental_scan_skips_current_sessions() {
        let root = tempfile::tempdir().unwrap();
        let db_path = root.path().join("sessions.db");
        let conn = setup_devin_db(root.path());
        insert_session(&conn, "ses-1", 0);
        insert_node(&conn, "ses-1", 0, None, &user_message("u1", "hello"), 1788279318);
        drop(conn);

        let store = setup_store();
        store.insert_session(&make_session("ses-1", Some(1_788_279_401_000), 1)).unwrap();
        seed_empty_usage_state(
            &store,
            "devin",
            "ses-1",
            USAGE_PARSER_VERSION,
            Some(1_788_279_401_000),
        );
        seed_empty_event_state(
            &store,
            "devin",
            "ses-1",
            EVENT_PARSER_VERSION,
            Some(1_788_279_401_000),
        );
        seed_empty_metadata_state(&store, "devin", "ses-1", METADATA_PARSER_VERSION);

        let result = scan_devin(
            Some(&db_path),
            Some(&AdapterSyncContext::from_store_for_test(&store, "devin").unwrap()),
            None,
            true,
            false,
        )
        .unwrap();
        assert!(result.scan.sessions.is_empty());
        assert_eq!(result.scan.stats.skipped_sessions, 1);

        // Force reprocesses even when the session state is current.
        let forced = scan_devin(
            Some(&db_path),
            Some(&AdapterSyncContext::from_store_for_test(&store, "devin").unwrap()),
            None,
            true,
            true,
        )
        .unwrap();
        assert_eq!(forced.scan.sessions.len(), 1);
    }
}
