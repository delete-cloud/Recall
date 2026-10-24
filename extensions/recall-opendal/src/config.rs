use crate::error::{Failure, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub scheme: String,
    #[serde(flatten)]
    options: HashMap<String, String>,
}

pub fn path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("RECALL_OPENDAL_CONFIG") {
        if path.is_empty() {
            return Err(Failure::new("not_configured", "RECALL_OPENDAL_CONFIG is empty"));
        }
        return Ok(path.into());
    }
    Ok(dirs::home_dir()
        .ok_or_else(|| Failure::new("not_configured", "cannot determine home directory"))?
        .join(".config/recall-opendal.json"))
}

fn parse(bytes: &[u8]) -> Result<Config> {
    let config: Config = serde_json::from_slice(bytes)
        .map_err(|_| Failure::new("not_configured", "invalid OpenDAL configuration JSON"))?;
    config.validate_options()?;
    Ok(config)
}

pub fn load() -> Result<Config> {
    let bytes = std::fs::read(path()?).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Failure::new("not_configured", "missing configuration; run --recall-remote-configure")
        } else {
            Failure::io(error)
        }
    })?;
    parse(&bytes)
}

impl Config {
    pub fn operator(&self) -> Result<opendal::blocking::Operator> {
        let mut options = self.sanitized_options()?;
        // These two pinned services do not implement SDK environment lookup.
        // Bridge explicit process environment credentials in memory only, after
        // validating the saved configuration. Never serialize these options.
        match self.scheme.as_str() {
            "s3" if !options.contains_key("endpoint") => {
                // These are the pinned SDK's endpoint fallbacks. Resolve and
                // validate them here so env URLs obey the same credential ban.
                for env in ["AWS_ENDPOINT_URL", "AWS_ENDPOINT", "AWS_S3_ENDPOINT"] {
                    match std::env::var(env) {
                        Ok(endpoint) => {
                            validate_endpoint(&endpoint)?;
                            options.insert("endpoint".into(), endpoint);
                            break;
                        }
                        Err(std::env::VarError::NotPresent) => {}
                        Err(std::env::VarError::NotUnicode(_)) => {
                            return Err(Failure::new(
                                "not_configured",
                                "environment endpoint is not valid UTF-8",
                            ));
                        }
                    }
                }
            }
            "webdav" => {
                for (option, env) in [
                    ("username", "WEBDAV_USERNAME"),
                    ("password", "WEBDAV_PASSWORD"),
                    ("token", "WEBDAV_TOKEN"),
                ] {
                    credential_from_env(&mut options, option, env)?;
                }
            }
            "b2" => {
                credential_from_env(&mut options, "application_key_id", "B2_APPLICATION_KEY_ID")?;
                credential_from_env(&mut options, "application_key", "B2_APPLICATION_KEY")?;
                if !options.contains_key("application_key_id")
                    || !options.contains_key("application_key")
                {
                    return Err(Failure::new(
                        "authentication",
                        "B2 credentials are unavailable in the environment",
                    ));
                }
            }
            _ => {}
        }
        let operator =
            opendal::Operator::via_iter(&self.scheme, options).map_err(Failure::backend)?;
        opendal::blocking::Operator::new(operator).map_err(Failure::backend)
    }

    fn validate_options(&self) -> Result<()> {
        // A closed list rejects SDK aliases, encryption keys, and future secret
        // fields as well as misspellings. Unknown fields must never be ignored
        // or copied into the provider's persisted target configuration.
        let allowed: &[&str] = match self.scheme.as_str() {
            "fs" => &["root", "atomic_write_dir"],
            "s3" => &[
                "bucket",
                "root",
                "endpoint",
                "region",
                "profile",
                "credential_profile",
                "enable_virtual_host_style",
                "disable_ec2_metadata",
                "disable_list_objects_v2",
                "default_storage_class",
                "server_side_encryption",
                "checksum_algorithm",
                "enable_request_payer",
            ],
            "webdav" => &["endpoint", "root", "disable_create_dir"],
            "b2" => &["bucket", "bucket_id", "root"],
            "memory" => &["root"],
            _ => return Err(Failure::new("not_configured", "unsupported OpenDAL scheme")),
        };
        if self.options.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(Failure::new(
                "not_configured",
                "unsupported configuration field; credentials must come from the environment or an SDK profile",
            ));
        }
        if self.options.contains_key("profile") && self.options.contains_key("credential_profile") {
            return Err(Failure::new(
                "not_configured",
                "choose profile or credential_profile, not both",
            ));
        }
        if let Some(endpoint) = self.options.get("endpoint") {
            validate_endpoint(endpoint)?;
        }
        Ok(())
    }

    fn sanitized_options(&self) -> Result<HashMap<String, String>> {
        self.validate_options()?;
        let mut options = self.options.clone();
        if let Some(profile) = options.remove("credential_profile") {
            // OpenDAL 0.59.5 calls the SDK selector `profile`.
            options.insert("profile".into(), profile);
        }
        if self.scheme == "fs" {
            let root = options
                .get("root")
                .ok_or_else(|| Failure::new("not_configured", "fs backend requires a root"))?;
            if !Path::new(root).is_absolute() {
                return Err(Failure::new(
                    "not_configured",
                    "fs root must be an absolute existing directory",
                ));
            }
            // FsBuilder creates missing roots. Check and resolve the target
            // first so an unmounted or removed library cannot become empty.
            let root = std::fs::canonicalize(root).map_err(Failure::io)?;
            if !std::fs::metadata(&root).map_err(Failure::io)?.is_dir() {
                return Err(Failure::new("not_configured", "fs root must be a directory"));
            }
            let staging = root.join(".recall-opendal-tmp");
            if let Some(configured) = options.get("atomic_write_dir") {
                let configured = Path::new(configured);
                let parent = configured.parent().ok_or_else(|| {
                    Failure::new("not_configured", "invalid fs staging directory")
                })?;
                if !configured.is_absolute()
                    || std::fs::canonicalize(parent).map_err(Failure::io)? != root
                    || configured.file_name() != staging.file_name()
                {
                    return Err(Failure::new(
                        "not_configured",
                        "fs staging must be .recall-opendal-tmp under the root",
                    ));
                }
            }
            match std::fs::symlink_metadata(&staging) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(Failure::new(
                        "not_configured",
                        "fs staging must not be a symbolic link",
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(Failure::io(error)),
            }
            let root = root
                .to_str()
                .ok_or_else(|| Failure::new("not_configured", "fs root must be UTF-8"))?;
            let staging = staging
                .to_str()
                .ok_or_else(|| Failure::new("not_configured", "fs staging must be UTF-8"))?;
            options.insert("root".into(), root.into());
            options.insert("atomic_write_dir".into(), staging.into());
        }
        Ok(options)
    }
}

fn credential_from_env(
    options: &mut HashMap<String, String>,
    option: &str,
    env: &str,
) -> Result<()> {
    match std::env::var(env) {
        Ok(value) if !value.is_empty() => {
            options.insert(option.into(), value);
        }
        Ok(_) | Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(Failure::new(
                "authentication",
                "environment credential is not valid UTF-8",
            ));
        }
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str) -> Result<()> {
    let invalid = || {
        Failure::new(
            "not_configured",
            "endpoint must be an HTTP(S) URL without credentials, query, or fragment",
        )
    };
    if endpoint.trim() != endpoint || endpoint.chars().any(char::is_control) {
        return Err(invalid());
    }
    let url = url::Url::parse(endpoint).map_err(|_| invalid())?;
    let authority = endpoint
        .split_once("://")
        .ok_or_else(invalid)?
        .1
        .split(['/', '?', '#'])
        .next()
        .ok_or_else(invalid)?;
    // Reject empty userinfo and percent-encoded authority tricks as well as
    // URL-parser-normalized usernames. Percent escapes are unnecessary in a
    // DNS/IP authority; forbidding them also closes double-encoded forms.
    if !matches!(url.scheme(), "http" | "https")
        || authority.is_empty()
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || authority.contains(['@', '%', '\\'])
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(())
}

pub fn configure(args: &[String]) -> Result<()> {
    let config = match args {
        [flag, json] if flag == "--config-json" => parse(json.as_bytes())?,
        [flag, file] if flag == "--config-file" => {
            parse(&std::fs::read(file).map_err(Failure::io)?)?
        }
        [] if path()?.exists() => load()?,
        [] if std::io::stdin().is_terminal() => {
            eprint!(
                "Non-sensitive OpenDAL configuration JSON (e.g. {{\"scheme\":\"fs\",\"root\":\"/absolute/path\"}}): "
            );
            std::io::stderr().flush().map_err(Failure::io)?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).map_err(Failure::io)?;
            parse(line.as_bytes())?
        }
        [] => {
            return Err(Failure::new(
                "not_configured",
                "use --config-json or --config-file in non-interactive mode",
            ));
        }
        _ => {
            return Err(Failure::new(
                "invalid_request",
                "expected --config-json JSON or --config-file PATH",
            ));
        }
    };
    if std::io::stdin().is_terminal() && path()?.exists() {
        let destination = serde_json::to_string_pretty(&config)
            .map_err(|_| Failure::new("unavailable", "cannot display provider destination"))?;
        eprint!(
            "Proposed destination:\n{destination}\nReplace the existing target? Type yes to confirm: "
        );
        std::io::stderr().flush().map_err(Failure::io)?;
        let mut confirmation = String::new();
        std::io::stdin().read_line(&mut confirmation).map_err(Failure::io)?;
        if confirmation.trim() != "yes" {
            return Err(Failure::new("not_configured", "configuration replacement cancelled"));
        }
    }
    crate::storage::with_operator(|| crate::storage::verify(&config.operator()?))?;
    let path = path()?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).map_err(Failure::io)?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(Failure::io)?;
    serde_json::to_writer_pretty(&mut file, &config)
        .map_err(|_| Failure::new("unavailable", "cannot serialize provider configuration"))?;
    file.as_file_mut().sync_all().map_err(Failure::io)?;
    file.persist(&path).map_err(|error| Failure::io(error.error))?;
    eprintln!("saved OpenDAL configuration (scheme={})", config.scheme);
    Ok(())
}
