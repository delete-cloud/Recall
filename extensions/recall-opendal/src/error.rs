use serde::Serialize;
use std::error::Error as _;

pub type Result<T> = std::result::Result<T, Failure>;

#[derive(Debug, Serialize)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
}

impl Failure {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into().chars().take(4096).collect() }
    }

    pub fn io(error: std::io::Error) -> Self {
        let (code, message) = match error.kind() {
            std::io::ErrorKind::NotFound => ("target_missing", "local path is missing"),
            std::io::ErrorKind::PermissionDenied => ("permission", "local access denied"),
            std::io::ErrorKind::AlreadyExists => ("conflict", "local destination already exists"),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted => {
                ("transient", "local I/O interrupted or timed out")
            }
            _ => ("unavailable", "local I/O failed"),
        };
        // io::Error can wrap an OpenDAL error, URL, or arbitrary source text.
        // Only its stable kind crosses the process boundary.
        Self::new(code, message)
    }

    pub fn backend(error: opendal::Error) -> Self {
        use opendal::ErrorKind;
        let response = backend_response(&error);
        let code = if authentication_evidence(&error, &response) {
            "authentication"
        } else if response.status.is_some()
            && response.service == Some("s3")
            && response.code == Some("NoSuchBucket")
        {
            "target_missing"
        } else if response.status == Some(404)
            && !matches!(
                (response.service, response.code),
                (Some("s3"), Some("NoSuchKey")) | (Some("b2"), Some("no_such_file"))
            )
        {
            // HTTP 404 can conceal authorization failure. It does not establish
            // absence, even when OpenDAL classifies the response as NotFound.
            "unavailable"
        } else {
            match error.kind() {
                ErrorKind::NotFound => "object_missing",
                ErrorKind::PermissionDenied => "permission",
                ErrorKind::ConfigInvalid => "not_configured",
                ErrorKind::AlreadyExists | ErrorKind::ConditionNotMatch | ErrorKind::Conflict => {
                    "conflict"
                }
                ErrorKind::RangeNotSatisfied => "integrity",
                ErrorKind::IsADirectory | ErrorKind::NotADirectory | ErrorKind::IsSameFile => {
                    "invalid_request"
                }
                ErrorKind::RateLimited => "transient",
                _ if error.is_temporary() => "transient",
                _ => "unavailable",
            }
        };
        let message = match code {
            "authentication" => "backend credentials were rejected or are unavailable",
            "object_missing" => "backend object is missing",
            "target_missing" => "backend target is missing",
            "permission" => "backend operation denied",
            "not_configured" => "backend configuration is invalid",
            "conflict" => "backend object conflicts with the requested operation",
            "integrity" => "backend object data violates the transport contract",
            "invalid_request" => "backend rejected the requested path or operation",
            "transient" => "backend operation temporarily failed",
            _ => "backend operation failed",
        };
        // OpenDAL Display/Debug includes endpoint, response headers/body, and
        // source errors. Never print it, even after a best-effort substitution.
        Self::new(code, message)
    }
}

fn authentication_evidence(error: &opendal::Error, response: &BackendResponse<'_>) -> bool {
    // SDK sources retain their typed credential-invalid classification. Plain
    // signing, network, config, and permission errors are insufficient evidence.
    let mut source = error.source();
    while let Some(current) = source {
        if current
            .downcast_ref::<reqsign_core::Error>()
            .is_some_and(|error| error.kind() == reqsign_core::ErrorKind::CredentialInvalid)
        {
            return true;
        }
        source = current.source();
    }
    if error.source().is_some() && error.message() == "loading credential to sign http request" {
        return true;
    }

    if response.status == Some(401) {
        return true;
    }
    if !matches!(response.status, Some(400 | 403)) {
        return false;
    }
    matches!(
        (response.service, response.code),
        (
            Some("s3"),
            Some(
                "InvalidAccessKeyId"
                    | "SignatureDoesNotMatch"
                    | "ExpiredToken"
                    | "ExpiredTokenException"
                    | "InvalidToken"
                    | "InvalidSecurity"
                    | "TokenRefreshRequired"
            )
        ) | (Some("b2"), Some("bad_auth_token" | "expired_auth_token" | "invalid_auth_token"))
    )
}

struct BackendResponse<'a> {
    status: Option<u16>,
    service: Option<&'static str>,
    code: Option<&'a str>,
}

fn backend_response(error: &opendal::Error) -> BackendResponse<'_> {
    // Pinned OpenDAL 0.59.5 exposes message/kind/source but no HTTP-context
    // accessor. Its response context uses http::response::Parts Debug. Read
    // only the status at that exact context boundary, before the raw message;
    // do not search server bodies/headers or source strings for status codes.
    // A changed upstream representation fails closed to ordinary error mapping.
    let rendered = error.to_string();
    let context = rendered.split_once(" => ").map_or(rendered.as_str(), |(context, _)| context);
    let response = context.split_once("response: Parts { status: ").map(|(_, value)| value);
    let status = response
        .and_then(|response| response.split_once(','))
        .and_then(|(status, _)| status.parse::<u16>().ok());

    // Service parsers preserve only their Debug-encoded structured codes in
    // message(). Match the leading code field exactly, never a body substring.
    let service = match context
        .rsplit_once("service: ")
        .and_then(|(_, value)| value.split([',', ' ']).next())
    {
        Some("s3") => Some("s3"),
        Some("b2") => Some("b2"),
        _ => None,
    };
    let message = error.message();
    let code = match service {
        Some("s3") => message.strip_prefix("S3Error { code: \""),
        Some("b2") => message
            .strip_prefix("B2Error { status: ")
            .and_then(|rest| rest.split_once(", code: \"").map(|(_, code)| code)),
        _ => None,
    }
    .and_then(|code| code.split_once("\", message: ").map(|(code, _)| code));
    BackendResponse { status, service, code }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Failure {}
