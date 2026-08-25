use anyhow::{anyhow, Result};
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use sha2::{Digest, Sha256};

/// RBAC roles (PRD FR-PLAT-005). `automation` shares operator privileges but is
/// valid only for `/api/*` calls, never for HTML console pages.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Viewer,
    Operator,
    Automation,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Result<Role> {
        match s {
            "viewer" => Ok(Role::Viewer),
            "operator" => Ok(Role::Operator),
            "automation" => Ok(Role::Automation),
            "admin" => Ok(Role::Admin),
            other => Err(anyhow!("unknown role '{other}'")),
        }
    }

    /// Numeric privilege rank for >= comparisons.
    pub fn rank(self) -> u8 {
        match self {
            Role::Viewer => 0,
            Role::Operator | Role::Automation => 1,
            Role::Admin => 2,
        }
    }
}

/// Minimum role required for a request. `None` = public endpoint.
/// Returns the required rank plus whether the endpoint is API (vs console page).
pub fn requirement(method: &str, path: &str) -> Option<(u8, bool)> {
    // Public endpoints: operability + login flow.
    if path == "/api/health" || path == "/api/openapi.json" {
        return None;
    }
    if method == "GET" && (path == "/login" || path == "/login.html") {
        return None;
    }
    if method == "POST" && path == "/login" {
        return None;
    }
    // Signing out must always be possible for whoever holds a cookie.
    if method == "POST" && path == "/logout" {
        return None;
    }
    let is_api = path.starts_with("/api/");
    let min_rank = match (method, path) {
        // read-only surface
        ("GET", _) => Role::Viewer.rank(),
        // operator surface: run things, acknowledge, device lifecycle tweaks
        ("POST", "/api/check")
        | ("POST", "/api/monitor/start")
        | ("POST", "/api/monitor/stop")
        | ("POST", "/api/ping")
        | ("POST", "/api/diagnose")
        | ("POST", "/api/trace")
        | ("POST", "/api/event/ack")
        | ("POST", "/api/associate")
        | ("POST", "/api/device") => Role::Operator.rank(),
        // admin surface: topology-changing, config-changing, destructive
        ("POST", "/api/discover")
        | ("POST", "/api/inspect")
        | ("POST", "/api/settings")
        | ("POST", "/api/webhook/test") => Role::Admin.rank(),
        // any other POST defaults to admin (deny-by-default)
        (_, _) => Role::Admin.rank(),
    };
    Some((min_rank, is_api))
}

/// Does an authenticated principal satisfy a requirement?
/// `automation` tokens are accepted for API paths only — never for pages.
pub fn authorized(role: Role, is_api: bool, required_rank: u8) -> bool {
    if role == Role::Automation && !is_api {
        return false;
    }
    role.rank() >= required_rank
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2 hash failed: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, phc_hash: &str) -> bool {
    PasswordHash::new(phc_hash)
        .and_then(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .map(|_| ())
        })
        .is_ok()
}

/// Generate a fresh bearer/session token; returns (raw, sha256-hex).
/// Only the hash is persisted.
pub fn new_token() -> (String, String) {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let raw = format!("nms_{}", hex_encode(&bytes));
    let hashed = token_hash(&raw);
    (raw, hashed)
}

pub fn token_hash(raw: &str) -> String {
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex_encode(&h.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let h = hash_password("s3cret!").unwrap();
        assert!(verify_password("s3cret!", &h));
        assert!(!verify_password("wrong", &h));
        assert!(h.starts_with("$argon2"));
    }

    #[test]
    fn tokens_are_unique_and_hashed() {
        let (raw1, h1) = new_token();
        let (_, h2) = new_token();
        assert_ne!(h1, h2);
        assert!(raw1.starts_with("nms_"));
        assert_eq!(token_hash(&raw1), h1);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn role_matrix() {
        // public endpoints
        assert!(requirement("GET", "/api/health").is_none());
        assert!(requirement("GET", "/api/openapi.json").is_none());
        assert!(requirement("POST", "/login").is_none());
        // reads need viewer
        assert_eq!(requirement("GET", "/console"), Some((0, false)));
        assert_eq!(requirement("GET", "/api/status"), Some((0, true)));
        // operator surface
        assert_eq!(requirement("POST", "/api/ping"), Some((1, true)));
        // admin surface
        assert_eq!(requirement("POST", "/api/settings"), Some((2, true)));
        // unknown POST deny-by-default at admin
        assert_eq!(requirement("POST", "/api/unknown"), Some((2, true)));

        // authorization checks
        assert!(authorized(Role::Viewer, false, 0));
        assert!(!authorized(Role::Viewer, true, 1));
        assert!(authorized(Role::Operator, true, 1));
        assert!(authorized(Role::Automation, true, 1), "automation may call APIs");
        assert!(!authorized(Role::Automation, false, 0), "automation never gets pages");
        assert!(authorized(Role::Admin, false, 2));
        assert!(!authorized(Role::Operator, true, 2));
    }

    #[test]
    fn roles_parse() {
        assert_eq!(Role::parse("viewer").unwrap(), Role::Viewer);
        assert_eq!(Role::parse("admin").unwrap(), Role::Admin);
        assert!(Role::parse("root").is_err());
    }
}
