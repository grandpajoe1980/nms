//! Small local encrypted credential vault (FR-CFG-001).
//!
//! Records contain only version, opaque credential id, nonce, and ciphertext.
//! The master key is read on demand from `NMS_VAULT_KEY` or
//! `NMS_VAULT_KEY_FILE` and is never persisted by this module.

use chacha20poly1305::{aead::{Aead, KeyInit}, Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const SCHEMA: &str = "nms-vault:v1";
const VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    InvalidId,
    MissingMasterKey,
    InvalidMasterKey,
    MasterKeyFile,
    InsecureMasterKeyFile,
    RecordNotFound,
    RecordInvalid,
    AuthenticationFailed,
    Storage,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidId => "credential reference is invalid",
            Self::MissingMasterKey => "vault master key is not configured",
            Self::InvalidMasterKey => "vault master key must be exactly 64 hexadecimal characters",
            Self::MasterKeyFile => "vault master key file could not be read",
            Self::InsecureMasterKeyFile => "vault master key file permissions are too broad",
            Self::RecordNotFound => "credential reference was not found",
            Self::RecordInvalid => "vault record is invalid",
            Self::AuthenticationFailed => "vault record authentication failed",
            Self::Storage => "vault storage operation failed",
        })
    }
}

impl std::error::Error for VaultError {}

#[derive(Serialize, Deserialize)]
struct VaultRecord {
    version: u8,
    schema: String,
    credential_id: String,
    nonce: String,
    ciphertext: String,
}

pub fn validate_id(id: &str) -> Result<(), VaultError> {
    if id.is_empty()
        || id.starts_with('.')
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(VaultError::InvalidId);
    }
    Ok(())
}

fn record_path(root: &Path, id: &str) -> Result<PathBuf, VaultError> {
    validate_id(id)?;
    Ok(root.join("credentials").join(format!("{id}.json")))
}

fn parse_hex_key(text: &str) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(VaultError::InvalidMasterKey);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    for idx in 0..32 {
        let pair = &text.as_bytes()[idx * 2..idx * 2 + 2];
        key[idx] = (hex(pair[0]) << 4) | hex(pair[1]);
    }
    Ok(key)
}

fn hex(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

fn master_key() -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if let Some(value) = std::env::var_os("NMS_VAULT_KEY") {
        let value = value.to_str().ok_or(VaultError::InvalidMasterKey)?;
        return parse_hex_key(value);
    }
    let Some(path) = std::env::var_os("NMS_VAULT_KEY_FILE") else {
        return Err(VaultError::MissingMasterKey);
    };
    let path = PathBuf::from(path);
    #[cfg(unix)]
    {
        let metadata = fs::metadata(&path).map_err(|_| VaultError::MasterKeyFile)?;
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(VaultError::InsecureMasterKeyFile);
        }
    }
    #[cfg(not(unix))]
    fs::metadata(&path).map_err(|_| VaultError::MasterKeyFile)?;
    let value = fs::read_to_string(path).map_err(|_| VaultError::MasterKeyFile)?;
    parse_hex_key(value.trim())
}

fn aad(id: &str) -> Vec<u8> {
    format!("{SCHEMA}:credential:{id}").into_bytes()
}

fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode(text: &str) -> Result<Vec<u8>, VaultError> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(VaultError::RecordInvalid);
    }
    Ok((0..text.len() / 2)
        .map(|idx| {
            let pair = &text.as_bytes()[idx * 2..idx * 2 + 2];
            (hex(pair[0]) << 4) | hex(pair[1])
        })
        .collect())
}

fn restrictive_create(path: &Path) -> Result<fs::File, VaultError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|_| VaultError::Storage)
}

fn atomic_write(path: &Path, body: &[u8]) -> Result<(), VaultError> {
    let parent = path.parent().ok_or(VaultError::Storage)?;
    fs::create_dir_all(parent).map_err(|_| VaultError::Storage)?;
    // Credential references are write-once. Rotation is an explicit delete
    // followed by create. Hard-link publication is atomic and no-clobber on
    // Unix and Windows, unlike exists()+rename (which has a TOCTOU race).
    let mut suffix = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut suffix);
    let temp = parent.join(format!(".{}.tmp-{}", path.file_name().and_then(|x| x.to_str()).unwrap_or("vault"), encode(&suffix)));
    let result = (|| {
        let mut file = restrictive_create(&temp)?;
        use std::io::Write;
        file.write_all(body).map_err(|_| VaultError::Storage)?;
        file.sync_all().map_err(|_| VaultError::Storage)?;
        drop(file);
        fs::hard_link(&temp, path).map_err(|_| VaultError::Storage)
    })();
    let _ = fs::remove_file(&temp);
    result
}

pub fn write_secret(root: &Path, id: &str, secret: &[u8]) -> Result<(), VaultError> {
    let path = record_path(root, id)?;
    let key = master_key()?;
    let cipher = XChaCha20Poly1305::new(&Key::try_from(&key[..]).map_err(|_| VaultError::Storage)?);
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(&XNonce::try_from(&nonce[..]).map_err(|_| VaultError::Storage)?, chacha20poly1305::aead::Payload { msg: secret, aad: &aad(id) })
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let record = VaultRecord {
        version: VERSION,
        schema: SCHEMA.to_string(),
        credential_id: id.to_string(),
        nonce: encode(&nonce),
        ciphertext: encode(&encrypted),
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| VaultError::Storage)?;
    atomic_write(&path, &bytes)
}

pub fn read_secret(root: &Path, id: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let path = record_path(root, id)?;
    let bytes = fs::read(path).map_err(|_| VaultError::RecordNotFound)?;
    let record: VaultRecord = serde_json::from_slice(&bytes).map_err(|_| VaultError::RecordInvalid)?;
    if record.version != VERSION || record.schema != SCHEMA || record.credential_id != id {
        return Err(VaultError::RecordInvalid);
    }
    let nonce = decode(&record.nonce).map_err(|_| VaultError::RecordInvalid)?;
    if nonce.len() != 24 {
        return Err(VaultError::RecordInvalid);
    }
    let ciphertext = decode(&record.ciphertext).map_err(|_| VaultError::RecordInvalid)?;
    let key = master_key()?;
    let cipher = XChaCha20Poly1305::new(&Key::try_from(&key[..]).map_err(|_| VaultError::Storage)?);
    let plain = cipher
        .decrypt(&XNonce::try_from(&nonce[..]).map_err(|_| VaultError::Storage)?, chacha20poly1305::aead::Payload { msg: &ciphertext, aad: &aad(id) })
        .map_err(|_| VaultError::AuthenticationFailed)?;
    Ok(Zeroizing::new(plain))
}

pub fn delete_secret(root: &Path, id: &str) -> Result<(), VaultError> {
    let path = record_path(root, id)?;
    fs::remove_file(path).map_err(|_| VaultError::RecordNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_key<T>(f: impl FnOnce(&Path) -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("NMS_VAULT_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        std::env::remove_var("NMS_VAULT_KEY_FILE");
        let dir = tempfile::tempdir().unwrap();
        let out = f(dir.path());
        std::env::remove_var("NMS_VAULT_KEY");
        out
    }

    #[test]
    fn encryption_at_rest_roundtrip_and_unique_nonce() {
        with_key(|root| {
            write_secret(root, "router-key", b"PRIVATE KEY MATERIAL").unwrap();
            let first = fs::read(root.join("credentials/router-key.json")).unwrap();
            assert_eq!(
                write_secret(root, "router-key", b"REPLACEMENT"),
                Err(VaultError::Storage)
            );
            assert_eq!(
                &*read_secret(root, "router-key").unwrap(),
                b"PRIVATE KEY MATERIAL"
            );
            write_secret(root, "router-key-2", b"PRIVATE KEY MATERIAL").unwrap();
            let second = fs::read(root.join("credentials/router-key-2.json")).unwrap();
            assert_ne!(first, second);
            let first_nonce: serde_json::Value = serde_json::from_slice(&first).unwrap();
            let second_nonce: serde_json::Value = serde_json::from_slice(&second).unwrap();
            assert_ne!(first_nonce["nonce"], second_nonce["nonce"]);
            assert!(!String::from_utf8_lossy(&second).contains("PRIVATE KEY MATERIAL"));
        });
    }

    #[test]
    fn tamper_and_wrong_key_rejected() {
        with_key(|root| {
            write_secret(root, "tamper", b"secret").unwrap();
            write_secret(root, "wrong-key", b"secret").unwrap();
            let path = root.join("credentials/tamper.json");
            let mut bytes = fs::read(&path).unwrap();
            let idx = bytes.len() - 3;
            bytes[idx] = if bytes[idx] == b'0' { b'1' } else { b'0' };
            fs::write(&path, bytes).unwrap();
            assert_eq!(read_secret(root, "tamper"), Err(VaultError::AuthenticationFailed));
            std::env::set_var("NMS_VAULT_KEY", "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
            assert_eq!(read_secret(root, "wrong-key"), Err(VaultError::AuthenticationFailed));
            std::env::set_var("NMS_VAULT_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        });
    }

    #[test]
    fn env_key_precedes_file_and_invalid_env_does_not_fallback() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("master");
        fs::write(&key_file, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::env::set_var("NMS_VAULT_KEY_FILE", &key_file);
        std::env::set_var("NMS_VAULT_KEY", "bad");
        assert_eq!(master_key(), Err(VaultError::InvalidMasterKey));
        std::env::remove_var("NMS_VAULT_KEY");
        assert!(master_key().is_ok());
        std::env::remove_var("NMS_VAULT_KEY_FILE");
    }
}
