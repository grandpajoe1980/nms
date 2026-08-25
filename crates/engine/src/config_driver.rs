//! Read-only configuration drivers (FR-CFG-002, FR-CFG-003).
//!
//! The SSH implementation is intentionally behind the `ssh` feature.  The
//! default binary retains the cheap discovery path; enabling `ssh` opts into
//! the heavier config-read transport from the dedicated `inspect` pass.

use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

/// Supported command profiles for the first config-read vertical slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigProfile {
    CiscoIosXe,
    ArubaAosCx,
}

impl ConfigProfile {
    pub fn commands(self) -> &'static [&'static str] {
        match self {
            Self::CiscoIosXe => &["terminal length 0", "terminal width 0", "show running-config"],
            Self::ArubaAosCx => &["no paging", "show running-config"],
        }
    }
}

impl fmt::Display for ConfigProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CiscoIosXe => "cisco-ios-xe",
            Self::ArubaAosCx => "aruba-aos-cx",
        })
    }
}

impl FromStr for ConfigProfile {
    type Err = ConfigProfileParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "cisco-ios-xe" | "ios-xe" | "cisco" => Ok(Self::CiscoIosXe),
            "aruba-aos-cx" | "aos-cx" | "aruba" => Ok(Self::ArubaAosCx),
            _ => Err(ConfigProfileParseError),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ConfigProfileParseError;

impl fmt::Display for ConfigProfileParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unsupported config profile (use cisco-ios-xe or aruba-aos-cx)")
    }
}

impl std::error::Error for ConfigProfileParseError {}

/// SSH connection settings.  Credentials are references only: no password,
/// key bytes, or known-host contents are accepted by this type.
#[derive(Clone)]
pub struct SshConfigOptions {
    pub host: IpAddr,
    pub port: u16,
    pub username: String,
    pub credential_ref: String,
    pub vault_dir: PathBuf,
    pub known_hosts_path: PathBuf,
    pub timeout_ms: u64,
    pub profile: ConfigProfile,
}

impl fmt::Debug for SshConfigOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshConfigOptions")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("credential_ref", &"<credential reference>")
            .field("vault_dir", &"<vault reference>")
            .field("known_hosts_path", &"<known-hosts reference>")
            .field("timeout_ms", &self.timeout_ms)
            .field("profile", &self.profile)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ConfigReadError {
    FeatureDisabled,
    InvalidOptions,
    KeyReferenceUnavailable,
    KnownHostsUnavailable,
    HostKeyRejected,
    ConnectionFailed,
    AuthenticationFailed,
    CommandFailed,
    OutputInvalid,
}

impl fmt::Display for ConfigReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FeatureDisabled => "SSH config backup is unavailable (build with --features ssh)",
            Self::InvalidOptions => "SSH config backup options are invalid",
            Self::KeyReferenceUnavailable => "SSH key reference could not be read",
            Self::KnownHostsUnavailable => "known-hosts reference could not be read",
            Self::HostKeyRejected => "SSH server host key was not accepted by known-hosts",
            Self::ConnectionFailed => "SSH connection failed",
            Self::AuthenticationFailed => "SSH public-key authentication failed",
            Self::CommandFailed => "SSH config-read command failed",
            Self::OutputInvalid => "SSH config-read output was invalid",
        })
    }
}

impl std::error::Error for ConfigReadError {}

/// Parse a recorded command session into normalized configuration text.
/// Fixtures may use explicit markers; live CLI output is also handled by
/// taking the body after `show running-config` through the `end` line.
pub fn extract_config(profile: ConfigProfile, session: &str) -> Result<String, ConfigReadError> {
    let text = session.replace("\r\n", "\n");
    let body = if let (Some(start), Some(end)) = (
        text.find("--- BEGIN CONFIG ---"),
        text.find("--- END CONFIG ---"),
    ) {
        let start = start + "--- BEGIN CONFIG ---".len();
        &text[start..end]
    } else {
        let marker = profile
            .commands()
            .iter()
            .find(|command| command.starts_with("show running-config"))
            .copied()
            .ok_or(ConfigReadError::OutputInvalid)?;
        let start = text
            .lines()
            .position(|line| line.trim_end().ends_with(marker))
            .ok_or(ConfigReadError::OutputInvalid)?;
        let lines: Vec<&str> = text.lines().skip(start + 1).collect();
        let end = lines
            .iter()
            .position(|line| line.trim() == "end")
            .map(|i| i + 1)
            .unwrap_or(lines.len());
        return normalize_config(&lines[..end].join("\n"));
    };
    normalize_config(body)
}

fn normalize_config(config: &str) -> Result<String, ConfigReadError> {
    let lines: Vec<&str> = config
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.is_empty() {
        return Err(ConfigReadError::OutputInvalid);
    }
    Ok(format!("{}\n", lines.join("\n")))
}

#[cfg(not(feature = "ssh"))]
pub fn read_config_raw(_options: &SshConfigOptions) -> Result<String, ConfigReadError> {
    validate_ssh_references(_options)?;
    Err(ConfigReadError::FeatureDisabled)
}

#[cfg(feature = "ssh")]
pub fn read_config_raw(options: &SshConfigOptions) -> Result<String, ConfigReadError> {
    validate_ssh_references(options)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| ConfigReadError::ConnectionFailed)?;
    runtime.block_on(read_config_async(options))
}

fn validate_ssh_references(options: &SshConfigOptions) -> Result<(), ConfigReadError> {
    if options.username.trim().is_empty() || options.port == 0 || options.timeout_ms == 0 {
        return Err(ConfigReadError::InvalidOptions);
    }
    if !options.known_hosts_path.is_file() {
        return Err(ConfigReadError::KnownHostsUnavailable);
    }
    Ok(())
}

pub fn read_config(options: &SshConfigOptions) -> Result<String, ConfigReadError> {
    let raw = read_config_raw(options)?;
    extract_config(options.profile, &raw)
}

pub fn ssh_feature_enabled() -> bool {
    cfg!(feature = "ssh")
}

#[cfg(feature = "ssh")]
async fn read_config_async(options: &SshConfigOptions) -> Result<String, ConfigReadError> {
    use std::sync::Arc;
    use std::time::Duration;
    use russh::client::Handler;
    use russh::keys::{decode_secret_key, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
    use russh::{client, ChannelMsg, Disconnect};

    struct StrictHostKeyHandler {
        host: String,
        port: u16,
        known_hosts: PathBuf,
    }

    impl Handler for StrictHostKeyHandler {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            server_public_key: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(host_key_is_trusted(
                &self.host,
                self.port,
                &server_public_key.public_key(),
                &self.known_hosts,
            ))
        }
    }

    let secret = crate::vault::read_secret(&options.vault_dir, &options.credential_ref)
        .map_err(|_| ConfigReadError::KeyReferenceUnavailable)?;
    let secret_text = std::str::from_utf8(&secret).map_err(|_| ConfigReadError::KeyReferenceUnavailable)?;
    let key = decode_secret_key(secret_text, None)
        .map_err(|_| ConfigReadError::KeyReferenceUnavailable)?;
    let host = options.host.to_string();
    let handler = StrictHostKeyHandler {
        host: host.clone(),
        port: options.port,
        known_hosts: options.known_hosts_path.clone(),
    };
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_millis(options.timeout_ms)),
        ..Default::default()
    });
    let mut session = tokio::time::timeout(
        Duration::from_millis(options.timeout_ms),
        client::connect(config, (host.as_str(), options.port), handler),
    )
    .await
    .map_err(|_| ConfigReadError::ConnectionFailed)?
    .map_err(|_| ConfigReadError::ConnectionFailed)?;
    let auth = session
        .authenticate_publickey(
            options.username.clone(),
            PrivateKeyWithHashAlg::new(
                Arc::new(key),
                session
                    .best_supported_rsa_hash()
                    .await
                    .map_err(|_| ConfigReadError::AuthenticationFailed)?
                    .flatten(),
            ),
        )
        .await
        .map_err(|_| ConfigReadError::AuthenticationFailed)?;
    if !auth.success() {
        return Err(ConfigReadError::AuthenticationFailed);
    }

    // Use one interactive channel so paging changes apply to the subsequent
    // `show running-config` command on IOS-XE/AOS-CX.
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|_| ConfigReadError::CommandFailed)?;
    channel
        .request_pty(true, "vt100", 240, 80, 0, 0, &[])
        .await
        .map_err(|_| ConfigReadError::CommandFailed)?;
    channel
        .request_shell(true)
        .await
        .map_err(|_| ConfigReadError::CommandFailed)?;
    let script = format!("{}\nexit\n", options.profile.commands().join("\n"));
    channel
        .data_bytes(script)
        .await
        .map_err(|_| ConfigReadError::CommandFailed)?;
    channel
        .eof()
        .await
        .map_err(|_| ConfigReadError::CommandFailed)?;
    let mut output = String::new();
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                output.push_str(&String::from_utf8_lossy(&data));
            }
            _ => {}
        }
    }
    let _ = session.disconnect(Disconnect::ByApplication, "", "English").await;
    Ok(output)
}

#[cfg(feature = "ssh")]
fn host_key_is_trusted(
    host: &str,
    port: u16,
    key: &russh::keys::PublicKey,
    known_hosts: &std::path::Path,
) -> bool {
    russh::keys::check_known_hosts_path(host, port, key, known_hosts).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CISCO: &str = include_str!("../../../fixtures/configs/cisco-ios-xe-session.txt");
    const ARUBA: &str = include_str!("../../../fixtures/configs/aruba-aos-cx-session.txt");

    #[test]
    fn profiles_expose_vendor_paging_and_config_commands() {
        assert_eq!(ConfigProfile::CiscoIosXe.commands()[0], "terminal length 0");
        assert_eq!(ConfigProfile::CiscoIosXe.commands()[2], "show running-config");
        assert_eq!(ConfigProfile::ArubaAosCx.commands()[0], "no paging");
        assert_eq!(ConfigProfile::ArubaAosCx.commands()[1], "show running-config");
    }

    #[test]
    fn recorded_sessions_extract_both_profiles() {
        let cisco = extract_config(ConfigProfile::CiscoIosXe, CISCO).unwrap();
        let aruba = extract_config(ConfigProfile::ArubaAosCx, ARUBA).unwrap();
        assert!(cisco.contains("hostname edge-r1"));
        assert!(cisco.ends_with("end\n"));
        assert!(aruba.contains("hostname edge-sw1"));
        assert!(aruba.ends_with("end\n"));
    }

    #[test]
    fn options_debug_and_errors_never_include_secret_material() {
        let opts = SshConfigOptions {
            host: "192.0.2.1".parse().unwrap(),
            port: 22,
            username: "netops".into(),
            credential_ref: "private-secret-key".into(),
            vault_dir: PathBuf::from("vault"),
            known_hosts_path: PathBuf::from("known-hosts-secret"),
            timeout_ms: 1000,
            profile: ConfigProfile::CiscoIosXe,
        };
        let debug = format!("{opts:?}");
        assert!(!debug.contains("private-secret-key"));
        assert!(!debug.contains("known-hosts-secret"));
        assert!(!ConfigReadError::AuthenticationFailed.to_string().contains("netops"));
    }

    #[test]
    fn missing_known_hosts_fails_closed_before_any_connection() {
        let dir = tempfile::tempdir().unwrap();
        let opts = SshConfigOptions {
            host: "192.0.2.1".parse().unwrap(),
            port: 22,
            username: "netops".into(),
            credential_ref: "missing".into(),
            vault_dir: dir.path().to_path_buf(),
            known_hosts_path: dir.path().join("missing-known-hosts"),
            timeout_ms: 1000,
            profile: ConfigProfile::CiscoIosXe,
        };
        assert_eq!(read_config_raw(&opts), Err(ConfigReadError::KnownHostsUnavailable));
    }

    #[cfg(not(feature = "ssh"))]
    #[test]
    fn default_build_reports_feature_disabled_for_valid_references() {
        let dir = tempfile::tempdir().unwrap();
        let known_hosts = dir.path().join("known_hosts");
        std::fs::write(&known_hosts, "").unwrap();
        let opts = SshConfigOptions {
            host: "192.0.2.1".parse().unwrap(),
            port: 22,
            username: "netops".into(),
            credential_ref: "missing".into(),
            vault_dir: dir.path().to_path_buf(),
            known_hosts_path: known_hosts,
            timeout_ms: 1000,
            profile: ConfigProfile::CiscoIosXe,
        };
        assert_eq!(read_config_raw(&opts), Err(ConfigReadError::FeatureDisabled));
        assert!(!ssh_feature_enabled());
    }

    #[cfg(feature = "ssh")]
    #[test]
    fn unknown_host_key_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let known_hosts = dir.path().join("known_hosts");
        std::fs::write(
            &known_hosts,
            "192.0.2.2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ\n",
        )
        .unwrap();
        let key = russh::keys::PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ",
        )
        .unwrap();
        assert!(!host_key_is_trusted("192.0.2.1", 22, &key, &known_hosts));
    }
}
