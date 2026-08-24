use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Router,
    Wap,
    Endpoint,
}

impl Role {
    pub fn label(&self) -> &'static str {
        match self {
            Role::Router => "router",
            Role::Wap => "wap",
            Role::Endpoint => "endpoint",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Up,
    Down,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Device {
    pub ip: Ipv4Addr,
    #[serde(default)]
    pub mac: Option<String>,
    pub role: Role,
    pub state: State,
    #[serde(default)]
    pub subnet: Option<String>,
    #[serde(default)]
    pub rtt_ms: Option<f64>,
    #[serde(default)]
    pub reply_ttl: Option<u8>,
    #[serde(default)]
    pub hint: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(default)]
    pub down_since: Option<String>,
    #[serde(default)]
    pub ever_up: bool,
    #[serde(default)]
    pub wap: Option<Ipv4Addr>,
    #[serde(default)]
    pub wap_source: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub device_class: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Subnet {
    pub cidr: String,
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub sampled: bool,
    #[serde(default)]
    pub hosts: u64,
    #[serde(default)]
    pub probed: u64,
    #[serde(default)]
    pub alive: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Edge {
    pub src: String,
    pub dst: String,
    pub kind: String,
}

#[derive(Serialize, Deserialize)]
pub struct Model {
    pub generated_at: String,
    pub scan_duration_ms: u64,
    pub backend: String,
    pub subnets: Vec<Subnet>,
    pub devices: Vec<Device>,
    pub edges: Vec<Edge>,
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}

impl Model {
    pub fn new() -> Self {
        Model {
            generated_at: chrono::Utc::now().to_rfc3339(),
            scan_duration_ms: 0,
            backend: String::new(),
            subnets: Vec::new(),
            devices: Vec::new(),
            edges: Vec::new(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Model> {
        let json = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn device_index(&self) -> HashMap<Ipv4Addr, usize> {
        self.devices.iter().enumerate().map(|(i, d)| (d.ip, i)).collect()
    }

    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let up = self.devices.iter().filter(|d| d.state == State::Up).count();
        let down = self.devices.iter().filter(|d| d.state == State::Down).count();
        let routers = self.devices.iter().filter(|d| d.role == Role::Router).count();
        let waps = self.devices.iter().filter(|d| d.role == Role::Wap).count();
        (up, down, routers, waps)
    }
}
