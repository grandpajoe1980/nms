//! Lightweight structured logging: writes to stderr AND an optional log file
//! (output/nms.log) so wedges and failures are diagnosable after the fact.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

static LOG_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Enable file logging. Call once at startup (serve/monitor) with the output
/// dir's nms.log path. Safe to call multiple times; first call wins.
pub fn init(path: PathBuf) {
    let _ = LOG_PATH.set(Some(path));
}

fn timestamp() -> String {
    chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f").to_string()
}

pub fn log(level: &str, msg: &str) {
    let line = format!("[{}][{}] {}", timestamp(), level, msg);
    eprintln!("{line}");
    if let Some(Some(path)) = LOG_PATH.get() {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{line}");
        }
    }
}

pub fn info(msg: &str) {
    log("INFO", msg);
}

pub fn warn(msg: &str) {
    log("WARN", msg);
}

pub fn error(msg: &str) {
    log("ERROR", msg);
}
