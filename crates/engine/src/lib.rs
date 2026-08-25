//! nms-engine: sweeps, inventory store, ops pipeline, diagnostics, jobs.
//! The domain core — no HTTP/UI dependencies.

pub mod arp;
pub mod auth;
pub mod cfgmod;
pub mod check;
pub mod db;
pub mod diag;
pub mod discover;
pub mod engine;
pub mod inspect;
pub mod jobs;
pub mod metrics;
pub mod model;
pub mod monitor;
pub mod neighbors;
pub mod netutil;
pub mod ops;
pub mod oui;
pub mod ping;
pub mod profile;
pub mod progress;
pub mod report;
pub mod reports;
pub mod routes;
pub mod snmpprobe;
pub mod snow;
pub mod trace;

/// Convenience re-exports for CLI consumers.
pub use engine::{sweep, Outcome, ScanParams, Target};
