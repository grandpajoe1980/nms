// Temporary until all consumers land (removed during integration).
#![allow(dead_code)]

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Row};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

pub const DEFAULT_SETTINGS: &[(&str, &str)] = &[
    ("poll_interval_secs", "60"),
    ("rtt_warn_ms", "150"),
    ("rtt_crit_ms", "400"),
    ("loss_window", "6"),
    ("loss_warn_pct", "33"),
    ("flap_window_mins", "30"),
    ("flap_threshold", "5"),
    ("raw_retention_hours", "36"),
    ("hourly_retention_days", "14"),
    ("daily_retention_days", "400"),
    ("absent_retire_days", "30"),
    ("webhook_url", ""),
    ("webhook_enabled", "0"),
    ("site_auto_prefix", "24"),
    ("sla_target_pct", "99.5"),
];

pub struct Db {
    conn: Mutex<Connection>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct DeviceRec {
    pub id: i64,
    pub ip: String,
    pub mac: Option<String>,
    pub name: Option<String>,
    pub role: String,
    pub site_id: Option<i64>,
    pub site_source: String,
    pub parent_id: Option<i64>,
    pub managed: bool,
    pub poll_secs: Option<i64>,
    pub first_seen_ts: i64,
    pub last_seen_ts: i64,
    pub ever_up: bool,
    pub state: String,
    pub eff_state: String,
    pub perf_status: String,
    pub down_since_ts: Option<i64>,
    pub maintenance_until_ts: Option<i64>,
        pub flap_count: i64,
    pub stable_cycles: i64,
    pub hostname: Option<String>,
    pub device_class: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct Sample {
    pub device_id: i64,
    pub ts_millis: i64,
    pub up: bool,
    pub rtt_ms: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub id: i64,
    pub device_id: i64,
    pub state: String,
    pub started_ts: i64,
    pub ended_ts: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct EventRec {
    pub id: i64,
    pub created_ts: i64,
    pub updated_ts: Option<i64>,
    pub device_id: Option<i64>,
    pub ip: Option<String>,
    pub kind: String,
    pub severity: String,
    pub state: String,
    pub message: String,
    pub details: Option<String>,
    pub acknowledged: bool,
    pub ack_by: Option<String>,
    pub ack_ts: Option<i64>,
    pub cleared_ts: Option<i64>,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn now_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("open sqlite {}", path.display()))?;
        Self::init(conn)
    }

    pub fn open_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        // Lightweight migrations (ignore failures when column already exists).
        for stmt in [
            "ALTER TABLE devices ADD COLUMN hostname TEXT",
            "ALTER TABLE devices ADD COLUMN device_class TEXT",
            "ALTER TABLE devices ADD COLUMN stable_cycles INTEGER NOT NULL DEFAULT 0",
        ] {
            let _ = conn.execute(stmt, []);
        }
        for (k, v) in DEFAULT_SETTINGS {
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES (?1, ?2)",
                params![k, v],
            )?;
        }
        Ok(Db { conn: Mutex::new(conn) })
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta(
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL UNIQUE,
  region     TEXT,
  created_ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices(
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  ip                   TEXT NOT NULL UNIQUE,
  mac                  TEXT,
  name                 TEXT,
  role                 TEXT NOT NULL,
  site_id              INTEGER REFERENCES sites(id),
  site_source          TEXT NOT NULL DEFAULT 'auto',
  parent_id            INTEGER REFERENCES devices(id),
  managed              INTEGER NOT NULL DEFAULT 1,
  poll_secs            INTEGER,
  first_seen_ts        INTEGER NOT NULL,
  last_seen_ts         INTEGER NOT NULL,
  ever_up              INTEGER NOT NULL DEFAULT 0,
  state                TEXT NOT NULL DEFAULT 'unknown',
  eff_state            TEXT NOT NULL DEFAULT 'unknown',
  perf_status          TEXT NOT NULL DEFAULT 'ok',
  down_since_ts        INTEGER,
  maintenance_until_ts INTEGER,
  flap_count           INTEGER NOT NULL DEFAULT 0,
  notes                TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_site ON devices(site_id);
CREATE INDEX IF NOT EXISTS idx_devices_parent ON devices(parent_id);
CREATE INDEX IF NOT EXISTS idx_devices_eff ON devices(eff_state);
CREATE TABLE IF NOT EXISTS samples(
  device_id INTEGER NOT NULL,
  ts        INTEGER NOT NULL,
  up        INTEGER NOT NULL,
  rtt_ms    REAL,
  PRIMARY KEY (device_id, ts)
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
CREATE TABLE IF NOT EXISTS rollup_hourly(
  device_id   INTEGER NOT NULL,
  hour        INTEGER NOT NULL,
  probes      INTEGER NOT NULL,
  ups         INTEGER NOT NULL,
  rtt_sum     REAL NOT NULL DEFAULT 0,
  rtt_min     REAL,
  rtt_max     REAL,
  jitter_sum  REAL NOT NULL DEFAULT 0,
  jitter_n    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (device_id, hour)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_rollup_hourly_hour ON rollup_hourly(hour);
CREATE TABLE IF NOT EXISTS rollup_daily(
  device_id  INTEGER NOT NULL,
  day        INTEGER NOT NULL,
  probes     INTEGER NOT NULL,
  ups        INTEGER NOT NULL,
  rtt_sum    REAL NOT NULL DEFAULT 0,
  PRIMARY KEY (device_id, day)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_rollup_daily_day ON rollup_daily(day);
CREATE TABLE IF NOT EXISTS segments(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id  INTEGER NOT NULL,
  state      TEXT NOT NULL,
  started_ts INTEGER NOT NULL,
  ended_ts   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_segments_dev ON segments(device_id, started_ts);
CREATE INDEX IF NOT EXISTS idx_segments_open ON segments(state) WHERE ended_ts IS NULL;
CREATE TABLE IF NOT EXISTS events(
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  created_ts   INTEGER NOT NULL,
  updated_ts   INTEGER,
  device_id    INTEGER,
  ip           TEXT,
  kind         TEXT NOT NULL,
  severity     TEXT NOT NULL,
  state        TEXT NOT NULL DEFAULT 'open',
  message      TEXT NOT NULL,
  details      TEXT,
  acknowledged INTEGER NOT NULL DEFAULT 0,
  ack_by       TEXT,
  ack_ts       INTEGER,
  cleared_ts   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_open ON events(state, severity, created_ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id, kind, state);
CREATE TABLE IF NOT EXISTS audit_log(
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      INTEGER NOT NULL,
  actor   TEXT NOT NULL,
  action  TEXT NOT NULL,
  target  TEXT,
  details TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
CREATE TABLE IF NOT EXISTS outbound(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  created_ts INTEGER NOT NULL,
  sent_ts    INTEGER,
  status     TEXT NOT NULL DEFAULT 'pending',
  tries      INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  event_id   INTEGER,
  payload    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outbound_status ON outbound(status, created_ts);
CREATE TABLE IF NOT EXISTS device_diag(
  device_id INTEGER PRIMARY KEY,
  ts        INTEGER NOT NULL,
  sent      INTEGER NOT NULL,
  recv      INTEGER NOT NULL,
  loss_pct  REAL NOT NULL,
  rtt_min   REAL,
  rtt_avg   REAL,
  rtt_max   REAL,
  rtt_p95   REAL,
  jitter_ms REAL,
  score     INTEGER NOT NULL,
  verdict   TEXT NOT NULL,
  open_ports TEXT,
  method    TEXT
);
CREATE TABLE IF NOT EXISTS users(
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL,
  disabled      INTEGER NOT NULL DEFAULT 0,
  created_ts    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  role       TEXT NOT NULL,
  created_ts INTEGER NOT NULL,
  expires_ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens(
  token_hash TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  role       TEXT NOT NULL,
  disabled   INTEGER NOT NULL DEFAULT 0,
  created_ts INTEGER NOT NULL
);
"#;

// ---------------------------------------------------------------- settings

pub fn get_setting(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        params![key],
        |r| r.get(0),
    )
    .optional()
    .ok()
    .flatten()
}

pub fn get_setting_or(conn: &Connection, key: &str, default: &str) -> String {
    get_setting(conn, key).unwrap_or_else(|| default.to_string())
}

pub fn set_setting(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn all_settings(conn: &Connection) -> HashMap<String, String> {
    let mut stmt = match conn.prepare("SELECT key, value FROM meta") {
        Ok(s) => s,
        Err(_) => return HashMap::new(),
    };
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .ok();
    let mut out = HashMap::new();
    if let Some(rows) = rows {
        for row in rows.flatten() {
            out.insert(row.0, row.1);
        }
    }
    out
}

// ------------------------------------------------------------------- audit

pub fn audit(conn: &Connection, actor: &str, action: &str, target: &str, details: &str) {
    let _ = conn.execute(
        "INSERT INTO audit_log(ts, actor, action, target, details) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![now(), actor, action, target, details],
    );
}

// ------------------------------------------------------------------- sites

pub fn ensure_site(conn: &Connection, name: &str) -> Result<i64> {
    let existing: Option<i64> = conn
        .query_row("SELECT id FROM sites WHERE name = ?1", params![name], |r| r.get(0))
        .optional()?;
    if let Some(id) = existing {
        return Ok(id);
    }
    conn.execute(
        "INSERT INTO sites(name, created_ts) VALUES (?1, ?2)",
        params![name, now()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn site_name(conn: &Connection, site_id: Option<i64>) -> String {
    let Some(id) = site_id else { return "-".into() };
    conn.query_row("SELECT name FROM sites WHERE id = ?1", params![id], |r| {
        r.get::<_, String>(0)
    })
    .optional()
    .ok()
    .flatten()
    .unwrap_or_else(|| "-".into())
}

/// Auto-site label from an IPv4 address using the configured prefix length.
pub fn auto_site_label(ip: &str, prefix: u8) -> Option<String> {
    let addr: std::net::Ipv4Addr = ip.parse().ok()?;
    let octets = addr.octets();
    let keep = (prefix as usize).clamp(8, 32).div_ceil(8);
    let parts: Vec<String> =
        octets.iter().take(keep).map(|b| b.to_string()).collect();
    Some(format!("{}/{}", parts.join("."), prefix))
}

// ----------------------------------------------------------------- devices

fn row_device(r: &Row) -> rusqlite::Result<DeviceRec> {
    Ok(DeviceRec {
        id: r.get(0)?,
        ip: r.get(1)?,
        mac: r.get(2)?,
        name: r.get(3)?,
        role: r.get(4)?,
        site_id: r.get(5)?,
        site_source: r.get(6)?,
        parent_id: r.get(7)?,
        managed: r.get::<_, i64>(8)? != 0,
        poll_secs: r.get(9)?,
        first_seen_ts: r.get(10)?,
        last_seen_ts: r.get(11)?,
        ever_up: r.get::<_, i64>(12)? != 0,
        state: r.get(13)?,
        eff_state: r.get(14)?,
        perf_status: r.get(15)?,
        down_since_ts: r.get(16)?,
        maintenance_until_ts: r.get(17)?,
        flap_count: r.get(18)?,
        stable_cycles: r.get(19)?,
        hostname: r.get(20)?,
        device_class: r.get(21)?,
    })
}

const DEVICE_COLS: &str = "id, ip, mac, name, role, site_id, site_source, parent_id, managed,
     poll_secs, first_seen_ts, last_seen_ts, ever_up, state, eff_state, perf_status,
     down_since_ts, maintenance_until_ts, flap_count, stable_cycles, hostname, device_class";

pub fn device_by_ip(conn: &Connection, ip: &str) -> Result<Option<DeviceRec>> {
    let sql = format!("SELECT {DEVICE_COLS} FROM devices WHERE ip = ?1");
    Ok(conn
        .query_row(&sql, params![ip], row_device)
        .optional()?)
}

pub fn device_by_id(conn: &Connection, id: i64) -> Result<Option<DeviceRec>> {
    let sql = format!("SELECT {DEVICE_COLS} FROM devices WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], row_device)
        .optional()?)
}

pub fn all_devices(conn: &Connection) -> Result<Vec<DeviceRec>> {
    let sql = format!("SELECT {DEVICE_COLS} FROM devices ORDER BY ip");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], row_device)?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub struct DeviceUpdate<'a> {
    pub ip: &'a str,
    pub mac: Option<String>,
    pub role: &'a str,
    pub subnet_site_label: Option<String>,
    pub parent_ip: Option<&'a str>,
    pub state: &'a str,
    pub up_now: bool,
    pub rtt_ms: Option<f64>,
    pub ts: i64,
    pub site_prefix: u8,
    pub hostname: Option<String>,
    pub device_class: Option<String>,
}

/// Upsert by IP. Manual site assignment (`site_source='manual'`) and the
/// maintenance window are never overwritten by automatic sync.
pub fn upsert_device(conn: &Connection, u: &DeviceUpdate) -> Result<DeviceRec> {
    let existing = device_by_ip(conn, u.ip)?;
    let site_id = match existing.as_ref().and_then(|d| d.site_id) {
        Some(id) if existing.as_ref().is_some_and(|d| d.site_source == "manual") => Some(id),
        _ => match &u.subnet_site_label {
            Some(label) => Some(ensure_site(conn, label)?),
            None => None,
        },
    };
    let site_source = if existing.as_ref().is_some_and(|d| d.site_source == "manual") {
        "manual".to_string()
    } else if u.subnet_site_label.is_some() {
        "auto".to_string()
    } else {
        existing
            .as_ref()
            .map(|d| d.site_source.clone())
            .unwrap_or_else(|| "auto".into())
    };
    let parent_id = match u.parent_ip {
        Some(pip) => device_by_ip(conn, pip)?.map(|p| p.id),
        None => None,
    };
    let mac = u.mac.clone().or_else(|| existing.as_ref().and_then(|d| d.mac.clone()));
    let hostname = u
        .hostname
        .clone()
        .or_else(|| existing.as_ref().and_then(|d| d.hostname.clone()));
    let device_class = u
        .device_class
        .clone()
        .or_else(|| existing.as_ref().and_then(|d| d.device_class.clone()));
    let ever_up = existing.as_ref().is_some_and(|d| d.ever_up) || u.up_now;
    let (first, last) = match &existing {
        Some(d) => (d.first_seen_ts, u.ts),
        None => (u.ts, u.ts),
    };
    conn.execute(
        "INSERT INTO devices(ip, mac, role, site_id, site_source, parent_id, first_seen_ts,
             last_seen_ts, ever_up, state, hostname, device_class)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(ip) DO UPDATE SET
             mac = excluded.mac,
             role = excluded.role,
             site_id = COALESCE(CASE WHEN devices.site_source = 'manual'
                                     THEN devices.site_id END, excluded.site_id),
             site_source = excluded.site_source,
             parent_id = excluded.parent_id,
             last_seen_ts = excluded.last_seen_ts,
             ever_up = MAX(devices.ever_up, excluded.ever_up),
             state = excluded.state,
             hostname = COALESCE(excluded.hostname, devices.hostname),
             device_class = COALESCE(excluded.device_class, devices.device_class)",
        params![
            u.ip,
            mac,
            u.role,
            site_id,
            site_source,
            parent_id,
            first,
            last,
            ever_up as i64,
            u.state,
            hostname,
            device_class
        ],
    )?;
    let rec = device_by_ip(conn, u.ip)?.context("device vanished after upsert")?;
    Ok(rec)
}

pub fn set_device_fields(
    conn: &Connection,
    id: i64,
    eff_state: &str,
    perf_status: &str,
    down_since_ts: Option<i64>,
    flap_count: i64,
    stable_cycles: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE devices SET eff_state = ?2, perf_status = ?3, down_since_ts = ?4,
             flap_count = ?5, stable_cycles = ?6 WHERE id = ?1",
        params![id, eff_state, perf_status, down_since_ts, flap_count, stable_cycles],
    )?;
    Ok(())
}

pub fn assign_site(conn: &Connection, id: i64, site_name_opt: Option<&str>) -> Result<()> {
    match site_name_opt {
        Some(name) => {
            let sid = ensure_site(conn, name)?;
            conn.execute(
                "UPDATE devices SET site_id = ?2, site_source = 'manual' WHERE id = ?1",
                params![id, sid],
            )?;
        }
        None => {
            conn.execute(
                "UPDATE devices SET site_id = NULL, site_source = 'auto' WHERE id = ?1",
                params![id],
            )?;
        }
    }
    Ok(())
}

pub fn set_maintenance(conn: &Connection, id: i64, until_ts: Option<i64>) -> Result<()> {
    conn.execute(
        "UPDATE devices SET maintenance_until_ts = ?2 WHERE id = ?1",
        params![id, until_ts],
    )?;
    Ok(())
}

pub fn set_managed(conn: &Connection, id: i64, managed: bool) -> Result<()> {
    conn.execute(
        "UPDATE devices SET managed = ?2 WHERE id = ?1",
        params![id, managed as i64],
    )?;
    Ok(())
}

// ----------------------------------------------------------------- samples

pub fn insert_samples(conn: &Connection, batch: &[Sample]) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    // NOTE: runs inside the caller's transaction when called from ops; the
    // prepared statement batches all rows on one connection either way.
    let mut stmt = conn.prepare("INSERT OR REPLACE INTO samples(device_id, ts, up, rtt_ms)
                                 VALUES (?1, ?2, ?3, ?4)")?;
    for s in batch {
        stmt.execute(params![s.device_id, s.ts_millis, s.up as i64, s.rtt_ms])?;
    }
    Ok(())
}

/// Recompute one device-hour rollup from raw samples, including jitter
/// (mean absolute delta between consecutive RTTs).
pub fn recompute_hourly_rollup(conn: &Connection, device_id: i64, hour_start_secs: i64) -> Result<()> {
    let lo = hour_start_secs * 1000;
    let hi = lo + 3_600_000;
    let mut stmt = conn.prepare(
        "SELECT ts, up, rtt_ms FROM samples
         WHERE device_id = ?1 AND ts >= ?2 AND ts < ?3 ORDER BY ts",
    )?;
    let rows: Vec<(i64, bool, Option<f64>)> = stmt
        .query_map(params![device_id, lo, hi], |r| {
            Ok((r.get(0)?, r.get::<_, i64>(1)? != 0, r.get(2)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(stmt);

    let probes = rows.len() as i64;
    let ups = rows.iter().filter(|(_, up, _)| *up).count() as i64;
    let rtts: Vec<f64> = rows.iter().filter_map(|(_, _, r)| *r).collect();
    let rtt_sum: f64 = rtts.iter().sum();
    let rtt_min = rtts.iter().cloned().fold(f64::NAN, f64::min);
    let rtt_max = rtts.iter().cloned().fold(f64::NAN, f64::max);
    let rtt_min = if rtt_min.is_nan() { None } else { Some(rtt_min) };
    let rtt_max = if rtt_max.is_nan() { None } else { Some(rtt_max) };
    let mut jitter_sum = 0.0;
    let mut jitter_n = 0i64;
    for w in rtts.windows(2) {
        jitter_sum += (w[1] - w[0]).abs();
        jitter_n += 1;
    }
    conn.execute(
        "INSERT INTO rollup_hourly(device_id, hour, probes, ups, rtt_sum, rtt_min, rtt_max,
                                   jitter_sum, jitter_n)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(device_id, hour) DO UPDATE SET
             probes = excluded.probes, ups = excluded.ups, rtt_sum = excluded.rtt_sum,
             rtt_min = excluded.rtt_min, rtt_max = excluded.rtt_max,
             jitter_sum = excluded.jitter_sum, jitter_n = excluded.jitter_n",
        params![device_id, hour_start_secs, probes, ups, rtt_sum, rtt_min, rtt_max, jitter_sum, jitter_n],
    )?;
    Ok(())
}

/// Aggregate finished hours into daily rollups (pure SQL, run periodically).
pub fn refresh_daily_rollups(conn: &Connection, day_start_secs: i64) -> Result<()> {
    let lo = day_start_secs;
    let hi = lo + 86_400;
    conn.execute(
        "INSERT INTO rollup_daily(device_id, day, probes, ups, rtt_sum)
         SELECT device_id, ?1, SUM(probes), SUM(ups), SUM(rtt_sum)
         FROM rollup_hourly WHERE hour >= ?1 AND hour < ?2
         GROUP BY device_id
         ON CONFLICT(device_id, day) DO UPDATE SET
             probes = excluded.probes, ups = excluded.ups, rtt_sum = excluded.rtt_sum",
        params![day_start_secs, hi],
    )?;
    Ok(())
}

pub fn recent_rtt_series(conn: &Connection, device_id: i64, limit: usize) -> Result<Vec<(i64, Option<f64>)>> {
    let mut stmt = conn.prepare(
        "SELECT ts, rtt_ms FROM samples WHERE device_id = ?1 AND up = 1
         ORDER BY ts DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![device_id, limit as i64], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, Option<f64>>(1)?))
    })?;
    let mut v: Vec<_> = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    v.reverse();
    Ok(v)
}

pub fn uptime_pct_window(conn: &Connection, device_id: i64, since_secs: i64) -> Option<f64> {
    conn.query_row(
        "SELECT 100.0 * SUM(ups) / NULLIF(SUM(probes), 0)
         FROM rollup_hourly WHERE device_id = ?1 AND hour >= ?2",
        params![device_id, since_secs],
        |r| r.get(0),
    )
    .optional()
    .ok()
    .flatten()
}

pub fn mttr_secs_window(conn: &Connection, since_secs: i64) -> Option<f64> {
    conn.query_row(
        "SELECT AVG(ended_ts - started_ts) FROM segments
         WHERE state = 'down' AND ended_ts IS NOT NULL AND started_ts >= ?1",
        params![since_secs],
        |r| r.get(0),
    )
    .optional()
    .ok()
    .flatten()
}

// ---------------------------------------------------------------- segments

pub fn open_segment(conn: &Connection, device_id: i64, state: &str, ts: i64) -> Result<i64> {
    close_open_segments(conn, device_id, ts)?;
    conn.execute(
        "INSERT INTO segments(device_id, state, started_ts) VALUES (?1, ?2, ?3)",
        params![device_id, state, ts],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn close_open_segments(conn: &Connection, device_id: i64, ts: i64) -> Result<usize> {
    conn.execute(
        "UPDATE segments SET ended_ts = ?2 WHERE device_id = ?1 AND ended_ts IS NULL",
        params![device_id, ts],
    )
    .map_err(Into::into)
}

pub fn current_segment(conn: &Connection, device_id: i64) -> Result<Option<Segment>> {
    let res = conn
        .query_row(
            "SELECT id, device_id, state, started_ts, ended_ts FROM segments
             WHERE device_id = ?1 AND ended_ts IS NULL ORDER BY started_ts DESC LIMIT 1",
            params![device_id],
            |r| {
                Ok(Segment {
                    id: r.get(0)?,
                    device_id: r.get(1)?,
                    state: r.get(2)?,
                    started_ts: r.get(3)?,
                    ended_ts: r.get(4)?,
                })
            },
        )
        .optional()?;
    Ok(res)
}

pub fn segments_window(conn: &Connection, device_id: i64, since_secs: i64, limit: usize) -> Result<Vec<Segment>> {
    let mut stmt = conn.prepare(
        "SELECT id, device_id, state, started_ts, ended_ts FROM segments
         WHERE device_id = ?1 AND started_ts >= ?2 ORDER BY started_ts DESC LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![device_id, since_secs, limit as i64], |r| {
        Ok(Segment {
            id: r.get(0)?,
            device_id: r.get(1)?,
            state: r.get(2)?,
            started_ts: r.get(3)?,
            ended_ts: r.get(4)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

// ------------------------------------------------------------------ events

fn row_event(r: &Row) -> rusqlite::Result<EventRec> {
    Ok(EventRec {
        id: r.get(0)?,
        created_ts: r.get(1)?,
        updated_ts: r.get(2)?,
        device_id: r.get(3)?,
        ip: r.get(4)?,
        kind: r.get(5)?,
        severity: r.get(6)?,
        state: r.get(7)?,
        message: r.get(8)?,
        details: r.get(9)?,
        acknowledged: r.get::<_, i64>(10)? != 0,
        ack_by: r.get(11)?,
        ack_ts: r.get(12)?,
        cleared_ts: r.get(13)?,
    })
}

const EVENT_COLS: &str = "id, created_ts, updated_ts, device_id, ip, kind, severity, state, \
     message, details, acknowledged, ack_by, ack_ts, cleared_ts";

pub fn open_event_for(conn: &Connection, device_id: i64, kind: &str) -> Result<Option<EventRec>> {
    let sql = format!(
        "SELECT {EVENT_COLS} FROM events
         WHERE device_id = ?1 AND kind = ?2 AND state = 'open'
         ORDER BY created_ts DESC LIMIT 1"
    );
    Ok(conn.query_row(&sql, params![device_id, kind], row_event).optional()?)
}

#[allow(clippy::too_many_arguments)]
pub fn create_event(
    conn: &Connection,
    device_id: Option<i64>,
    ip: Option<&str>,
    kind: &str,
    severity: &str,
    message: &str,
    details: Option<&str>,
    ts: i64,
) -> Result<EventRec> {
    conn.execute(
        "INSERT INTO events(created_ts, device_id, ip, kind, severity, state, message, details)
         VALUES (?1, ?2, ?3, ?4, ?5, 'open', ?6, ?7)",
        params![ts, device_id, ip, kind, severity, message, details],
    )?;
    let id = conn.last_insert_rowid();
    Ok(EventRec {
        id,
        created_ts: ts,
        updated_ts: None,
        device_id,
        ip: ip.map(str::to_string),
        kind: kind.into(),
        severity: severity.into(),
        state: "open".into(),
        message: message.into(),
        details: details.map(str::to_string),
        acknowledged: false,
        ack_by: None,
        ack_ts: None,
        cleared_ts: None,
    })
}

pub fn update_event_details(conn: &Connection, id: i64, details: &str, ts: i64) -> Result<()> {
    conn.execute(
        "UPDATE events SET details = ?2, updated_ts = ?3 WHERE id = ?1",
        params![id, details, ts],
    )?;
    Ok(())
}

pub fn clear_event(conn: &Connection, id: i64, ts: i64) -> Result<()> {
    conn.execute(
        "UPDATE events SET state = 'closed', cleared_ts = ?2, updated_ts = ?2 WHERE id = ?1",
        params![id, ts],
    )?;
    Ok(())
}

pub fn clear_open_events_of_kind(conn: &Connection, device_id: i64, kinds: &[&str], ts: i64) -> Result<usize> {
    let mut n = 0;
    for k in kinds {
        n += conn.execute(
            "UPDATE events SET state = 'closed', cleared_ts = ?3, updated_ts = ?3
             WHERE device_id = ?1 AND kind = ?2 AND state = 'open'",
            params![device_id, k, ts],
        )?;
    }
    Ok(n)
}

pub fn ack_event(conn: &Connection, id: i64, ack: bool, by: &str, ts: i64) -> Result<usize> {
    if ack {
        conn.execute(
            "UPDATE events SET acknowledged = 1, ack_by = ?2, ack_ts = ?3 WHERE id = ?1",
            params![id, by, ts],
        )?;
    } else {
        conn.execute(
            "UPDATE events SET acknowledged = 0, ack_by = NULL, ack_ts = NULL WHERE id = ?1",
            params![id],
        )?;
    }
    Ok(1)
}

pub fn event_by_id(conn: &Connection, id: i64) -> Result<Option<EventRec>> {
    let sql = format!("SELECT {EVENT_COLS} FROM events WHERE id = ?1");
    Ok(conn.query_row(&sql, params![id], row_event).optional()?)
}

pub fn list_events(
    conn: &Connection,
    only_open: bool,
    severity: Option<&str>,
    device_id: Option<i64>,
    offset: i64,
    limit: i64,
) -> Result<Vec<EventRec>> {
    use rusqlite::types::Value;
    let mut sql = format!("SELECT {EVENT_COLS} FROM events WHERE 1=1");
    let mut args: Vec<Value> = Vec::new();
    if only_open {
        sql.push_str(" AND state = 'open'");
    }
    if let Some(sev) = severity {
        args.push(Value::Text(sev.to_string()));
        sql.push_str(&format!(" AND severity = ?{}", args.len()));
    }
    if let Some(did) = device_id {
        args.push(Value::Integer(did));
        sql.push_str(&format!(" AND device_id = ?{}", args.len()));
    }
    args.push(Value::Integer(limit));
    sql.push_str(&format!(" ORDER BY created_ts DESC, id DESC LIMIT ?{}", args.len()));
    args.push(Value::Integer(offset));
    sql.push_str(&format!(" OFFSET ?{}", args.len()));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args), row_event)?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn event_counts(conn: &Connection) -> (i64, i64, i64) {
    let open_crit_warn: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE state='open' AND severity IN ('critical','warning')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let unacked: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE state='open' AND acknowledged = 0
             AND severity IN ('critical','warning')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap_or(0);
    (open_crit_warn, unacked, total)
}

// ---------------------------------------------------------- outbound queue

pub fn queue_outbound(conn: &Connection, event_id: i64, payload: &str, ts: i64) -> Result<i64> {
    conn.execute(
        "INSERT INTO outbound(created_ts, status, event_id, payload) VALUES (?1, 'pending', ?2, ?3)",
        params![ts, event_id, payload],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn pending_outbound(conn: &Connection, limit: i64) -> Result<Vec<(i64, String)>> {
    let mut stmt = conn.prepare(
        "SELECT id, payload FROM outbound
         WHERE status = 'pending' AND tries < 5 ORDER BY created_ts LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn mark_outbound(conn: &Connection, id: i64, ok: bool, err: Option<&str>) -> Result<()> {
    if ok {
        conn.execute(
            "UPDATE outbound SET status='sent', sent_ts=?2, tries=tries+1, last_error=NULL WHERE id=?1",
            params![id, now()],
        )?;
    } else {
        conn.execute(
            "UPDATE outbound SET tries=tries+1, last_error=?2,
                 status=CASE WHEN tries+1 >= 5 THEN 'failed' ELSE 'pending' END
             WHERE id=?1",
            params![id, err.unwrap_or("unknown")],
        )?;
    }
    Ok(())
}

// --------------------------------------------------------------- retention

pub fn prune_old_data(
    conn: &Connection,
    raw_cutoff_secs: i64,
    hourly_cutoff_secs: i64,
    daily_cutoff_secs: i64,
) -> Result<(usize, usize, usize)> {
    let raw_cut_ms = raw_cutoff_secs * 1000;
    let mut raw = 0usize;
    loop {
        let deleted = conn.execute(
            "DELETE FROM samples WHERE rowid IN
                 (SELECT rowid FROM samples WHERE ts < ?1 LIMIT 20000)",
            params![raw_cut_ms],
        )?;
        raw += deleted;
        if deleted == 0 {
            break;
        }
    }
    let mut hourly = 0usize;
    loop {
        let deleted = conn.execute(
            "DELETE FROM rollup_hourly WHERE hour < ?1 AND hour IN
                 (SELECT hour FROM rollup_hourly WHERE hour < ?1 LIMIT 50000)",
            params![hourly_cutoff_secs],
        )?;
        hourly += deleted;
        if deleted == 0 {
            break;
        }
    }
    let mut daily = 0usize;
    loop {
        let deleted = conn.execute(
            "DELETE FROM rollup_daily WHERE day < ?1 AND day IN
                 (SELECT day FROM rollup_daily WHERE day < ?1 LIMIT 50000)",
            params![daily_cutoff_secs],
        )?;
        daily += deleted;
        if deleted == 0 {
            break;
        }
    }
    Ok((raw, hourly, daily))
}

pub fn purge_sent_outbound(conn: &Connection, older_than_secs: i64) -> Result<usize> {
    conn.execute(
        "DELETE FROM outbound WHERE status IN ('sent','failed') AND created_ts < ?1",
        params![older_than_secs],
    )
    .map_err(Into::into)
}

// ------------------------------------------------------- device lifecycle

/// Remove a device and its probe history from the inventory.
/// Events are kept (they carry the IP as text) for audit continuity.
pub fn remove_device(conn: &Connection, id: i64) -> Result<bool> {
    conn.execute("DELETE FROM samples WHERE device_id = ?1", params![id])?;
    conn.execute("DELETE FROM segments WHERE device_id = ?1", params![id])?;
    conn.execute("DELETE FROM rollup_hourly WHERE device_id = ?1", params![id])?;
    conn.execute("DELETE FROM rollup_daily WHERE device_id = ?1", params![id])?;
    conn.execute("DELETE FROM device_diag WHERE device_id = ?1", params![id])?;
    let n = conn.execute("DELETE FROM devices WHERE id = ?1", params![id])?;
    Ok(n > 0)
}

/// Drop inventory entries that have not been seen for a long time so that
/// decommissioned hardware eventually disappears instead of lingering "down".
/// Manually sited or explicitly unmanaged devices are preserved.
pub fn retire_absent_devices(conn: &Connection, cutoff_ts: i64) -> Result<usize> {
    let stale: Vec<i64> = {
        let Ok(mut stmt) = conn.prepare(
            "SELECT id FROM devices
             WHERE last_seen_ts < ?1 AND managed = 1
               AND COALESCE(site_source,'auto') != 'manual'",
        ) else {
            return Ok(0);
        };
        stmt.query_map(params![cutoff_ts], |r| r.get(0))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default()
    };
    let mut n = 0;
    for id in stale {
        if remove_device(conn, id)? {
            n += 1;
        }
    }
    Ok(n)
}

pub fn epoch_day(ts: i64) -> i64 {
    ts - ts.rem_euclid(86_400)
}

// ------------------------------------------------------------------- auth

pub struct UserRec {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub disabled: bool,
}

pub fn create_user(conn: &Connection, username: &str, password_hash: &str, role: &str) -> Result<i64> {
    conn.execute(
        "INSERT INTO users(username, password_hash, role, created_ts) VALUES (?1, ?2, ?3, ?4)",
        params![username, password_hash, role, now()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn get_user(conn: &Connection, username: &str) -> Result<Option<UserRec>> {
    let res = conn
        .query_row(
            "SELECT id, username, password_hash, role, disabled FROM users WHERE username = ?1",
            params![username],
            |r| {
                Ok(UserRec {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    password_hash: r.get(2)?,
                    role: r.get(3)?,
                    disabled: r.get::<_, i64>(4)? != 0,
                })
            },
        )
        .optional()?;
    Ok(res)
}

pub fn list_users(conn: &Connection) -> Result<Vec<(String, String, bool)>> {
    let mut stmt = conn.prepare("SELECT username, role, disabled FROM users ORDER BY username")?;
    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? != 0))
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn set_user_disabled(conn: &Connection, username: &str, disabled: bool) -> Result<usize> {
    conn.execute(
        "UPDATE users SET disabled = ?2 WHERE username = ?1",
        params![username, disabled as i64],
    )
    .map_err(Into::into)
}

pub fn create_session(
    conn: &Connection,
    token_hash: &str,
    user_id: i64,
    role: &str,
    expires_ts: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO sessions(token_hash, user_id, role, created_ts, expires_ts) VALUES (?1,?2,?3,?4,?5)",
        params![token_hash, user_id, role, now(), expires_ts],
    )?;
    Ok(())
}

/// Returns the session's role if a live (unexpired) session exists for `token_hash`.
pub fn session_role(conn: &Connection, token_hash: &str) -> Result<Option<String>> {
    let res: Option<(String, i64)> = conn
        .query_row(
            "SELECT u.role, s.expires_ts FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = ?1 AND u.disabled = 0",
            params![token_hash],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match res {
        Some((role, expires)) if expires > now() => Ok(Some(role)),
        _ => Ok(None),
    }
}

pub fn delete_session(conn: &Connection, token_hash: &str) -> Result<()> {
    conn.execute("DELETE FROM sessions WHERE token_hash = ?1", params![token_hash])?;
    Ok(())
}

pub fn prune_expired_sessions(conn: &Connection) -> Result<usize> {
    conn.execute("DELETE FROM sessions WHERE expires_ts < ?1", params![now()])
        .map_err(Into::into)
}

pub fn add_api_token(conn: &Connection, token_hash: &str, name: &str, role: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO api_tokens(token_hash, name, role, created_ts) VALUES (?1, ?2, ?3, ?4)",
        params![token_hash, name, role, now()],
    )?;
    Ok(())
}

pub fn api_token_role(conn: &Connection, token_hash: &str) -> Result<Option<String>> {
    let res: Option<String> = conn
        .query_row(
            "SELECT role FROM api_tokens WHERE token_hash = ?1 AND disabled = 0",
            params![token_hash],
            |r| r.get(0),
        )
        .optional()?;
    Ok(res)
}

// ------------------------------------------------------------------- diag

#[allow(clippy::too_many_arguments)]
pub fn save_diag(
    conn: &Connection,
    device_id: i64,
    ts: i64,
    sent: i64,
    recv: i64,
    loss_pct: f64,
    rtt_min: Option<f64>,
    rtt_avg: Option<f64>,
    rtt_max: Option<f64>,
    rtt_p95: Option<f64>,
    jitter_ms: Option<f64>,
    score: i64,
    verdict: &str,
    open_ports: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO device_diag(device_id, ts, sent, recv, loss_pct, rtt_min, rtt_avg,
             rtt_max, rtt_p95, jitter_ms, score, verdict, open_ports)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
         ON CONFLICT(device_id) DO UPDATE SET
             ts=excluded.ts, sent=excluded.sent, recv=excluded.recv,
             loss_pct=excluded.loss_pct, rtt_min=excluded.rtt_min, rtt_avg=excluded.rtt_avg,
             rtt_max=excluded.rtt_max, rtt_p95=excluded.rtt_p95, jitter_ms=excluded.jitter_ms,
             score=excluded.score, verdict=excluded.verdict, open_ports=excluded.open_ports",
        params![device_id, ts, sent, recv, loss_pct, rtt_min, rtt_avg, rtt_max, rtt_p95,
                jitter_ms, score, verdict, open_ports],
    )?;
    Ok(())
}

pub fn latest_diag(conn: &Connection, device_id: i64) -> Result<Option<serde_json::Value>> {
    let res = conn
        .query_row(
            "SELECT ts, sent, recv, loss_pct, rtt_min, rtt_avg, rtt_max, rtt_p95, jitter_ms,
                    score, verdict, open_ports
             FROM device_diag WHERE device_id = ?1",
            params![device_id],
            |r| {
                Ok(serde_json::json!({
                    "ts": r.get::<_, i64>(0)?,
                    "sent": r.get::<_, i64>(1)?,
                    "recv": r.get::<_, i64>(2)?,
                    "loss_pct": r.get::<_, f64>(3)?,
                    "rtt_min": r.get::<_, Option<f64>>(4)?,
                    "rtt_avg": r.get::<_, Option<f64>>(5)?,
                    "rtt_max": r.get::<_, Option<f64>>(6)?,
                    "rtt_p95": r.get::<_, Option<f64>>(7)?,
                    "jitter_ms": r.get::<_, Option<f64>>(8)?,
                    "score": r.get::<_, i64>(9)?,
                    "verdict": r.get::<_, String>(10)?,
                    "open_ports": r.get::<_, Option<String>>(11)?,
                }))
            },
        )
        .optional()?;
    Ok(res)
}

pub fn epoch_hour(ts_millis: i64) -> i64 {
    let secs = ts_millis / 1000;
    secs - secs.rem_euclid(3600)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Db {
        Db::open_memory().unwrap()
    }

    #[test]
    fn settings_roundtrip_and_defaults() {
        let db = setup();
        let c = db.lock();
        assert_eq!(get_setting_or(&c, "poll_interval_secs", "x"), "60");
        set_setting(&c, "poll_interval_secs", "30").unwrap();
        assert_eq!(get_setting_or(&c, "poll_interval_secs", "x"), "30");
        assert!(all_settings(&c).contains_key("webhook_url"));
    }

    #[test]
    fn device_upsert_preserves_manual_site() {
        let db = setup();
        let c = db.lock();
        let u = DeviceUpdate {
            ip: "10.0.0.5",
            mac: None,
            role: "endpoint",
            subnet_site_label: Some("10.0.0/24".into()),
            parent_ip: None,
            state: "up",
            up_now: true,
            rtt_ms: Some(5.0),
            ts: 1_000,
            site_prefix: 24,
            hostname: None,
            device_class: None,
        };
        let d1 = upsert_device(&c, &u).unwrap();
        assert_eq!(site_name(&c, d1.site_id), "10.0.0/24");
        assign_site(&c, d1.id, Some("hq-building-3")).unwrap();
        let d2 = upsert_device(&c, &u).unwrap();
        assert_eq!(site_name(&c, d2.site_id), "hq-building-3");
        assert_eq!(d2.site_source, "manual");
    }

    #[test]
    fn event_lifecycle() {
        let db = setup();
        let c = db.lock();
        let ev = create_event(&c, Some(1), Some("10.0.0.5"), "device_down", "critical",
                              "router down", None, 100).unwrap();
        assert!(open_event_for(&c, 1, "device_down").unwrap().is_some());
        ack_event(&c, ev.id, true, "web", 110).unwrap();
        clear_event(&c, ev.id, 120).unwrap();
        let got = list_events(&c, false, None, None, 0, 10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].state, "closed");
        assert!(got[0].acknowledged);
        assert_eq!(got[0].cleared_ts, Some(120));
        assert!(list_events(&c, true, None, None, 0, 10).unwrap().is_empty());
    }

    #[test]
    fn segments_close_and_reopen() {
        let db = setup();
        let c = db.lock();
        open_segment(&c, 7, "up", 100).unwrap();
        open_segment(&c, 7, "down", 200).unwrap();
        let cur = current_segment(&c, 7).unwrap().unwrap();
        assert_eq!(cur.state, "down");
        assert_eq!(cur.started_ts, 200);
        let closed = segments_window(&c, 7, 0, 10).unwrap();
        assert_eq!(closed.len(), 2);
        let prev = closed.iter().find(|s| s.id != cur.id).unwrap();
        assert_eq!(prev.ended_ts, Some(200));
    }

    #[test]
    fn hourly_rollup_math_with_jitter() {
        let db = setup();
        let c = db.lock();
        let base: i64 = 1_700_000_000_000;
        let mk = |i: i64, up: bool, rtt: Option<f64>| Sample {
            device_id: 42,
            ts_millis: base + i * 60_000,
            up,
            rtt_ms: rtt,
        };
        insert_samples(&c, &[
            mk(0, true, Some(10.0)),
            mk(1, true, Some(20.0)),
            mk(2, true, Some(15.0)),
            mk(3, false, None),
        ])
        .unwrap();
        recompute_hourly_rollup(&c, 42, base / 1000 - base / 1000 % 3600).unwrap();
        let pct = uptime_pct_window(&c, 42, 0).unwrap();
        assert!((pct - 75.0).abs() < 0.001);
        let jit: f64 = c
            .query_row(
                "SELECT jitter_sum / jitter_n FROM rollup_hourly WHERE device_id=42",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!((jit - 7.5).abs() < 0.001);
    }

    #[test]
    fn daily_rollup_from_hourly() {
        let db = setup();
        let c = db.lock();
        let day = 1_700_000_000 - 1_700_000_000 % 86_400;
        for h in 0..3i64 {
            c.execute(
                "INSERT INTO rollup_hourly(device_id,hour,probes,ups,rtt_sum) VALUES (1,?1,10,9,90.0)",
                params![day + h * 3600],
            )
            .unwrap();
        }
        refresh_daily_rollups(&c, day).unwrap();
        let (probes, ups): (i64, i64) = c
            .query_row("SELECT probes, ups FROM rollup_daily WHERE device_id=1 AND day=?1",
                       params![day], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!((probes, ups), (30, 27));
    }

    #[test]
    fn retention_prunes() {
        let db = setup();
        let c = db.lock();
        insert_samples(&c, &[Sample { device_id: 1, ts_millis: 1_000, up: true, rtt_ms: Some(1.0) }])
            .unwrap();
        c.execute("INSERT INTO rollup_hourly(device_id,hour,probes,ups) VALUES (1, 10, 1, 1)", [])
            .unwrap();
        c.execute("INSERT INTO rollup_daily(device_id,day,probes,ups) VALUES (1, 10, 1, 1)", [])
            .unwrap();
        let (raw, hr, dy) = prune_old_data(&c, 2_000, 100, 100).unwrap();
        assert_eq!((raw, hr, dy), (1, 1, 1));
        let left: i64 = c.query_row("SELECT COUNT(*) FROM samples", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 0);
    }

    #[test]
    fn auto_site_labels() {
        assert_eq!(auto_site_label("192.168.86.20", 24).unwrap(), "192.168.86/24");
        assert_eq!(auto_site_label("10.1.2.3", 16).unwrap(), "10.1/16");
        assert!(auto_site_label("not-an-ip", 24).is_none());
    }

    #[test]
    fn outbound_queue_flow() {
        let db = setup();
        let c = db.lock();
        let id = queue_outbound(&c, 9, "{\"x\":1}", 5).unwrap();
        assert_eq!(pending_outbound(&c, 10).unwrap().len(), 1);
        mark_outbound(&c, id, false, Some("conn refused")).unwrap();
        assert_eq!(pending_outbound(&c, 10).unwrap().len(), 1);
        mark_outbound(&c, id, true, None).unwrap();
        assert!(pending_outbound(&c, 10).unwrap().is_empty());
    }

    #[test]
    fn audit_appends() {
        let db = setup();
        let c = db.lock();
        audit(&c, "web", "event.ack", "event:3", "{}");
        let n: i64 = c.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn session_expiry_and_disabled_user() {
        let db = setup();
        let c = db.lock();
        let uid = create_user(&c, "alice", "hash", "operator").unwrap();
        // expired session
        create_session(&c, "expired", uid, "operator", 100).unwrap();
        assert!(session_role(&c, "expired").unwrap().is_none());
        // live session
        create_session(&c, "live", uid, "operator", 9_999_999_999).unwrap();
        assert_eq!(session_role(&c, "live").unwrap().as_deref(), Some("operator"));
        // disabled user invalidates live sessions
        set_user_disabled(&c, "alice", true).unwrap();
        assert!(session_role(&c, "live").unwrap().is_none());
        // pruning removes only expired rows — the live session survives
        prune_expired_sessions(&c).unwrap();
        let n: i64 = c.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn api_token_roles() {
        let db = setup();
        let c = db.lock();
        add_api_token(&c, "h1", "ansible", "automation").unwrap();
        assert_eq!(api_token_role(&c, "h1").unwrap().as_deref(), Some("automation"));
        assert!(api_token_role(&c, "missing").unwrap().is_none());
    }
}
