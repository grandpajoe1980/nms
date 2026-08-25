use crate::db::{self, Db};
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// POST a JSON payload to the configured webhook endpoint.
pub fn send_webhook(url: &str, payload: serde_json::Value) -> Result<u16, String> {
    ureq::post(url)
        .timeout(Duration::from_secs(10))
        .send_json(payload)
        .map(|r| r.status())
        .map_err(|e| e.to_string())
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { TABLE[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[n as usize & 63] as char } else { '=' });
    }
    out
}

/// HTTP Basic auth header value ("Basic <base64 user:pass>").
pub fn basic_auth_header(user: &str, pass: &str) -> String {
    format!("Basic {}", base64_encode(format!("{user}:{pass}").as_bytes()))
}

/// POST JSON with HTTP Basic auth (ServiceNow Table API style).
pub fn send_webhook_basic(
    url: &str,
    payload: serde_json::Value,
    user: &str,
    pass: &str,
) -> Result<u16, String> {
    ureq::post(url)
        .set("Authorization", &basic_auth_header(user, pass))
        .timeout(Duration::from_secs(10))
        .send_json(payload)
        .map(|r| r.status())
        .map_err(|e| e.to_string())
}

fn setting_i64(dbh: &Db, key: &str, default: i64) -> i64 {
    let conn = dbh.lock();
    db::get_setting_or(&conn, key, &default.to_string()).parse().unwrap_or(default)
}

/// Periodic maintenance: daily rollups, retention pruning, queue hygiene.
pub fn start_housekeeping(dbh: Arc<Db>) {
    std::thread::Builder::new()
        .name("housekeeping".into())
        .spawn(move || loop {
            let conn = dbh.lock();
            let now = chrono::Utc::now().timestamp();
            let yesterday = db::epoch_day(now) - 86_400;
            if let Err(e) = db::refresh_daily_rollups(&conn, yesterday) {
                eprintln!("[jobs] daily rollup failed: {e}");
            }
            drop(conn);
            // Re-lock per step to avoid long exclusive holds.
            let raw_h = setting_i64(&dbh, "raw_retention_hours", 36);
            let hourly_d = setting_i64(&dbh, "hourly_retention_days", 14);
            let daily_d = setting_i64(&dbh, "daily_retention_days", 400);
            let conn = dbh.lock();
            match db::prune_old_data(
                &conn,
                now - raw_h * 3600,
                now - hourly_d * 86_400,
                db::epoch_day(now) - daily_d * 86_400,
            ) {
                Ok((raw, hr, dy)) if raw + hr + dy > 0 => {
                    println!("[jobs] retention pruned rows: samples={raw} hourly={hr} daily={dy}");
                }
                Ok(_) => {}
                Err(e) => eprintln!("[jobs] retention failed: {e}"),
            }
            let _ = db::purge_sent_outbound(&conn, now - 7 * 86_400);
            let _ = db::prune_expired_sessions(&conn);
            drop(conn);
            std::thread::sleep(Duration::from_secs(600));
        })
        .expect("spawn housekeeping");
}

/// Deliver queued alert payloads to the configured webhook (ServiceNow etc).
pub fn start_webhook_sender(dbh: Arc<Db>) {
    std::thread::Builder::new()
        .name("webhook-sender".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            let (enabled, snow_on) = {
                let conn = dbh.lock();
                (
                    db::get_setting_or(&conn, "webhook_enabled", "0") == "1",
                    db::get_setting_or(&conn, "snow_transform", "0") == "1",
                )
            };
            if !enabled {
                continue;
            }
            // ServiceNow mode targets the instance's Incident Table API with
            // Basic auth; raw mode posts the v1 payload to webhook_url.
            // NOTE: password lives in settings (SQLite) for now — CFG-001
            // vault upgrade path will replace this; it is never logged,
            // audited, or returned by any GET.
            let (url, snow_user, snow_pass) = {
                let conn = dbh.lock();
                if snow_on {
                    (
                        format!(
                            "{}/api/now/table/incident",
                            db::get_setting_or(&conn, "snow_instance_url", "")
                                .trim_end_matches('/')
                        ),
                        db::get_setting_or(&conn, "snow_username", ""),
                        db::get_setting_or(&conn, "snow_password", ""),
                    )
                } else {
                    (db::get_setting_or(&conn, "webhook_url", ""), String::new(), String::new())
                }
            };
            if url.is_empty() || (snow_on && (snow_user.is_empty() || snow_pass.is_empty())) {
                if snow_on {
                    // misconfigured SNOW: skip quietly until configured
                    continue;
                }
                continue;
            }
            let batch = {
                let conn = dbh.lock();
                db::pending_outbound(&conn, 25).unwrap_or_default()
            };
            for (id, payload) in batch {
                let body = match transform_for_delivery(&payload, snow_on) {
                    Ok(b) => b,
                    Err(e) => {
                        let conn = dbh.lock();
                        let _ = db::mark_outbound(&conn, id, false, Some(&e));
                        eprintln!("[jobs] webhook #{id} transform failed: {e}");
                        continue;
                    }
                };
                let value: serde_json::Value =
                    serde_json::from_str(&body).unwrap_or(serde_json::json!({"raw": body}));
                let res = if snow_on {
                    send_webhook_basic(&url, value, &snow_user, &snow_pass)
                } else {
                    send_webhook(&url, value)
                };
                let conn = dbh.lock();
                match res {
                    Ok(status) => {
                        let _ = db::mark_outbound(&conn, id, true, None);
                        let _ = status;
                    }
                    Err(e) => {
                        let _ = db::mark_outbound(&conn, id, false, Some(&e));
                        eprintln!("[jobs] webhook #{id} failed: {e}");
                    }
                }
            }
        })
        .expect("spawn webhook sender");
}

/// Pure delivery-time transformer: raw v1 passthrough by default; when
/// ServiceNow mode is on, convert to an incident body (or a resolve patch for
/// recovery kinds). Malformed JSON in SNOW mode is an error, never dropped.
fn transform_for_delivery(payload: &str, snow_on: bool) -> Result<String, String> {
    if !snow_on {
        return Ok(payload.to_string());
    }
    let value: serde_json::Value =
        serde_json::from_str(payload).map_err(|e| format!("payload not JSON: {e}"))?;
    let kind = value
        .pointer("/event/kind")
        .and_then(|k| k.as_str())
        .unwrap_or("")
        .to_string();
    if crate::snow::is_recovery_kind(&kind) {
        let mapped =
            crate::snow::resolve_patch(&value).map_err(|e| e.to_string())?;
        Ok(serde_json::to_string(&mapped).map_err(|e| e.to_string())?)
    } else {
        let mapped =
            crate::snow::to_incident_payload(&value).map_err(|e| e.to_string())?;
        Ok(serde_json::to_string(&mapped).map_err(|e| e.to_string())?)
    }
}

/// Hourly scheduled reporting: rolling 24h availability snapshot plus a
/// once-per-day dated CSV (StableNet-style report generation).
pub fn start_report_writer(dbh: Arc<Db>, out_dir: PathBuf) {
    std::thread::Builder::new()
        .name("report-writer".into())
        .spawn(move || {
            let reports_dir = out_dir.join("reports");
            let mut last_day = String::new();
            loop {
                std::thread::sleep(Duration::from_secs(3600));
                if std::fs::create_dir_all(&reports_dir).is_err() {
                    continue;
                }
                let conn = dbh.lock();
                let csv = crate::reports::availability_csv(&conn, 24);
                drop(conn);
                let _ = std::fs::write(reports_dir.join("latest-24h.csv"), &csv);
                let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
                if day != last_day {
                    let path = reports_dir.join(format!("daily-{day}.csv"));
                    if !path.exists() {
                        let _ = std::fs::write(&path, &csv);
                        println!("[jobs] wrote {}", path.display());
                    }
                    last_day = day.clone();
                    // prune snapshots older than 90 days
                    if let Ok(entries) = std::fs::read_dir(&reports_dir) {
                        let cutoff = chrono::Utc::now() - chrono::Duration::days(90);
                        for e in entries.flatten() {
                            let name_ok = e
                                .file_name()
                                .to_string_lossy()
                                .starts_with("daily-");
                            if !name_ok {
                                continue;
                            }
                            let stale = e.metadata().ok()
                                .and_then(|m| m.modified().ok())
                                .map(|t| t.elapsed().map(|d| d.as_secs()).unwrap_or(0))
                                .unwrap_or(0)
                                > 90 * 86_400;
                            let date_stale = chrono::NaiveDate::parse_from_str(
                                e.file_name().to_string_lossy().trim_start_matches("daily-").trim_end_matches(".csv"),
                                "%Y-%m-%d",
                            )
                            .map(|d| d.and_hms_opt(0, 0, 0).map(|dt| dt.and_utc().timestamp() < cutoff.timestamp()).unwrap_or(false))
                            .unwrap_or(false);
                            if stale || date_stale {
                                let _ = std::fs::remove_file(e.path());
                            }
                        }
                    }
                }
            }
        })
        .expect("spawn report writer");
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1_DOWN: &str = r#"{"type":"nms.event","ts":"2026-08-24T12:00:00Z",
        "event":{"id":42,"kind":"device_down","severity":"critical",
                 "message":"router down","details":null,"created_ts":1000},
        "device":{"ip":"10.20.30.1","role":"router","site":"hq-1"}}"#;
    const V1_UP: &str = r#"{"type":"nms.event","ts":"2026-08-24T13:00:00Z",
        "event":{"id":43,"kind":"device_up","severity":"info",
                 "message":"back","details":null,"created_ts":2000},
        "device":{"ip":"10.20.30.1","role":"router","site":"hq-1"}}"#;

    #[test]
    fn passthrough_when_snow_off() {
        let out = transform_for_delivery(V1_DOWN, false).unwrap();
        assert_eq!(out, V1_DOWN);
    }

    #[test]
    fn snow_on_maps_incident_and_resolve() {
        let down = transform_for_delivery(V1_DOWN, true).unwrap();
        let v: serde_json::Value = serde_json::from_str(&down).unwrap();
        assert_eq!(v["impact"], "1");
        assert_eq!(v["correlation_id"], "nms-42");
        assert!(v["short_description"].as_str().unwrap().contains("down"));

        let up = transform_for_delivery(V1_UP, true).unwrap();
        let v: serde_json::Value = serde_json::from_str(&up).unwrap();
        assert_eq!(v["state"], "7");
        assert!(v["close_notes"].as_str().unwrap().contains("Auto-resolved"));
    }

    #[test]
    fn malformed_json_in_snow_mode_is_err() {
        assert!(transform_for_delivery("{not json", true).is_err());
        // and passthrough mode tolerates it
        assert!(transform_for_delivery("{not json", false).is_ok());
    }
}

#[cfg(test)]
mod basic_auth_tests {
    use super::*;

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(basic_auth_header("joe", "s3cret"), "Basic am9lOnMzY3JldA==");
    }
}
