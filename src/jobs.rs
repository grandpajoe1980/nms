use crate::db::{self, Db};
use anyhow::Result;
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
            let enabled = {
                let conn = dbh.lock();
                db::get_setting_or(&conn, "webhook_enabled", "0") == "1"
            };
            if !enabled {
                continue;
            }
            let url = {
                let conn = dbh.lock();
                db::get_setting_or(&conn, "webhook_url", "")
            };
            if url.is_empty() {
                continue;
            }
            let batch = {
                let conn = dbh.lock();
                db::pending_outbound(&conn, 25).unwrap_or_default()
            };
            for (id, payload) in batch {
                let value: serde_json::Value =
                    serde_json::from_str(&payload).unwrap_or(serde_json::json!({"raw": payload}));
                let res = send_webhook(&url, value);
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
