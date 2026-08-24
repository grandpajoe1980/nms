//! Availability/metrics query helpers shared by the console UI, CSV reports
//! and the scheduled report writer. Pure reads over the ops store.

use rusqlite::Connection;
use std::fmt::Write;

pub(crate) type SiteRow = (String, i64, i64, i64, f64, f64);

pub fn availability_rows(conn: &Connection, hours: i64) -> Vec<SiteRow> {
    let now = chrono::Utc::now().timestamp();
    let since = now - hours * 3600;
    conn.prepare(
        "SELECT COALESCE((SELECT name FROM sites WHERE id = d.site_id), 'unassigned'),
                COUNT(DISTINCT d.id),
                COALESCE(SUM(r.probes), 0), COALESCE(SUM(r.ups), 0),
                100.0 * COALESCE(SUM(r.ups), 0) / MAX(COALESCE(SUM(r.probes), 0), 1),
                COALESCE(SUM(r.rtt_sum), 0) / MAX(COALESCE(SUM(r.ups), 0), 1)
         FROM devices d LEFT JOIN rollup_hourly r
           ON r.device_id = d.id AND r.hour >= ?1
         WHERE d.managed = 1
         GROUP BY 1 ORDER BY 5 ASC",
    )
    .and_then(|mut stmt| {
        stmt.query_map([since], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, f64>(4)?,
                r.get::<_, f64>(5)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
    })
    .unwrap_or_default()
}

pub fn devices_csv(conn: &Connection, hours: i64, site: Option<&str>) -> String {
    let now = chrono::Utc::now().timestamp();
    let since = now - hours * 3600;
    let mut out = String::from("ip,role,site,eff_state,perf,probes,ups,uptime_pct,avg_rtt_ms\n");
    if let Ok(mut stmt) = conn.prepare(
        "SELECT d.ip, d.role, COALESCE((SELECT name FROM sites WHERE id=d.site_id),'unassigned'),
                d.eff_state, d.perf_status,
                COALESCE(SUM(r.probes),0), COALESCE(SUM(r.ups),0),
                100.0 * COALESCE(SUM(r.ups),0) / MAX(COALESCE(SUM(r.probes),0),1),
                COALESCE(SUM(r.rtt_sum),0) / MAX(COALESCE(SUM(r.ups),0),1)
         FROM devices d LEFT JOIN rollup_hourly r
           ON r.device_id = d.id AND r.hour >= ?1
         WHERE d.managed = 1 AND (?2 IS NULL OR d.site_id IN
               (SELECT id FROM sites WHERE name = ?2))
         GROUP BY d.id ORDER BY d.ip",
    ) {
        let rows = stmt.query_map(rusqlite::params![since, site], |r| {
            Ok((
                r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?, r.get::<_, f64>(7)?, r.get::<_, f64>(8)?,
            ))
        });
        if let Ok(rows) = rows {
            for (ip, role, sname, st, perf, probes, ups, pct, rtt) in rows.flatten() {
                let _ = writeln!(out, "{ip},{role},{sname},{st},{perf},{probes},{ups},{pct:.3},{rtt:.2}");
            }
        }
    }
    out
}

pub fn availability_csv(conn: &Connection, hours: i64) -> String {
    let mut out = String::from("site,devices,probes,ups,uptime_pct,avg_rtt_ms\n");
    for (site, devs, probes, ups, pct, rtt) in availability_rows(conn, hours) {
        let _ = writeln!(out, "{site},{devs},{probes},{ups},{pct:.3},{rtt:.2}");
    }
    out
}
