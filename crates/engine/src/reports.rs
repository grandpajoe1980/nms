//! Availability/metrics query helpers shared by the console UI, CSV reports
//! and the scheduled report writer. Pure reads over the ops store.

use rusqlite::Connection;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::fmt::Write;

pub(crate) type SiteRow = (String, i64, i64, i64, f64, f64);

/// An explicit UTC query window. Reports carry these bounds so a report can
/// be reproduced without relying on the clock at read time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ReportWindow {
    pub start_ts: i64,
    pub end_ts: i64,
}

impl ReportWindow {
    pub fn trailing_hours(end_ts: i64, hours: i64) -> Self {
        let hours = hours.max(1);
        Self {
            start_ts: end_ts.saturating_sub(hours.saturating_mul(3_600)),
            end_ts,
        }
    }
}

fn availability_rows_window(conn: &Connection, window: ReportWindow) -> Vec<SiteRow> {
    conn.prepare(
        "SELECT COALESCE((SELECT name FROM sites WHERE id = d.site_id), 'unassigned'),
                COUNT(DISTINCT d.id),
                COALESCE(SUM(r.probes), 0), COALESCE(SUM(r.ups), 0),
                100.0 * COALESCE(SUM(r.ups), 0) / MAX(COALESCE(SUM(r.probes), 0), 1),
                COALESCE(SUM(r.rtt_sum), 0) / MAX(COALESCE(SUM(r.ups), 0), 1)
         FROM devices d LEFT JOIN rollup_hourly r
           ON r.device_id = d.id AND r.hour >= ?1 AND r.hour < ?2
         WHERE d.managed = 1
         GROUP BY 1 ORDER BY 5 ASC",
    )
    .and_then(|mut stmt| {
        stmt.query_map([window.start_ts, window.end_ts], |r| {
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

pub fn availability_rows(conn: &Connection, hours: i64) -> Vec<SiteRow> {
    availability_rows_window(conn, ReportWindow::trailing_hours(chrono::Utc::now().timestamp(), hours))
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
    availability_csv_window(conn, ReportWindow::trailing_hours(chrono::Utc::now().timestamp(), hours))
}

pub fn availability_csv_window(conn: &Connection, window: ReportWindow) -> String {
    let target = conn
        .query_row("SELECT value FROM meta WHERE key='sla_target_pct'", [], |r| {
            r.get::<_, String>(0)
        })
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(99.5);
    let mut out = String::from("site,devices,probes,ups,uptime_pct,target_pct,sla_status,avg_rtt_ms\n");
    for (site, devs, probes, ups, pct, rtt) in availability_rows_window(conn, window) {
        let status = if pct >= target { "met" } else { "missed" };
        let _ = writeln!(
            out,
            "{site},{devs},{probes},{ups},{pct:.3},{target:.2},{status},{rtt:.2}"
        );
    }
    out
}

fn iso(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|v| v.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| ts.to_string())
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Build the print-ready availability report. The source window is explicit
/// metadata and no current-clock value is included in the document body.
pub fn availability_html(conn: &Connection, window: ReportWindow) -> String {
    availability_html_with_status(conn, window, "PDF renderer status is recorded in the report metadata")
}

pub fn availability_html_with_status(
    conn: &Connection,
    window: ReportWindow,
    pdf_status: &str,
) -> String {
    let rows = availability_rows_window(conn, window);
    let target: f64 = crate::db::get_setting_or(conn, "sla_target_pct", "99.5")
        .parse()
        .unwrap_or(99.5);
    let source = format!("{}..{}", iso(window.start_ts), iso(window.end_ts));
    let mut out = String::new();
    let _ = write!(
        out,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>NMS availability report</title>\
<meta name=\"nms-report-source-window\" content=\"{}\"><meta name=\"nms-report-window-start\" content=\"{}\"><meta name=\"nms-report-window-end\" content=\"{}\">\
<style>@page{{size:auto;margin:16mm}}body{{font:12px system-ui,sans-serif;color:#172033}}h1{{font-size:22px;margin:0 0 4px}}.meta{{color:#52617a;margin-bottom:20px}}table{{border-collapse:collapse;width:100%}}th,td{{border-bottom:1px solid #cbd5e1;padding:7px;text-align:left}}th{{background:#e2e8f0}}.num{{text-align:right;font-variant-numeric:tabular-nums}}.warn{{color:#b42318;font-weight:600}}.ok{{color:#087443;font-weight:600}}.notice{{border:1px solid #f0b429;padding:8px;margin:14px 0}}@media print{{.notice{{break-inside:avoid}}}}</style></head><body>\
<h1>Availability report</h1><div class=\"meta\">Source window: <span class=\"mono\">{}</span><br>Target uptime: {:.2}%</div>\
<div class=\"notice\">{}</div><table><thead><tr><th>Site</th><th class=\"num\">Devices</th><th class=\"num\">Probes</th><th class=\"num\">Uptime</th><th>SLA</th><th class=\"num\">Avg RTT</th></tr></thead><tbody>",
        html_escape(&source),
        html_escape(&iso(window.start_ts)),
        html_escape(&iso(window.end_ts)),
        html_escape(&source),
        target,
        html_escape(pdf_status)
    );
    for (site, devs, probes, ups, pct, rtt) in rows {
        let status = if pct >= target { "met" } else { "missed" };
        let class = if status == "met" { "ok" } else { "warn" };
        let _ = write!(
            out,
            "<tr><td>{}</td><td class=\"num\">{devs}</td><td class=\"num\">{probes} / {ups}</td><td class=\"num\">{pct:.3}%</td><td class=\"{class}\">{status}</td><td class=\"num\">{rtt:.2} ms</td></tr>",
            html_escape(&site)
        );
    }
    out.push_str("</tbody></table></body></html>");
    out
}

pub trait PdfRenderer: Send + Sync {
    fn render(&self, html_path: &Path, pdf_path: &Path) -> Result<(), String>;
}

/// Adapter for Chromium-compatible headless print commands. Arguments are
/// passed directly to the process; no shell or string command is involved.
pub struct CommandPdfRenderer {
    program: PathBuf,
}

impl CommandPdfRenderer {
    pub fn new(program: PathBuf) -> Self {
        Self { program }
    }

    fn args_for(&self, html_path: &Path, pdf_path: &Path) -> Vec<std::ffi::OsString> {
        vec![
            "--headless".into(),
            "--disable-gpu".into(),
            format!("--print-to-pdf={}", pdf_path.display()).into(),
            html_path.as_os_str().to_owned(),
        ]
    }
}

impl PdfRenderer for CommandPdfRenderer {
    fn render(&self, html_path: &Path, pdf_path: &Path) -> Result<(), String> {
        let status = Command::new(&self.program)
            .args(self.args_for(html_path, pdf_path))
            .status()
            .map_err(|e| format!("start PDF renderer '{}': {e}", self.program.display()))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("PDF renderer exited with {status}"))
        }
    }
}

pub fn configured_pdf_renderer(conn: &Connection) -> Option<CommandPdfRenderer> {
    let configured = crate::db::get_setting_or(conn, "report_pdf_renderer", "");
    let path = if configured.trim().is_empty() {
        std::env::var_os("NMS_PDF_RENDERER")
            .map(PathBuf::from)
            .or_else(detect_pdf_renderer)
    } else {
        Some(PathBuf::from(configured))
    }?;
    if path.as_os_str().is_empty() { None } else { Some(CommandPdfRenderer::new(path)) }
}

/// Find a locally installed Chromium-compatible renderer. Explicit setting
/// and environment configuration always take precedence over this fallback.
fn detect_pdf_renderer() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    #[cfg(windows)]
    {
        if let Some(root) = std::env::var_os("ProgramFiles(x86)") {
            candidates.push(PathBuf::from(root).join("Microsoft/Edge/Application/msedge.exe"));
        }
        if let Some(root) = std::env::var_os("ProgramFiles") {
            let root = PathBuf::from(root);
            candidates.push(root.join("Microsoft/Edge/Application/msedge.exe"));
            candidates.push(root.join("Google/Chrome/Application/chrome.exe"));
        }
        if let Some(root) = std::env::var_os("LOCALAPPDATA") {
            candidates.push(PathBuf::from(root).join("Google/Chrome/Application/chrome.exe"));
        }
    }
    #[cfg(unix)]
    candidates.extend([
        PathBuf::from("/usr/bin/google-chrome"),
        PathBuf::from("/usr/bin/chromium"),
        PathBuf::from("/usr/bin/chromium-browser"),
    ]);
    candidates.into_iter().find(|path| path.is_file())
}

#[derive(Serialize)]
struct ReportMetadata<'a> {
    report: &'static str,
    date: &'a str,
    source_window: ReportWindow,
    html: &'a str,
    pdf: &'a str,
    pdf_status: &'a str,
}

/// Write one daily HTML report, metadata sidecar, and (when configured and
/// valid) PDF. Missing/failed renderers leave HTML usable and never fail the
/// report writer loop.
pub fn write_daily_report(
    conn: &Connection,
    reports_dir: &Path,
    date: &str,
    window: ReportWindow,
    renderer: Option<&dyn PdfRenderer>,
) -> Result<String, String> {
    std::fs::create_dir_all(reports_dir).map_err(|e| e.to_string())?;
    let html_name = format!("daily-{date}.html");
    let pdf_name = format!("daily-{date}.pdf");
    let metadata_name = format!("daily-{date}.json");
    let html_path = reports_dir.join(&html_name);
    let pdf_path = reports_dir.join(&pdf_name);
    let status = if renderer.is_some() { "PDF render pending" } else { "PDF unavailable: configure report_pdf_renderer or NMS_PDF_RENDERER" };
    let html = availability_html_with_status(conn, window, status);
    std::fs::write(&html_path, &html).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&pdf_path);
    let pdf_status = match renderer {
        Some(renderer) => match renderer.render(&html_path, &pdf_path) {
            Ok(()) => match std::fs::read(&pdf_path) {
                Ok(bytes) if bytes.starts_with(b"%PDF") => "ready".to_string(),
                Ok(_) => { let _ = std::fs::remove_file(&pdf_path); "renderer did not produce a PDF".to_string() }
                Err(e) => format!("renderer did not produce a PDF: {e}"),
            },
            Err(e) => format!("PDF render failed: {e}"),
        },
        None => "renderer missing".to_string(),
    };
    // Refresh the HTML notice with the final status so a missing or broken
    // browser is visible even when the HTML report is opened directly.
    let final_html = availability_html_with_status(conn, window, &pdf_status);
    if final_html != html {
        std::fs::write(&html_path, final_html).map_err(|e| e.to_string())?;
    }
    let metadata = ReportMetadata { report: "availability", date, source_window: window, html: &html_name, pdf: &pdf_name, pdf_status: &pdf_status };
    let metadata_json = serde_json::to_vec_pretty(&metadata).map_err(|e| e.to_string())?;
    std::fs::write(reports_dir.join(metadata_name), metadata_json).map_err(|e| e.to_string())?;
    Ok(pdf_status)
}

/// Remove all dated report artifacts older than the same 90-day cutoff.
pub fn prune_daily_reports(reports_dir: &Path, now_ts: i64) -> usize {
    let cutoff = chrono::DateTime::from_timestamp(now_ts, 0)
        .map(|v| v.date_naive() - chrono::Duration::days(90));
    let Some(cutoff) = cutoff else { return 0 };
    let Ok(entries) = std::fs::read_dir(reports_dir) else { return 0 };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(date) = name.strip_prefix("daily-").and_then(|v| v.get(..10)) else { continue };
        let Ok(date) = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d") else { continue };
        if date < cutoff && std::fs::remove_file(entry.path()).is_ok() { removed += 1; }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    struct FakeRenderer;

    impl PdfRenderer for FakeRenderer {
        fn render(&self, _html_path: &Path, pdf_path: &Path) -> Result<(), String> {
            std::fs::write(pdf_path, b"%PDF-1.7\nfake\n").map_err(|e| e.to_string())
        }
    }

    fn seeded_db() -> crate::db::Db {
        let db = crate::db::Db::open_memory().unwrap();
        let conn = db.lock();
        conn.execute("INSERT INTO sites(name,created_ts) VALUES ('HQ <west>',1)", []).unwrap();
        conn.execute("INSERT INTO devices(ip,role,site_id,site_source,first_seen_ts,last_seen_ts) VALUES ('10.0.0.1','router',1,'test',1,1)", []).unwrap();
        conn.execute("INSERT INTO rollup_hourly(device_id,hour,probes,ups,rtt_sum) VALUES (1,1500,10,9,90)", []).unwrap();
        drop(conn);
        db
    }

    #[test]
    fn html_is_deterministic_and_records_source_window() {
        let db = seeded_db();
        let conn = db.lock();
        let window = ReportWindow { start_ts: 1000, end_ts: 2000 };
        let first = availability_html(&conn, window);
        assert_eq!(first, availability_html(&conn, window));
        assert!(first.contains("nms-report-source-window"));
        assert!(first.contains("1970-01-01T00:16:40Z"));
        assert!(first.contains("HQ &lt;west&gt;"));
        assert!(first.contains("@page"));
    }

    #[test]
    fn fake_renderer_writes_pdf_and_metadata_window() {
        let db = seeded_db();
        let dir = tempdir().unwrap();
        let conn = db.lock();
        let status = write_daily_report(
            &conn,
            dir.path(),
            "2026-08-24",
            ReportWindow { start_ts: 1000, end_ts: 2000 },
            Some(&FakeRenderer),
        ).unwrap();
        assert_eq!(status, "ready");
        assert!(std::fs::read(dir.path().join("daily-2026-08-24.pdf")).unwrap().starts_with(b"%PDF"));
        let metadata = std::fs::read_to_string(dir.path().join("daily-2026-08-24.json")).unwrap();
        assert!(metadata.contains("\"start_ts\": 1000"));
        assert!(std::fs::read_to_string(dir.path().join("daily-2026-08-24.html")).unwrap().contains("source-window"));
    }

    #[test]
    fn missing_renderer_keeps_html_and_marks_metadata_without_pdf() {
        let db = seeded_db();
        let dir = tempdir().unwrap();
        let conn = db.lock();
        let status = write_daily_report(&conn, dir.path(), "2026-08-24", ReportWindow { start_ts: 1000, end_ts: 2000 }, None).unwrap();
        assert_eq!(status, "renderer missing");
        assert!(dir.path().join("daily-2026-08-24.html").exists());
        assert!(!dir.path().join("daily-2026-08-24.pdf").exists());
        let metadata = std::fs::read_to_string(dir.path().join("daily-2026-08-24.json")).unwrap();
        assert!(metadata.contains("renderer missing"));
        assert!(std::fs::read_to_string(dir.path().join("daily-2026-08-24.html")).unwrap().contains("renderer missing"));
    }

    #[test]
    fn retention_prunes_all_daily_artifact_types_by_date() {
        let dir = tempdir().unwrap();
        for ext in ["html", "pdf", "json", "csv"] {
            std::fs::write(dir.path().join(format!("daily-2026-05-01.{ext}")), b"old").unwrap();
            std::fs::write(dir.path().join(format!("daily-2026-08-01.{ext}")), b"new").unwrap();
        }
        assert_eq!(prune_daily_reports(dir.path(), chrono::DateTime::parse_from_rfc3339("2026-08-24T00:00:00Z").unwrap().timestamp()), 4);
        assert!(!dir.path().join("daily-2026-05-01.html").exists());
        assert!(dir.path().join("daily-2026-08-01.html").exists());
    }

    #[test]
    fn command_renderer_preserves_paths_as_individual_args() {
        let renderer = CommandPdfRenderer::new(PathBuf::from("C:\\Program Files\\Browser\\browser.exe"));
        let args = renderer.args_for(Path::new("C:\\reports with spaces\\report.html"), Path::new("C:\\reports with spaces\\report.pdf"));
        assert_eq!(args.len(), 4);
        assert_eq!(args[2].to_string_lossy(), "--print-to-pdf=C:\\reports with spaces\\report.pdf");
        assert_eq!(args[3].to_string_lossy(), "C:\\reports with spaces\\report.html");
    }
}
