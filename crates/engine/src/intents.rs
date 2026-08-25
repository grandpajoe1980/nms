//! Declarative network intent checks (FR-INT-001/002).
//! Intents are versioned YAML/JSON files in `output/intents/` that assert
//! desired network state (e.g. "each site has >= 2 up routers"). Evaluated
//! after every sweep cycle; violations emit `intent_violation` alarms.

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    /// Restrict to named sites; empty means all sites.
    #[serde(default)]
    pub sites: Vec<String>,
    pub rule: IntentRule,
}

fn default_severity() -> String { "warning".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IntentRule {
    /// At least N devices of a role must be eff_state=up in each site.
    MinRoleUp { role: String, count: i64 },
    /// Maximum percentage of managed devices allowed down per site.
    MaxDownPct { pct: f64 },
}

/// Result of evaluating one intent across all matching sites.
#[derive(Clone)]
pub struct IntentEvalResult {
    pub intent_id: String,
    pub compliant: bool,
    pub violations: Vec<SiteViolation>,
}

#[derive(Clone)]
pub struct SiteViolation {
    pub site: String,
    pub detail: String,
}

// ------------------------------------------------------------------ loading

pub fn load_intents(intents_dir: &Path) -> Vec<Intent> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(intents_dir) {
        let mut paths: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "yml" | "yaml" | "json") { continue; }
            match (|| -> Result<Intent> {
                let raw = std::fs::read_to_string(&p)?;
                match ext {
                    "json" => Ok(serde_json::from_str(&raw)?),
                    _ => serde_yaml::from_str(&raw).map_err(|e| e.into()),
                }
            })() {
                Ok(intent) => out.push(intent),
                Err(e) => crate::logging::warn(&format!(
                    "intent {} skipped: {e}", p.display()
                )),
            }
        }
    }
    out
}

// -------------------------------------------------------------- evaluation

struct SiteInfo { name: String }

fn all_sites(conn: &Connection) -> Vec<SiteInfo> {
    let mut stmt = match conn.prepare("SELECT name FROM sites ORDER BY name") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    stmt.query_map([], |r| Ok(SiteInfo { name: r.get::<_, String>(0)? }))
        .map(|rows| rows.flatten().collect())
        .unwrap_or_default()
}

/// Evaluate one intent rule for a given site. Returns (actual_value, compliant).
fn eval_rule(
    conn: &Connection,
    rule: &IntentRule,
    site_name: &str,
) -> Result<(String, bool)> {
    let site_id: Option<i64> = conn
        .query_row("SELECT id FROM sites WHERE name=?1", [site_name], |r| r.get(0))
        .ok();

    let Some(site_id) = site_id else {
        return Ok(("site not found".into(), false));
    };

    match rule {
        IntentRule::MinRoleUp { role, count } => {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM devices d
                 WHERE d.site_id = ?1 AND d.role = ?2 AND d.eff_state = 'up' AND d.managed = 1",
                rusqlite::params![site_id, role],
                |r| r.get(0),
            )?;
            Ok((format!("{n}"), *count <= n))
        }
        IntentRule::MaxDownPct { pct } => {
            let (total, down): (i64, i64) = conn.query_row(
                "SELECT COUNT(*),
                        SUM(CASE WHEN eff_state IN ('down','unreachable') THEN 1 ELSE 0 END)
                 FROM devices WHERE site_id = ?1 AND managed = 1",
                [site_id],
                |r| Ok((r.get(0)?, r.get::<_, Option<i64>>(1)?.unwrap_or(0))),
            )?;
            if total == 0 {
                return Ok(("no devices".into(), true));
            }
            let down_pct = 100.0 * down as f64 / total as f64;
            Ok((format!("{down_pct:.1}%"), down_pct <= *pct))
        }
    }
}

/// Evaluate all intents against the current database state.
pub fn evaluate(conn: &Connection, intents: &[Intent]) -> Vec<IntentEvalResult> {
    let sites = all_sites(conn);
    let mut results = Vec::new();

    for intent in intents {
        let target_sites: Vec<&SiteInfo> = if intent.sites.is_empty() {
            sites.iter().collect()
        } else {
            sites.iter().filter(|s| intent.sites.contains(&s.name)).collect()
        };

        let mut violations = Vec::new();
        for site in &target_sites {
            if let Ok((detail, false)) = eval_rule(conn, &intent.rule, &site.name) {
                violations.push(SiteViolation { site: site.name.clone(), detail });
            }
        }
        results.push(IntentEvalResult {
            intent_id: intent.id.clone(),
            compliant: violations.is_empty(),
            violations,
        });
    }
    results
}

// ------------------------------------------------- alarm lifecycle bridge

const KIND: &str = "intent_violation";

/// Composite event kind used by intent violations, e.g.
/// `intent:intent_violation/<id>` — the format the dashboard intent card
/// aggregates on (`kind LIKE 'intent:%'`). Dedupe key stays (device, kind)
/// with device_id NULL so one open violation per intent id (FR-EVT-001).
fn event_kind(intent_id: &str) -> String {
    format!("intent:{KIND}/{intent_id}")
}

/// Create or update `intent_violation` events for non-compliant intents,
/// clear them for recovered ones. Dedupe key: (device_id=NULL, kind=intent:{id}).
pub fn sync_intent_events(
    conn: &Connection,
    eval_results: &[IntentEvalResult],
    intents: &[Intent],
    now: i64,
) -> Result<(usize, usize)> {
    use rusqlite::params;
    let mut created = 0usize;
    let mut cleared = 0usize;

    for result in eval_results {
        let intent = intents.iter().find(|i| i.id == result.intent_id);
        let Some(intent) = intent else { continue };
        let sev = if intent.severity == "critical" { "critical" } else { "warning" };
        let ev_kind = event_kind(&intent.id);

        if result.compliant {
            // Clear any open violation for this intent
            cleared += conn.execute(
                "UPDATE events SET state='cleared', cleared_ts=?2, updated_ts=?2
                 WHERE kind = ?1 AND state = 'open'",
                params![ev_kind, now],
            )?;
        } else {
            // Check for existing open violation (dedupe)
            let existing: Option<i64> = conn
                .query_row(
                    "SELECT id FROM events WHERE kind=?1 AND state='open' LIMIT 1",
                    params![ev_kind],
                    |r| r.get(0),
                )
                .optional()?;

            if existing.is_none() {
                let detail = result.violations.iter()
                    .map(|v| format!("{}: {}", v.site, v.detail))
                    .collect::<Vec<_>>()
                    .join("; ");
                conn.execute(
                    "INSERT INTO events(created_ts, device_id, ip, kind, severity, state,
                         message, details)
                     VALUES (?1, NULL, NULL, ?2, ?3, 'open', ?4, ?5)",
                    params![
                        now,
                        ev_kind,
                        sev,
                        format!("{} ({})", intent.description, detail),
                        serde_json::json!({
                            "intent_id": intent.id,
                            "violations": result.violations.iter().map(|v| serde_json::json!({
                                "site": v.site, "detail": v.detail
                            })).collect::<Vec<_>>(),
                        }).to_string()
                    ],
                )?;
                created += 1;
            }
        }
    }

    // Clear stale intent events whose intents were removed from config.
    // The stored kinds carry the `intent:` composite prefix (see event_kind),
    // so the LIKE pattern must match that prefix, not the bare taxonomy kind.
    let active_ids: Vec<String> = intents.iter().map(|i| event_kind(&i.id)).collect();
    if active_ids.is_empty() {
        cleared += conn.execute(
            "UPDATE events SET state='cleared', cleared_ts=?1, updated_ts=?1
             WHERE kind LIKE 'intent:intent_violation/%' AND state='open'",
            params![now],
        )?;
    } else {
        let placeholders: Vec<String> = active_ids.iter().map(|_| "?".to_string()).collect();
        let sql = format!(
            "UPDATE events SET state='cleared', cleared_ts=?1, updated_ts=?1
             WHERE kind LIKE 'intent:intent_violation/%' AND state='open'
             AND kind NOT IN ({})",
            placeholders.join(",")
        );
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(now)];
        for id in &active_ids { params_vec.push(Box::new(id.clone())); }
        let refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|b| b.as_ref()).collect();
        cleared += conn.execute(&sql, refs.as_slice())?;
    }

    Ok((created, cleared))
}

/// Convenience loader for API consumers (server.rs): load intents plus their
/// live compliance in one call against an already-open connection.
pub fn load_and_evaluate(conn: &Connection, intents_dir: &Path) -> (Vec<Intent>, Vec<IntentEvalResult>) {
    let intents = load_intents(intents_dir);
    let results = evaluate(conn, &intents);
    (intents, results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn seed_site(conn: &Connection, name: &str) -> i64 {
        conn.execute(
            "INSERT INTO sites(name, created_ts) VALUES (?1, 1000)",
            [name],
        ).unwrap();
        conn.last_insert_rowid()
    }

    fn seed_device(conn: &Connection, ip: &str, site_id: i64, role: &str, eff: &str) {
        conn.execute(
            "INSERT INTO devices(ip, role, site_id, managed, first_seen_ts, last_seen_ts,
                 state, eff_state)
             VALUES (?1, ?2, ?3, 1, 1000, 1000, ?4, ?4)",
            rusqlite::params![ip, role, site_id, eff],
        ).unwrap();
    }

    fn min_role_up_intent(id: &str, role: &str, count: i64) -> Intent {
        Intent {
            id: id.into(),
            description: "test intent".into(),
            severity: "critical".into(),
            sites: vec![],
            rule: IntentRule::MinRoleUp { role: role.into(), count },
        }
    }

    fn open_count(conn: &Connection, kind: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM events WHERE kind=?1 AND state='open'",
            [kind],
            |r| r.get(0),
        ).unwrap()
    }

    #[test]
    fn yaml_parse_min_role_up() {
        let yaml = r#"
id: branch-wan-redundancy
description: Branch sites must have 2+ up routers
severity: critical
rule:
  type: min_role_up
  role: router
  count: 2
"#;
        let i: Intent = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(i.id, "branch-wan-redundancy");
        assert_eq!(i.severity, "critical");
        assert!(matches!(i.rule, IntentRule::MinRoleUp { ref role, count: 2 } if role == "router"));
        assert!(i.sites.is_empty());
    }

    #[test]
    fn json_parse_max_down_pct() {
        let json = r#"{"id":"low-down","rule":{"type":"max_down_pct","pct":10.0},"sites":["hq"]}"#;
        let i: Intent = serde_json::from_str(json).unwrap();
        assert_eq!(i.sites, vec!["hq"]);
        assert!(matches!(i.rule, IntentRule::MaxDownPct { pct } if pct == 10.0));
    }

    #[test]
    fn load_intents_reads_sorted_and_skips_invalid() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.yaml"), "not: valid\n").unwrap();
        std::fs::write(
            dir.path().join("b.yaml"),
            "id: wan\nrule:\n  type: min_role_up\n  role: router\n  count: 2\n",
        ).unwrap();
        std::fs::write(dir.path().join("notes.txt"), "ignored").unwrap();
        let loaded = load_intents(dir.path());
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "wan");
    }

    #[test]
    fn evaluation_passes_and_fails_against_seeded_state() {
        let db = Db::open_memory().unwrap();
        let conn = db.lock();
        let hq = seed_site(&conn, "hq");
        seed_device(&conn, "10.0.0.1", hq, "router", "up");
        seed_device(&conn, "10.0.0.2", hq, "router", "up");

        let ok = min_role_up_intent("wan", "router", 2);
        let res = evaluate(&conn, &[ok]);
        assert!(res[0].compliant);
        assert!(res[0].violations.is_empty());

        // Drop one router below the threshold -> violation with detail.
        let failing = min_role_up_intent("wan", "router", 3);
        let res = evaluate(&conn, &[failing]);
        assert!(!res[0].compliant);
        assert_eq!(res[0].violations.len(), 1);
        assert_eq!(res[0].violations[0].site, "hq");
        assert_eq!(res[0].violations[0].detail, "2");
    }

    #[test]
    fn max_down_pct_flags_excess_down_devices() {
        let db = Db::open_memory().unwrap();
        let conn = db.lock();
        let br = seed_site(&conn, "branch-1");
        seed_device(&conn, "10.9.0.1", br, "router", "down");
        seed_device(&conn, "10.9.0.2", br, "endpoint", "down");
        seed_device(&conn, "10.9.0.3", br, "endpoint", "up");
        seed_device(&conn, "10.9.0.4", br, "wap", "up");

        let strict = Intent {
            id: "low-down".into(),
            description: "few downs".into(),
            severity: "warning".into(),
            sites: vec!["branch-1".into()],
            rule: IntentRule::MaxDownPct { pct: 10.0 },
        };
        let res = evaluate(&conn, &[strict]);
        assert!(!res[0].compliant);
        assert_eq!(res[0].violations[0].detail, "50.0%");
    }

    #[test]
    fn sync_dedupes_open_violations_across_cycles() {
        let db = Db::open_memory().unwrap();
        let conn = db.lock();
        let intent = min_role_up_intent("wan", "router", 2);

        let violating = IntentEvalResult {
            intent_id: "wan".into(),
            compliant: false,
            violations: vec![SiteViolation { site: "hq".into(), detail: "1".into() }],
        };
        let (created, _) = sync_intent_events(&conn, std::slice::from_ref(&violating), &[intent], 2000).unwrap();
        assert_eq!(created, 1);
        assert_eq!(open_count(&conn, &event_kind("wan")), 1);

        // Re-evaluation of the same violation must not duplicate the alarm.
        let second = min_role_up_intent("wan", "router", 2);
        let (created, _) =
            sync_intent_events(&conn, &[violating], &[second], 2600).unwrap();
        assert_eq!(created, 0);
        assert_eq!(open_count(&conn, &event_kind("wan")), 1);
    }

    #[test]
    fn recovery_clears_open_violation() {
        let db = Db::open_memory().unwrap();
        let conn = db.lock();
        let intent = min_role_up_intent("wan", "router", 2);
        let violating = IntentEvalResult {
            intent_id: "wan".into(),
            compliant: false,
            violations: vec![SiteViolation { site: "hq".into(), detail: "1".into() }],
        };
        sync_intent_events(&conn, &[violating], &[intent], 2000).unwrap();
        assert_eq!(open_count(&conn, &event_kind("wan")), 1);

        let recovered = min_role_up_intent("wan", "router", 2);
        let compliant = IntentEvalResult {
            intent_id: "wan".into(),
            compliant: true,
            violations: vec![],
        };
        let (_, cleared) =
            sync_intent_events(&conn, &[compliant], &[recovered], 3000).unwrap();
        assert_eq!(cleared, 1);
        assert_eq!(open_count(&conn, &event_kind("wan")), 0);
        let state: String = conn.query_row(
            "SELECT state FROM events WHERE kind=?1 ORDER BY id DESC LIMIT 1",
            [&event_kind("wan")],
            |r| r.get(0),
        ).unwrap();
        assert_eq!(state, "cleared");
    }

    #[test]
    fn stale_clear_uses_composite_kind_prefix() {
        // Regression: the stale-clear UPDATE previously matched
        // `kind LIKE 'intent_violation:%'`, which never matches the actual
        // `intent:intent_violation/<id>` rows, so orphaned violations stayed
        // open forever after their intent was removed.
        let db = Db::open_memory().unwrap();
        let conn = db.lock();
        conn.execute(
            "INSERT INTO events(created_ts, device_id, ip, kind, severity, state, message)
             VALUES (1000, NULL, NULL, 'intent:intent_violation/orphan', 'warning', 'open', 'old')",
            [],
        ).unwrap();

        // Active config only knows about `wan`, evaluated as violating so the
        // create path is exercised too while the orphan must still be cleared.
        let intent = min_role_up_intent("wan", "router", 2);
        let violating = IntentEvalResult {
            intent_id: "wan".into(),
            compliant: false,
            violations: vec![SiteViolation { site: "hq".into(), detail: "1".into() }],
        };
        let (created, cleared) =
            sync_intent_events(&conn, &[violating], &[intent], 4000).unwrap();
        assert_eq!(created, 1);
        assert_eq!(cleared, 1, "orphaned intent event must be cleared by prefix match");
        let orphan_state: String = conn.query_row(
            "SELECT state FROM events WHERE kind='intent:intent_violation/orphan'",
            [],
            |r| r.get(0),
        ).unwrap();
        assert_eq!(orphan_state, "cleared");
        assert_eq!(open_count(&conn, &event_kind("wan")), 1);
    }

    #[test]
    fn removing_all_intents_clears_remaining_violations() {
        let db = Db::open_memory().unwrap();
        let conn = db.lock();
        conn.execute(
            "INSERT INTO events(created_ts, device_id, ip, kind, severity, state, message)
             VALUES (1000, NULL, NULL, 'intent:intent_violation/gone', 'warning', 'open', 'old')",
            [],
        ).unwrap();
        let (_, cleared) = sync_intent_events(&conn, &[], &[], 5000).unwrap();
        assert_eq!(cleared, 1);
        assert_eq!(open_count(&conn, "intent:intent_violation/gone"), 0);
    }

    #[test]
    fn load_and_evaluate_serves_api_shape() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_memory().unwrap();
        let intents_dir = dir.path().join("intents");
        // No intents yet -> empty, no panic.
        let (intents, results) = load_and_evaluate(&db.lock(), &intents_dir);
        assert!(intents.is_empty() && results.is_empty());

        std::fs::create_dir_all(&intents_dir).unwrap();
        std::fs::write(
            intents_dir.join("wan.yaml"),
            "id: wan\nrule:\n  type: min_role_up\n  role: router\n  count: 99\n",
        ).unwrap();
        {
            let conn = db.lock();
            seed_site(&conn, "hq");
            seed_device(&conn, "10.0.0.1", 1, "router", "up");
        }
        let (intents, results) = load_and_evaluate(&db.lock(), &intents_dir);
        assert_eq!(intents.len(), 1);
        assert_eq!(results[0].intent_id, "wan");
        assert!(!results[0].compliant);
    }
}
