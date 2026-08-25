//! Declarative network intent checks (FR-INT-001/002).
//! Intents are versioned YAML/JSON files in `output/intents/` that assert
//! desired network state (e.g. "each site has >= 2 up routers"). Evaluated
//! after every sweep cycle; violations emit `intent_violation` alarms.

use crate::db::{self, Db};
use anyhow::Result;
use rusqlite::Connection;
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
pub struct IntentEvalResult {
    pub intent_id: String,
    pub compliant: bool,
    pub violations: Vec<SiteViolation>,
}

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
            let ok = matches!(ext, "yml" | "yaml" | "json");
            if !ok { continue; }
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
        let mut checked = 0usize;
        for site in &target_sites {
            checked += 1;
            match eval_rule(conn, &intent.rule, &site.name) {
                Ok((detail, ok)) if !ok => {
                    violations.push(SiteViolation { site: site.name.clone(), detail });
                }
                _ => {}
            }
        }
        if checked == 0 && !target_sites.is_empty() {
            continue; // no matching sites found
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
        let ev_kind = format!("intent:{}/{}", KIND, intent.id);

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
                let detail = result.violations.iter().map(|v| format!("{}: {}", v.site, v.detail)).join("; ");
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

    // Clear stale intent events whose intents were removed from config
    let active_ids: Vec<String> = intents.iter().map(|i| format!("intent:{}/{}", KIND, i.id)).collect();
    if !active_ids.is_empty() {
        let placeholders: Vec<String> = active_ids.iter().map(|_| "?".to_string()).collect();
        let sql = format!(
            "UPDATE events SET state='cleared', cleared_ts=?1, updated_ts=?1
             WHERE kind LIKE 'intent_violation:%' AND state='open'
             AND kind NOT IN ({})",
            placeholders.join(",")
        );
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(now)];
        for id in &active_ids { params_vec.push(Box::new(id.clone())); }
        let refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|b| b.as_ref()).collect();
        conn.execute(&sql, refs.as_slice())?;
    }

    Ok((created, cleared))
}

use rusqlite::OptionalExtension;

// ------------------------------------------------------------------ helpers

fn join_strings(items: &[SiteViolation], sep: &str) -> String {
    items.iter().map(|v| format!("{}: {}", v.site, v.detail)).collect::<Vec<_>>().join(sep)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn trigger_matcher_matrix() {
        // This tests should_auto_run-style logic applied to intent severities
        let t = Some(Trigger { kinds: vec!["*".into()], severities: vec!["critical".into()] });
        assert!(should_auto_run(&t, "any", "critical"));
    }
}
