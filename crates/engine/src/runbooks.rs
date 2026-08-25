use crate::db::Db;
use anyhow::{anyhow, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const SCHEMA: &str = "nms.runbook.v1";

pub fn builtin_down_triage() -> BundleDef {
    BundleDef {
        schema: SCHEMA.into(), name: "down-device-triage".into(), title: "Down device triage".into(),
        trigger: Some(Trigger { kinds: vec!["device_down".into()], severities: vec!["critical".into()] }),
        steps: vec![
            StepDef { id: "ping".into(), kind: StepKind::PingBurst { count: 20, rate_pps: 20.0, timeout_ms: 1000 } },
            StepDef { id: "trace".into(), kind: StepKind::Trace { max_hops: 15 } },
            StepDef { id: "ports".into(), kind: StepKind::TcpScan { ports: None, timeout_ms: 250 } },
        ],
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Trigger { pub kinds: Vec<String>, pub severities: Vec<String> }
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StepDef { pub id: String, #[serde(flatten)] pub kind: StepKind }

#[allow(non_snake_case)]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StepKind {
    PingBurst { #[serde(default = "dc")] count: u32, #[serde(default = "dr")] rate_pps: f64, #[serde(default = "dt")] timeout_ms: u64 },
    Trace { #[serde(default = "dh")] max_hops: u8 },
    TcpScan { ports: Option<Vec<u16>>, #[serde(default = "dst")] timeout_ms: u64 },
    Pause { seconds: f64 },
}
fn dc() -> u32 { 20 } fn dr() -> f64 { 20.0 } fn dt() -> u64 { 1000 } fn dh() -> u8 { 15 } fn dst() -> u64 { 250 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BundleDef {
    #[serde(default = "ds")] pub schema: String,
    pub name: String, #[serde(default)] pub title: String,
    #[serde(default)] pub trigger: Option<Trigger>,
    pub steps: Vec<StepDef>,
}
fn ds() -> String { SCHEMA.into() }
impl BundleDef {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA { return Err(anyhow!("bad schema")); }
        if self.name.trim().is_empty() { return Err(anyhow!("name required")); }
        if self.steps.is_empty() { return Err(anyhow!("steps required")); } Ok(())
    }
}

const TABLE_SQL: &str = "
CREATE TABLE IF NOT EXISTS bundle_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bundle TEXT NOT NULL, device_ip TEXT NOT NULL, event_id INTEGER,
  started_ts INTEGER NOT NULL, finished_ts INTEGER,
  status TEXT NOT NULL DEFAULT 'running', steps_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_br_device ON bundle_runs(device_ip, started_ts);
";
pub fn ensure_schema(c: &Connection) -> Result<()> { c.execute_batch(TABLE_SQL)?; Ok(()) }

pub fn load_bundles(out_dir: &Path) -> Vec<BundleDef> {
    let mut out = Vec::new();
    let dir = out_dir.join("bundles");
    if let Ok(rd) = std::fs::read_dir(&dir) {
        let mut ps: Vec<_> = rd.flatten().map(|e| e.path()).collect(); ps.sort();
        for p in ps {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "yml"|"yaml"|"json") { continue; }
            let r = (|| -> Result<BundleDef> {
                let raw = std::fs::read_to_string(&p)?;
                let d: BundleDef = match ext { "json" => serde_json::from_str(&raw)?, _ => serde_yaml::from_str(&raw)? };
                d.validate()?; Ok(d)
            })();
            match r { Ok(d) => out.push(d), Err(e) => crate::logging::warn(&format!("rb skip {}: {}", p.display(), e)) }
        }
    }
    out.push(builtin_down_triage()); out
}

pub fn should_auto_run(t: &Option<Trigger>, kind: &str, sev: &str) -> bool {
    match t { None => false, Some(t) => t.kinds.iter().any(|k| k==kind) && t.severities.iter().any(|s| s==sev) }
}

static ACTIVE: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Serialize)]
pub struct StepResult { pub id: String, #[serde(rename="type")] pub kind: String, pub status: String, pub ms: u128, #[serde(skip_serializing_if="Option::is_none")] pub output: Option<serde_json::Value> }

pub fn execute(dbh: &Arc<Db>, b: &BundleDef, ip: Ipv4Addr, eid: Option<i64>, dl_ms: u64) -> Result<i64> {
    if ACTIVE.load(Ordering::Relaxed) >= 2 { return Err(anyhow!("concurrency cap")); }
    ACTIVE.fetch_add(1, Ordering::Relaxed);
    let r = exec_inner(dbh, b, ip, eid, dl_ms);
    ACTIVE.fetch_sub(1, Ordering::Relaxed); r
}

fn exec_inner(dbh: &Arc<Db>, b: &BundleDef, ip: Ipv4Addr, eid: Option<i64>, dl_ms: u64) -> Result<i64> {
    b.validate()?;
    let conn = dbh.lock(); ensure_schema(&conn)?;
    let now = chrono::Utc::now().timestamp();
    conn.execute("INSERT INTO bundle_runs(bundle,device_ip,event_id,started_ts,status) VALUES(?1,?2,?3,?4,'running')",
        rusqlite::params![b.name, ip.to_string(), eid, now])?;
    let rid = conn.last_insert_rowid(); drop(conn);
    let deadline = Instant::now() + Duration::from_millis(dl_ms.max(1000));
    let mut results: Vec<StepResult> = Vec::new();
    for step in &b.steps {
        if Instant::now() >= deadline {
            results.push(StepResult{ id:step.id.clone(), kind:skn(&step.kind).into(), status:"skipped".into(), ms:0, output:Some(serde_json::json!({"reason":"deadline"})) }); continue;
        }
        let t0 = Instant::now();
        match run_step(&step.kind, ip, deadline) {
            Ok(o) => results.push(StepResult{ id:step.id.clone(), kind:skn(&step.kind).into(), status:"ok".into(), ms:t0.elapsed().as_millis(), output:Some(o) }),
            Err(e) => results.push(StepResult{ id:step.id.clone(), kind:skn(&step.kind).into(), status:"fail".into(), ms:t0.elapsed().as_millis(), output:Some(serde_json::json!({"error":e.to_string()})) }),
        }
    }
    let all_skipped = results.iter().all(|r| r.status=="skipped");
    let any_fail = results.iter().any(|r| r.status=="fail");
    let status = if all_skipped {"skipped"} else if any_fail {"failed"} else {"ok"};
    let sj = serde_json::to_string(&results).unwrap_or_else(|_| "[]".into());
    let conn = dbh.lock();
    conn.execute("UPDATE bundle_runs SET finished_ts=?2,status=?3,steps_json=?4 WHERE id=?1",
        rusqlite::params![rid, chrono::Utc::now().timestamp(), status, sj])?;
    Ok(rid)
}

fn skn(k:&StepKind)->&'static str { match k { StepKind::PingBurst{..}=>"ping_burst", StepKind::Trace{..}=>"trace", StepKind::TcpScan{..}=>"tcp_scan", StepKind::Pause{..}=>"pause" } }

fn run_step(k:&StepKind, ip:Ipv4Addr, dl:Instant)->Result<serde_json::Value> {
    match k {
        StepKind::PingBurst{count,rate_pps,timeout_ms}=>{ let d=crate::diag::run_burst(ip,*count,*rate_pps,*timeout_ms)?; Ok(serde_json::to_value(&d)?) }
        StepKind::Trace{max_hops}=>{ let h=crate::trace::trace_path(ip,*max_hops,700,3)?; Ok(serde_json::to_value(&h)?) }
        StepKind::TcpScan{ports,timeout_ms}=>{ let l=ports.clone().unwrap_or_else(||crate::profile::PROFILE_PORTS.to_vec()); let o=crate::profile::scan_ports(ip,&l,*timeout_ms); let n=crate::profile::service_names(); let s:Vec<serde_json::Value>=o.iter().map(|p|serde_json::json!({"port":p,"service":n.get(p).copied().unwrap_or("?")})).collect(); Ok(serde_json::json!({"open":o,"services":s})) }
        StepKind::Pause{seconds}=>{ let d=Duration::from_secs_f64((*seconds).clamp(0.0,30.0)); if Instant::now()+d>dl{return Err(anyhow!("over deadline"))} std::thread::sleep(d); Ok(serde_json::json!({"paused":seconds})) }
    }
}

pub fn recent_runs(c:&Connection,ip:&str,limit:i64)->Result<Vec<serde_json::Value>> {
    let mut s=c.prepare("SELECT id,bundle,started_ts,finished_ts,status FROM bundle_runs WHERE device_ip=?1 ORDER BY id DESC LIMIT ?2")?;
    let rows=s.query_map(rusqlite::params![ip,limit],|r|Ok(serde_json::json!({"id":r.get::<_,i64>(0)?,"bundle":r.get::<_,String>(1)?,"started_ts":r.get::<_,i64>(2)?,"finished_ts":r.get::<_,Option<i64>>(3)?,"status":r.get::<_,String>(4)?})))?;
    Ok(rows.flatten().collect())
}

pub fn get_run(c:&Connection,id:i64)->Result<Option<serde_json::Value>> {
    use rusqlite::OptionalExtension;
    c.query_row("SELECT id,bundle,device_ip,started_ts,finished_ts,status,steps_json FROM bundle_runs WHERE id=?1",rusqlite::params![id],|r|{
        Ok(serde_json::json!({"id":r.get::<_,i64>(0)?,"bundle":r.get::<_,String>(1)?,"device_ip":r.get::<_,String>(2)?,"started_ts":r.get::<_,i64>(3)?,"finished_ts":r.get::<_,Option<i64>>(4)?,"status":r.get::<_,String>(5)?,"steps":serde_json::from_str::<serde_json::Value>(&r.get::<_,String>(6)?).unwrap_or(serde_json::json!([]))}))
    }).optional().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trigger_matching() {
        let t=Some(Trigger{kinds:vec!["device_down".into()],severities:vec!["critical".into()]});
        assert!(should_auto_run(&t,"device_down","critical"));
        assert!(!should_auto_run(&t,"device_down","info"));
        assert!(!should_auto_run(&None,"device_down","critical"));
    }
    #[test]
    fn validate_rejects_empty() {
        let mut b=builtin_down_triage(); b.steps.clear(); assert!(b.validate().is_err());
        let mut c=builtin_down_triage(); c.schema="x".into(); assert!(c.validate().is_err());
        assert!(builtin_down_triage().validate().is_ok());
    }
    #[test]
    fn execute_persists_evidence() {
        let dbh=Arc::new(Db::open_memory().unwrap());
        { let c=dbh.lock(); ensure_schema(&c).unwrap(); }
        let b=builtin_down_triage();
        let ip:Ipv4Addr="127.0.0.1".parse().unwrap();
        let rid=execute(&dbh,&b,ip,None,30000).unwrap();
        let conn=dbh.lock();
        let run=get_run(&conn,rid).unwrap().unwrap();
        assert_eq!(run["status"],"ok");
        assert_eq!(run["steps"].as_array().unwrap().len(),3);
        assert_eq!(run["steps"].as_array().unwrap()[2]["type"],"tcp_scan");
    }
}