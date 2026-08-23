use crate::check::{self, Transition};
use crate::model::State;
use anyhow::Result;
use chrono::Utc;
use std::io::Write;
use std::time::{Duration, Instant};

pub struct Params {
    pub check: check::Params,
    pub interval_secs: u64,
    pub exec: Option<String>,
}

pub fn run(p: Params) -> Result<()> {
    println!(
        "[*] monitoring started | interval={}s | out={}",
        p.interval_secs,
        p.check.out_dir.display()
    );
    println!("[*] alerts fire on up->down transitions; Ctrl+C to stop");
    let mut cycle = 0u64;
    loop {
        cycle += 1;
        let t0 = Instant::now();
        let stamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        match check::sweep_once(&p.check) {
            Ok(res) => {
                let went_down: Vec<&Transition> =
                    res.transitions.iter().filter(|t| t.to == State::Down && t.from == Some(State::Up)).collect();
                let recovered: Vec<&Transition> =
                    res.transitions.iter().filter(|t| t.to == State::Up && t.from == Some(State::Down)).collect();
                let new_devs: Vec<&Transition> =
                    res.transitions.iter().filter(|t| t.from.is_none() && t.to == State::Up).collect();

                for t in &went_down {
                    fire_down_alert(t, &p, &stamp);
                }
                for t in &recovered {
                    println!("[{stamp}] [recovered] {} {} is back up", t.role.label(), t.ip);
                }
                for t in &new_devs {
                    println!("[{stamp}] [new] {} appeared as {}", t.ip, t.role.label());
                }
                let (up, down, _, _) = res.model.counts();
                println!(
                    "[{stamp}] cycle {cycle}: known_up={up} known_down={down} | {} down-alert(s), {} recovered, {} new | sweep {:.1}s",
                    went_down.len(),
                    recovered.len(),
                    new_devs.len(),
                    t0.elapsed().as_secs_f64()
                );
            }
            Err(e) => eprintln!("[{stamp}] cycle {cycle} failed: {e}"),
        }
        let wait = Duration::from_secs(p.interval_secs)
            .saturating_sub(t0.elapsed())
            .max(Duration::from_secs(1));
        std::thread::sleep(wait);
    }
}

pub fn record_down_alert(t: &Transition, out_dir: &std::path::Path) -> String {
    let stamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let subnet_tag = t.subnet.as_deref().unwrap_or("-");
    let line = format!("[ALERT {stamp}] DOWN {} {ip} [{subnet_tag}]", t.role.label(), ip = t.ip);
    println!("\x07{line}");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let log_path = out_dir.join("alerts.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = writeln!(f, "{line}");
    }
    line
}

fn fire_down_alert(t: &Transition, p: &Params, _stamp: &str) {
    let subnet_tag = t.subnet.as_deref().unwrap_or("-");
    let line = record_down_alert(t, &p.check.out_dir);

    if let Some(tmpl) = &p.exec {
        let cmd = tmpl
            .replace("{ip}", &t.ip.to_string())
            .replace("{role}", t.role.label())
            .replace("{state}", "down")
            .replace("{subnet}", subnet_tag);
        let spawn = if cfg!(windows) {
            std::process::Command::new("cmd").args(["/C", &cmd]).spawn()
        } else {
            std::process::Command::new("sh").arg("-c").arg(&cmd).spawn()
        };
        if let Err(e) = spawn {
            eprintln!("[!] alert exec failed: {e}");
        }
    }
    let _ = line;
}
