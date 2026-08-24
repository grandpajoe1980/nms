use crate::ping;
use anyhow::Result;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, serde::Serialize)]
pub struct DiagResult {
    pub ip: String,
    pub sent: u32,
    pub recv: u32,
    pub loss_pct: f64,
    pub rtt_min: Option<f64>,
    pub rtt_avg: Option<f64>,
    pub rtt_max: Option<f64>,
    pub rtt_p95: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub score: i64,
    pub verdict: &'static str,
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((pct / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Link-quality score 0..100 derived from loss, jitter and latency.
pub fn score(loss_pct: f64, jitter: Option<f64>, avg_rtt: Option<f64>) -> (i64, &'static str) {
    let mut s = 100.0f64;
    s -= loss_pct * 1.5;
    if let Some(j) = jitter {
        s -= (j * 6.0).min(30.0);
    }
    if let Some(a) = avg_rtt {
        s -= ((a - 20.0).max(0.0)) * 0.3;
    }
    let s = s.clamp(0.0, 100.0).round() as i64;
    let verdict = if s >= 90 {
        "excellent"
    } else if s >= 75 {
        "good"
    } else if s >= 50 {
        "fair"
    } else {
        "poor"
    };
    (s, verdict)
}

/// Burst of single pings at a paced rate; the "speed test" of ICMP world:
/// measures responsiveness (loss/jitter/percentiles), not bandwidth Mbps.
pub fn run_burst(ip: Ipv4Addr, count: u32, rate_pps: f64, timeout_ms: u64) -> Result<DiagResult> {
    let mut pinger = ping::open(timeout_ms, 64)?;
    let interval = Duration::from_secs_f64(1.0 / rate_pps.max(1.0));
    let mut rtts: Vec<f64> = Vec::new();
    let mut sent = 0u32;
    let t0 = Instant::now();
    for _ in 0..count {
        let due = t0 + interval * sent;
        let now = Instant::now();
        if due > now {
            std::thread::sleep(due - now);
        }
        sent += 1;
        let r = pinger.ping(ip, None);
        if r.up {
            if let Some(rtt) = r.rtt_ms {
                rtts.push(rtt);
            }
        }
    }
    rtts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let recv = rtts.len() as u32;
    let loss_pct = 100.0 * (sent - recv) as f64 / sent.max(1) as f64;
    let rtt_min = rtts.first().copied();
    let rtt_max = rtts.last().copied();
    let rtt_avg = (!rtts.is_empty()).then(|| rtts.iter().sum::<f64>() / rtts.len() as f64);
    let rtt_p95 = (!rtts.is_empty()).then(|| percentile(&rtts, 95.0));
    let jitter = (rtts.len() >= 2).then(|| {
        let diffs: Vec<f64> =
            rtts.windows(2).map(|w| (w[1] - w[0]).abs()).collect();
        diffs.iter().sum::<f64>() / diffs.len() as f64
    });
    let (score, verdict) = score(loss_pct, jitter, rtt_avg);
    Ok(DiagResult {
        ip: ip.to_string(),
        sent,
        recv,
        loss_pct,
        rtt_min,
        rtt_avg,
        rtt_max,
        rtt_p95,
        jitter_ms: jitter,
        score,
        verdict,
    })
}
