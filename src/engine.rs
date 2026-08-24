use crate::ping;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub struct Target {
    pub ip: Ipv4Addr,
    pub ttl: Option<u8>,
}

impl Target {
    pub fn new(ip: Ipv4Addr) -> Self {
        Target { ip, ttl: None }
    }
    pub fn with_ttl(ip: Ipv4Addr, ttl: u8) -> Self {
        Target { ip, ttl: Some(ttl) }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Outcome {
    pub ip: Ipv4Addr,
    pub probed: bool,
    pub up: bool,
    pub rtt_ms: Option<f64>,
    pub reply_ttl: Option<u8>,
    pub responder: Option<Ipv4Addr>,
}

#[derive(Clone)]
pub struct ScanParams {
    pub rate_pps: f64,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub payload_len: usize,
}

impl Default for ScanParams {
    fn default() -> Self {
        ScanParams { rate_pps: 400.0, concurrency: 512, timeout_ms: 1000, payload_len: 32 }
    }
}

pub struct RateLimiter {
    start: Instant,
    rate: f64,
    count: AtomicU64,
}

pub struct Progress {
    pub done: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Progress {
    pub fn start(label: &'static str, total: usize) -> Self {
        crate::progress::begin(label, total);
        let done = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let done_t = done.clone();
        let stop_t = stop.clone();
        let handle = std::thread::spawn(move || {
            let start = Instant::now();
            while !stop_t.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(250));
                let d = done_t.load(Ordering::Relaxed);
                let el = start.elapsed().as_secs_f64().max(0.001);
                eprint!("\r[>] {d}/{total} probes ({:.0}/s)", d as f64 / el);
            }
        });
        Progress { done, stop, handle: Some(handle) }
    }

    pub fn finish(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        crate::progress::clear();
        eprintln!();
    }
}

impl RateLimiter {
    pub fn new(rate_pps: f64) -> Self {
        RateLimiter { start: Instant::now(), rate: rate_pps.max(1.0), count: AtomicU64::new(0) }
    }

    pub fn acquire(&self) {
        let ticket = self.count.fetch_add(1, Ordering::Relaxed);
        let due = self.start + Duration::from_secs_f64(ticket as f64 / self.rate);
        loop {
            let now = Instant::now();
            if now >= due || due - now > Duration::from_secs(5) {
                return;
            }
            std::thread::sleep((due - now).min(Duration::from_millis(25)));
        }
    }
}

pub fn sweep(
    targets: &[Target],
    p: &ScanParams,
    deadline: Option<Instant>,
    progress: Option<&AtomicUsize>,
) -> anyhow::Result<Vec<Outcome>> {
    let total = targets.len();
    if total == 0 {
        return Ok(Vec::new());
    }
    let cursor = AtomicUsize::new(0);
    let results: Mutex<Vec<Outcome>> = Mutex::new(Vec::with_capacity(total));
    let open_failed = AtomicBool::new(false);
    let workers = p.concurrency.max(1).min(total);
    let limiter = Arc::new(RateLimiter::new(p.rate_pps));

    std::thread::scope(|s| {
        for _w in 0..workers {
            let cursor = &cursor;
            let results = &results;
            let open_failed = &open_failed;
            let limiter = limiter.clone();
            let _ = std::thread::Builder::new()
                .stack_size(256 * 1024)
                .spawn_scoped(s, move || {
                    let mut pinger = match ping::open(p.timeout_ms, p.payload_len) {
                        Ok(pg) => pg,
                        Err(_) => {
                            open_failed.store(true, Ordering::Relaxed);
                            return;
                        }
                    };
                    loop {
                        if let Some(dl) = deadline {
                            if Instant::now() >= dl {
                                break;
                            }
                        }
                        let i = cursor.fetch_add(1, Ordering::Relaxed);
                        if i >= total {
                            break;
                        }
                        limiter.acquire();
                        let t = &targets[i];
                        let r = pinger.ping(t.ip, t.ttl);
                        results.lock().unwrap().push(Outcome {
                            ip: t.ip,
                            probed: true,
                            up: r.up,
                            rtt_ms: r.rtt_ms,
                            reply_ttl: r.reply_ttl,
                            responder: r.responder,
                        });
                        if let Some(pr) = progress {
                            pr.fetch_add(1, Ordering::Relaxed);
                        }
                        crate::progress::tick(1);
                    }
                });
        }
    });

    if open_failed.load(Ordering::Relaxed) {
        anyhow::bail!(
            "failed to open ICMP backend; on Linux/macOS run with root/CAP_NET_RAW or enable ping_group_range"
        );
    }

    let mut got: HashMap<Ipv4Addr, Outcome> =
        results.into_inner().unwrap().into_iter().map(|o| (o.ip, o)).collect();
    let mut out = Vec::with_capacity(total);
    for t in targets {
        out.push(got.remove(&t.ip).unwrap_or(Outcome {
            ip: t.ip,
            probed: false,
            up: false,
            rtt_ms: None,
            reply_ttl: None,
            responder: None,
        }));
    }
    Ok(out)
}
