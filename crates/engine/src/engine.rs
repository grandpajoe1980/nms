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

/// Factory boundary used by the production scheduler. The real ICMP opener
/// remains the default path; deterministic implementations can be supplied
/// by scale and lifecycle tests without bypassing scheduling or concurrency.
pub(crate) trait ProbeBackend: Send + Sync {
    fn open(&self, timeout_ms: u64, payload_len: usize) -> anyhow::Result<Box<dyn ping::Pinger>>;
}

pub(crate) struct IcmpBackend;

impl ProbeBackend for IcmpBackend {
    fn open(&self, timeout_ms: u64, payload_len: usize) -> anyhow::Result<Box<dyn ping::Pinger>> {
        ping::open(timeout_ms, payload_len)
    }
}

/// Deterministic in-process backend for acceptance tests. It implements the
/// same Pinger boundary as real ICMP while keeping scheduler behavior intact.
#[cfg(test)]
pub struct SyntheticBackend {
    down: Option<Ipv4Addr>,
    calls: Arc<AtomicUsize>,
}

#[cfg(test)]
impl SyntheticBackend {
    pub fn all_up() -> Self { Self { down: None, calls: Arc::new(AtomicUsize::new(0)) } }
    pub fn with_down(ip: Ipv4Addr) -> Self { Self { down: Some(ip), calls: Arc::new(AtomicUsize::new(0)) } }
    pub fn probe_count(&self) -> usize { self.calls.load(Ordering::Relaxed) }
}

#[cfg(test)]
struct SyntheticPinger { down: Option<Ipv4Addr>, calls: Arc<AtomicUsize> }

#[cfg(test)]
impl ping::Pinger for SyntheticPinger {
    fn ping(&mut self, ip: Ipv4Addr, _ttl: Option<u8>) -> ping::RawResult {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.down == Some(ip) { ping::RawResult::down() } else {
            ping::RawResult { up: true, rtt_ms: Some(0.0), reply_ttl: Some(64), responder: Some(ip) }
        }
    }
}

#[cfg(test)]
impl ProbeBackend for SyntheticBackend {
    fn open(&self, _timeout_ms: u64, _payload_len: usize) -> anyhow::Result<Box<dyn ping::Pinger>> {
        Ok(Box::new(SyntheticPinger { down: self.down, calls: self.calls.clone() }))
    }
}

pub struct Progress {
    pub done: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    finished: bool,
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
        Progress { done, stop, handle: Some(handle), finished: false }
    }

    pub fn finish(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.finished = true;
        eprintln!();
    }

    pub fn abort(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() { let _ = h.join(); }
        crate::progress::clear();
        self.finished = true;
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if self.finished { return; }
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() { let _ = h.join(); }
        crate::progress::clear();
    }
}

impl RateLimiter {
    pub fn new(rate_pps: f64) -> Self {
        RateLimiter { start: Instant::now(), rate: rate_pps.max(1.0), count: AtomicU64::new(0) }
    }

    pub fn acquire(&self) {
        let ticket = self.count.fetch_add(1, Ordering::Relaxed);
        let due = self.due_for_ticket(ticket);
        loop {
            let now = Instant::now();
            if now >= due {
                return;
            }
            std::thread::sleep((due - now).min(Duration::from_millis(25)));
        }
    }

    fn due_for_ticket(&self, ticket: u64) -> Instant {
        self.start + Self::delay_for_ticket(self.rate, ticket)
    }

    fn delay_for_ticket(rate: f64, ticket: u64) -> Duration {
        Duration::from_secs_f64(ticket as f64 / rate.max(1.0))
    }
}

pub fn sweep(
    targets: &[Target],
    p: &ScanParams,
    deadline: Option<Instant>,
    progress: Option<&AtomicUsize>,
) -> anyhow::Result<Vec<Outcome>> {
    sweep_with_backend(targets, p, deadline, progress, &IcmpBackend)
}

pub(crate) fn sweep_with_backend(
    targets: &[Target], p: &ScanParams, deadline: Option<Instant>,
    progress: Option<&AtomicUsize>, backend: &dyn ProbeBackend,
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
                    let mut pinger = match backend.open(p.timeout_ms, p.payload_len) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(n: usize) -> Vec<Target> {
        (0..n).map(|i| Target::new(Ipv4Addr::from(0x0a00_0001_u32 + i as u32))).collect()
    }

    #[test]
    fn limiter_does_not_bypass_due_times_beyond_five_seconds() {
        assert_eq!(RateLimiter::delay_for_ticket(1.0, 6), Duration::from_secs(6));
        let limiter = RateLimiter::new(1.0);
        assert!(limiter.due_for_ticket(6) > limiter.start + Duration::from_secs(5));
    }

    #[test]
    fn synthetic_scheduler_fast_equivalent() {
        let _progress_guard = crate::progress::test_lock();
        let target_list = targets(1_000);
        let params = ScanParams { rate_pps: 100_000.0, concurrency: 64, timeout_ms: 1, payload_len: 8 };
        let backend = SyntheticBackend::all_up();
        let start = Instant::now();
        let result = sweep_with_backend(&target_list, &params, None, None, &backend).unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(result.len(), target_list.len());
        assert!(result.iter().all(|outcome| outcome.probed && outcome.up));
    }

    struct SlowPinger;
    impl ping::Pinger for SlowPinger {
        fn ping(&mut self, ip: Ipv4Addr, _ttl: Option<u8>) -> ping::RawResult {
            std::thread::sleep(Duration::from_millis(20));
            ping::RawResult { up: true, rtt_ms: Some(0.0), reply_ttl: None, responder: Some(ip) }
        }
    }
    struct SlowBackend;
    impl ProbeBackend for SlowBackend {
        fn open(&self, _timeout_ms: u64, _payload_len: usize) -> anyhow::Result<Box<dyn ping::Pinger>> {
            Ok(Box::new(SlowPinger))
        }
    }

    #[test]
    fn deadline_partial_sweep_does_not_report_100_percent() {
        let _progress_guard = crate::progress::test_lock();
        let target_list = targets(1_000);
        let params = ScanParams { rate_pps: 100_000.0, concurrency: 8, timeout_ms: 1, payload_len: 8 };
        let progress = Progress::start("deadline-partial", target_list.len());
        let result = sweep_with_backend(
            &target_list,
            &params,
            Some(Instant::now() + Duration::from_millis(1)),
            Some(&progress.done),
            &SlowBackend,
        )
        .unwrap();
        progress.finish();
        assert_eq!(result.len(), target_list.len());
        assert!(result.iter().any(|outcome| !outcome.probed));
        assert!(crate::progress::snapshot().unwrap().percent < 100);
        crate::progress::clear();
    }

    #[test]
    #[ignore = "explicit release scale acceptance; run with --release --ignored"]
    fn ac_nfr_01_fifty_thousand_synthetic_targets() {
        let _progress_guard = crate::progress::test_lock();
        let target_list = targets(50_000);
        let params = ScanParams { rate_pps: 5_000.0, concurrency: 512, timeout_ms: 1, payload_len: 8 };
        let backend = SyntheticBackend::all_up();
        let progress = Progress::start("ac-nfr-01", target_list.len());
        let sampling = Arc::new(AtomicBool::new(true));
        let samples = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sampling_thread = {
            let sampling = sampling.clone();
            let samples = samples.clone();
            std::thread::spawn(move || {
                for _ in 0..20_000 {
                    if !sampling.load(Ordering::Relaxed) { break; }
                    if let Some(snapshot) = crate::progress::snapshot() {
                        samples.lock().unwrap().push(snapshot.percent);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        };
        let start = Instant::now();
        let result = match sweep_with_backend(&target_list, &params, Some(start + Duration::from_secs(90)), Some(&progress.done), &backend) {
            Ok(result) => result,
            Err(error) => {
                sampling.store(false, Ordering::Relaxed);
                let _ = sampling_thread.join();
                progress.abort();
                panic!("scale sweep failed: {error}");
            }
        };
        progress.finish();
        sampling.store(false, Ordering::Relaxed);
        sampling_thread.join().unwrap();
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(9_800), "limiter bypassed: elapsed={elapsed:?}");
        assert!(elapsed <= Duration::from_secs(90), "elapsed={elapsed:?}");
        assert_eq!(result.len(), target_list.len());
        assert!(result.iter().all(|outcome| outcome.probed));
        let samples = samples.lock().unwrap();
        assert!(samples.iter().any(|percent| *percent < 100));
        assert!(samples.windows(2).all(|window| window[1] >= window[0]));
        assert_eq!(crate::progress::snapshot().unwrap().percent, 100);
        crate::progress::clear();
    }
}
