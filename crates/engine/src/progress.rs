use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static CUR: Mutex<Option<Prog>> = Mutex::new(None);

pub struct Prog {
    label: &'static str,
    done: AtomicU64,
    total: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Snapshot {
    pub label: String,
    pub done: u64,
    pub total: u64,
    /// Whole-job completion, always clamped to the inclusive 0..=100 range.
    pub percent: u8,
}

pub fn begin(label: &'static str, total: usize) {
    let mut g = CUR.lock().unwrap_or_else(|e| e.into_inner());
    *g = Some(Prog {
        label,
        done: AtomicU64::new(0),
        total: total as u64,
    });
}

pub fn tick(n: usize) {
    let g = CUR.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = g.as_ref() {
        let increment = n as u64;
        let mut current = p.done.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(increment).min(p.total);
            match p
                .done
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }
}

pub fn clear() {
    let mut g = CUR.lock().unwrap_or_else(|e| e.into_inner());
    *g = None;
}

pub fn snapshot() -> Option<Snapshot> {
    let g = CUR.lock().unwrap_or_else(|e| e.into_inner());
    g.as_ref().map(|p| {
        let total = p.total;
        let done = p.done.load(Ordering::Relaxed).min(total);
        let percent = if total == 0 {
            100
        } else {
            (done.saturating_mul(100).checked_div(total).unwrap_or(100).min(100)) as u8
        };
        Snapshot {
            label: p.label.to_string(),
            done,
            total,
            percent,
        }
    })
}

#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn snapshot_clamps_done_and_reports_terminal_percent() {
        let _guard = test_lock();
        begin("test", 3);
        tick(99);
        let current = snapshot().unwrap();
        assert_eq!(current.done, 3);
        assert_eq!(current.total, 3);
        assert_eq!(current.percent, 100);
        assert_eq!(snapshot().unwrap().percent, 100);
        clear();
    }

    #[test]
    fn concurrent_ticks_are_monotonic_and_clamped() {
        let _guard = test_lock();
        begin("concurrent", 10_000);
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(thread::spawn(move || {
                for _ in 0..2_000 {
                    tick(1);
                }
            }));
        }
        let mut previous = 0;
        for _ in 0..100_000 {
            let current = snapshot().unwrap().done;
            assert!(current >= previous);
            previous = current;
            if current == 10_000 {
                break;
            }
            thread::yield_now();
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(snapshot().unwrap().percent, 100);
        clear();
    }

    #[test]
    fn partial_completion_is_not_reported_as_terminal_success() {
        let _guard = test_lock();
        begin("partial", 10);
        tick(3);
        assert_eq!(snapshot().unwrap().percent, 30);
        clear();
    }
}
