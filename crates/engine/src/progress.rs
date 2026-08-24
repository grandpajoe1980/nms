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
        p.done.fetch_add(n as u64, Ordering::Relaxed);
    }
}

pub fn clear() {
    let mut g = CUR.lock().unwrap_or_else(|e| e.into_inner());
    *g = None;
}

pub fn snapshot() -> Option<Snapshot> {
    let g = CUR.lock().unwrap_or_else(|e| e.into_inner());
    g.as_ref().map(|p| Snapshot {
        label: p.label.to_string(),
        done: p.done.load(Ordering::Relaxed),
        total: p.total,
    })
}
