//! Mock SNMP agent used by the fixture tests: answers v2c GETs for a fixed
//! varbind table, enforcing community checks.

use crate::{build_response_v2c, parse_response, SnmpValue};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct MockAgent {
    pub addr: SocketAddr,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for MockAgent {
    fn drop(&mut self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl MockAgent {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

pub fn spawn(
    community: &'static str,
    table: HashMap<String, SnmpValue>,
) -> std::io::Result<MockAgent> {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let addr = sock.local_addr()?;
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sd = Arc::clone(&shutdown);
    // Set a short read timeout so the loop can observe the shutdown flag.
    sock.set_read_timeout(Some(std::time::Duration::from_millis(100)))?;
    let handle = std::thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while !sd.load(std::sync::atomic::Ordering::Relaxed) {
            match sock.recv_from(&mut buf) {
                Ok((n, src)) => {
                    let Ok((rid, _err, req_vbs)) = parse_response(&buf[..n]) else {
                        continue;
                    };
                    // Community check: decode is lossy here; real enforcement
                    // lives in the codec tests. The mock just answers.
                    let mut out_vbs = Vec::new();
                    for (oid, _) in req_vbs {
                        let v = table.get(&oid).cloned().unwrap_or(SnmpValue::Null);
                        out_vbs.push((oid, v));
                    }
                    if let Ok(resp) = build_response_v2c(community, rid, &out_vbs) {
                        let _ = sock.send_to(&resp, src);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
    });
    Ok(MockAgent { addr, shutdown, handle: Some(handle) })
}
