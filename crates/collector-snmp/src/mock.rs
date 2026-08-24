//! Mock SNMP agent used by the fixture tests: answers v2c GET (exact match)
//! and GETNEXT (lexicographic successor over the varbind table, so arbitrary
//! subtree walks work), enforcing community checks. Past the last varbind it
//! reports v2c `endOfMibView`.

use crate::{build_response_v2c, cmp_oid, parse_message, SnmpValue, TAG_PDU_GETNEXT};
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
        let mut keys: Vec<String> = table.keys().cloned().collect();
        keys.sort_by(|a, b| cmp_oid(a, b));
        while !sd.load(std::sync::atomic::Ordering::Relaxed) {
            match sock.recv_from(&mut buf) {
                Ok((n, src)) => {
                    let Ok(msg) = parse_message(&buf[..n]) else {
                        continue;
                    };
                    let mut out_vbs = Vec::new();
                    match msg.pdu_tag {
                        TAG_PDU_GETNEXT => {
                            for (oid, _) in msg.varbinds {
                                match keys.iter().find(|k| cmp_oid(k, &oid) == std::cmp::Ordering::Greater) {
                                    Some(k) => out_vbs.push((
                                        k.clone(),
                                        table.get(k).cloned().unwrap_or(SnmpValue::Null),
                                    )),
                                    None => out_vbs.push((oid, SnmpValue::EndOfMibView)),
                                }
                            }
                        }
                        _ => {
                            for (oid, _) in msg.varbinds {
                                let v = table.get(&oid).cloned().unwrap_or(SnmpValue::Null);
                                out_vbs.push((oid, v));
                            }
                        }
                    }
                    if let Ok(resp) = build_response_v2c(community, msg.request_id, &out_vbs) {
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
