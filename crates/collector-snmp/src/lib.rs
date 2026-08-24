//! Minimal SNMP v2c client (GET + GETNEXT + GETBULK subtree walks) with a
//! hand-rolled BER/ASN.1 codec, verified against an in-process mock UDP agent
//! (see `mock`). Implements FR-PRF-003 (polling framework: [`walk`],
//! [`getbulk`]) and FR-DISC-003 (interface inventory: [`walk_if_table`]);
//! vendor profiles next.

pub mod mock;

use anyhow::{anyhow, bail, Result};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::Duration;

// ------------------------------------------------------------------ BER

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let n = 8 - start;
        out.push(0x80 | n as u8);
        out.extend_from_slice(&bytes[start..]);
    }
}

fn push_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    push_len(out, content.len());
    out.extend_from_slice(content);
}

fn enc_int(v: i64) -> Vec<u8> {
    let mut tmp = vec![];
    let mut x = v;
    loop {
        tmp.insert(0, (x & 0xff) as u8);
        x >>= 8;
        if (x == 0 && tmp[0] & 0x80 == 0) || (x == -1 && tmp[0] & 0x80 != 0) {
            break;
        }
    }
    push_tlv(&mut Vec::new(), 0x02, &tmp);
    let mut out = Vec::new();
    push_tlv(&mut out, 0x02, &tmp);
    out
}

fn enc_octet(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_tlv(&mut out, 0x04, s);
    out
}

fn enc_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// Encode an object identifier string "1.3.6.1..." into BER content octets.
fn enc_oid(oid: &str) -> Result<Vec<u8>> {
    let parts: Arcs = oid
        .split('.')
        .map(|p| p.parse::<u32>().map_err(|_| anyhow!("bad oid part '{p}'")))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if parts.len() < 2 {
        bail!("oid needs at least 2 arcs");
    }
    let mut body = Vec::new();
    let first = parts[0] * 40 + parts[1];
    push_base128(&mut body, first);
    for p in &parts[2..] {
        push_base128(&mut body, *p);
    }
    let mut out = Vec::new();
    push_tlv(&mut out, 0x06, &body);
    Ok(out)
}

type Arcs = Vec<u32>;

fn push_base128(out: &mut Vec<u8>, mut v: u32) {
    if v < 0x80 {
        out.push(v as u8);
        return;
    }
    let mut tmp = vec![ (v & 0x7f) as u8 ];
    v >>= 7;
    while v > 0 {
        tmp.insert(0, ((v & 0x7f) as u8) | 0x80);
        v >>= 7;
    }
    out.extend_from_slice(&tmp);
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn read_len(&mut self) -> Result<usize> {
        let mut len = self.b.get(self.pos).copied().ok_or_else(|| anyhow!("short len"))? as usize;
        self.pos += 1;
        if len & 0x80 != 0 {
            let n = len & 0x7f;
            len = 0;
            for _ in 0..n {
                len = (len << 8) | self.b.get(self.pos).copied().ok_or_else(|| anyhow!("short long-len"))? as usize;
                self.pos += 1;
            }
        }
        Ok(len)
    }

    fn tlv(&mut self, want_tag: u8) -> Result<&'a [u8]> {
        if self.pos >= self.b.len() || self.b[self.pos] != want_tag {
            bail!("expected tag {want_tag:#x} at {}", self.pos);
        }
        self.pos += 1;
        let len = self.read_len()?;
        let end = self.pos + len;
        if end > self.b.len() {
            bail!("tlv overruns buffer");
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Accept any context-constructed PDU tag (A0 Get, A1 GetNext,
    /// A2 Response, A3 Set) so the same decoder serves client and agent.
    fn any_pdu(&mut self) -> Result<&'a [u8]> {
        if self.pos >= self.b.len() || (self.b[self.pos] & 0xF0) != 0xA0 {
            bail!("expected snmp pdu at {}", self.pos);
        }
        self.pos += 1;
        let len = self.read_len()?;
        let end = self.pos + len;
        if end > self.b.len() {
            bail!("pdu overruns buffer");
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn skip_any(&mut self) -> Result<()> {
        if self.pos >= self.b.len() {
            bail!("eof");
        }
        let tag = self.b[self.pos];
        let _ = self.tlv(tag)?;
        Ok(())
    }
}

fn dec_int(b: &[u8]) -> Result<i64> {
    if b.is_empty() {
        return Ok(0);
    }
    let mut v = if b[0] & 0x80 != 0 { -1i64 } else { 0 };
    for &byte in b {
        v = (v << 8) | byte as i64;
    }
    Ok(v)
}

fn dec_oid(content: &[u8]) -> Result<String> {
    if content.is_empty() {
        bail!("empty oid");
    }
    let first = content[0] as u32;
    let a = first / 40;
    let b = first % 40;
    let mut arcs = vec![a, b];
    let mut v: u64 = 0;
    for &byte in &content[1..] {
        v = (v << 7) | (byte & 0x7f) as u64;
        if byte & 0x80 == 0 {
            arcs.push(v as u32);
            v = 0;
        }
    }
    Ok(arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join("."))
}

// ------------------------------------------------------------------ PDU

pub type VarBinds = Vec<(String, SnmpValue)>;

const TAG_SEQUENCE: u8 = 0x30;
const TAG_PDU_GETNEXT: u8 = 0xA1;
const TAG_PDU_RESPONSE: u8 = 0xA2;
/// GetBulkRequest PDU tag (SNMPv2c, RFC 3416 §4.2.3).
const TAG_PDU_GETBULK: u8 = 0xA5;
/// SNMPv2c exception tag: no successor object exists.
const TAG_END_OF_MIB_VIEW: u8 = 0x82;

#[derive(Debug, Clone, PartialEq)]
pub enum SnmpValue {
    Int(i64),
    Str(Vec<u8>),
    Oid(String),
    Null,
    /// v2c `endOfMibView` — lexicographic end of the varbind table.
    EndOfMibView,
    Other,
}

/// Build an SNMPv2c GetRequest for `oids` with the given request id.
pub fn build_get_v2c(community: &str, oids: &[&str], request_id: i32) -> Result<Vec<u8>> {
    let mut varbinds = Vec::new();
    for o in oids {
        let mut vb = enc_oid(o)?;
        vb.extend_from_slice(&enc_null());
        push_tlv(&mut varbinds, TAG_SEQUENCE, &vb);
    }

    let mut pdu = enc_int(request_id as i64);
    pdu.extend_from_slice(&enc_int(0)); // error-status
    pdu.extend_from_slice(&enc_int(0)); // error-index
    push_tlv(&mut pdu, TAG_SEQUENCE, &varbinds); // varbind list
    let mut wrapped = Vec::new();
    push_tlv(&mut wrapped, 0xA0, &pdu); // GetRequest context tag

    let mut msg = enc_int(1); // SNMPv2c
    msg.extend_from_slice(&enc_octet(community.as_bytes()));
    msg.extend_from_slice(&wrapped);
    let mut out = Vec::new();
    push_tlv(&mut out, TAG_SEQUENCE, &msg);
    Ok(out)
}

/// Build an SNMPv2c GetNextRequest for a single `oid` with the given request id.
pub fn build_getnext_v2c(community: &str, oid: &str, request_id: i32) -> Result<Vec<u8>> {
    let mut vb = enc_oid(oid)?;
    vb.extend_from_slice(&enc_null());
    let mut varbinds = Vec::new();
    push_tlv(&mut varbinds, TAG_SEQUENCE, &vb);

    let mut pdu = enc_int(request_id as i64);
    pdu.extend_from_slice(&enc_int(0)); // error-status
    pdu.extend_from_slice(&enc_int(0)); // error-index
    push_tlv(&mut pdu, TAG_SEQUENCE, &varbinds); // varbind list
    let mut wrapped = Vec::new();
    push_tlv(&mut wrapped, TAG_PDU_GETNEXT, &pdu); // GetNextRequest context tag

    let mut msg = enc_int(1); // SNMPv2c
    msg.extend_from_slice(&enc_octet(community.as_bytes()));
    msg.extend_from_slice(&wrapped);
    let mut out = Vec::new();
    push_tlv(&mut out, TAG_SEQUENCE, &msg);
    Ok(out)
}

/// Build an SNMPv2c GetBulkRequest (PDU tag 0xA5, RFC 3416 §4.2.3) for a
/// single `oid`. The PDU carries `non_repeaters` and `max_repetitions` in the
/// slots that GET/GETNEXT use for error-status/error-index.
pub fn build_getbulk_v2c(
    community: &str,
    oid: &str,
    request_id: i32,
    non_repeaters: i32,
    max_repetitions: i32,
) -> Result<Vec<u8>> {
    let mut vb = enc_oid(oid)?;
    vb.extend_from_slice(&enc_null());
    let mut varbinds = Vec::new();
    push_tlv(&mut varbinds, TAG_SEQUENCE, &vb); // varbind list

    let mut pdu = enc_int(request_id as i64);
    pdu.extend_from_slice(&enc_int(non_repeaters as i64)); // non-repeaters
    pdu.extend_from_slice(&enc_int(max_repetitions as i64)); // max-repetitions
    push_tlv(&mut pdu, TAG_SEQUENCE, &varbinds);
    let mut wrapped = Vec::new();
    push_tlv(&mut wrapped, TAG_PDU_GETBULK, &pdu); // GetBulkRequest context tag

    let mut msg = enc_int(1); // SNMPv2c
    msg.extend_from_slice(&enc_octet(community.as_bytes()));
    msg.extend_from_slice(&wrapped);
    let mut out = Vec::new();
    push_tlv(&mut out, TAG_SEQUENCE, &msg);
    Ok(out)
}

/// Build a RESPONSE PDU carrying `varbinds` (used by the mock test agent and
/// useful for simulator tooling).
pub fn build_response_v2c(
    community: &str,
    request_id: i32,
    varbinds: &[(String, SnmpValue)],
) -> Result<Vec<u8>> {
    let mut vb_bytes = Vec::new();
    for (oid, val) in varbinds {
        let mut vb = enc_oid(oid)?;
        match val {
            SnmpValue::Int(v) => vb.extend_from_slice(&enc_int(*v)),
            SnmpValue::Str(s) => vb.extend_from_slice(&enc_octet(s)),
            SnmpValue::Oid(o) => vb.extend_from_slice(&enc_oid(o)?),
            SnmpValue::Null => vb.extend_from_slice(&enc_null()),
            SnmpValue::EndOfMibView => vb.extend_from_slice(&[TAG_END_OF_MIB_VIEW, 0x00]),
            SnmpValue::Other => vb.extend_from_slice(&enc_null()),
        }
        push_tlv(&mut vb_bytes, TAG_SEQUENCE, &vb);
    }
    let mut pdu = enc_int(request_id as i64);
    pdu.extend_from_slice(&enc_int(0));
    pdu.extend_from_slice(&enc_int(0));
    push_tlv(&mut pdu, TAG_SEQUENCE, &vb_bytes);
    let mut wrapped = Vec::new();
    push_tlv(&mut wrapped, TAG_PDU_RESPONSE, &pdu);
    let mut msg = enc_int(1);
    msg.extend_from_slice(&enc_octet(community.as_bytes()));
    msg.extend_from_slice(&wrapped);
    let mut out = Vec::new();
    push_tlv(&mut out, TAG_SEQUENCE, &msg);
    Ok(out)
}

/// A decoded SNMP message: request id, error status, raw PDU tag
/// (`0xA0` GET, `0xA1` GETNEXT, `0xA2` RESPONSE, `0xA5` GETBULK, ...) and
/// varbinds. For GetBulkRequest PDUs the `non_repeaters` / `max_repetitions`
/// fields carry the bulk parameters (they reuse the error-status /
/// error-index wire slots per RFC 3416 §4.2.3); for all other PDUs they
/// mirror `error_status` / the error-index value.
#[derive(Debug, Clone)]
pub struct SnmpMessage {
    pub request_id: i32,
    pub error_status: i16,
    pub non_repeaters: i16,
    pub max_repetitions: i16,
    pub pdu_tag: u8,
    pub varbinds: VarBinds,
}

/// Parse any SNMP message (request or response) into its parts. The mock test
/// agent uses this to serve GET, GETNEXT and GETBULK from the same loop;
/// responses with repeated varbinds (bulk semantics) decode like any other
/// varbind list.
pub fn parse_message(buf: &[u8]) -> Result<SnmpMessage> {
    let mut top = Reader { b: buf, pos: 0 };
    let msg = top.tlv(TAG_SEQUENCE)?;
    let mut r = Reader { b: msg, pos: 0 };
    let _version = dec_int(r.tlv(0x02)?)?;
    let _community = r.tlv(0x04)?;
    if r.pos >= r.b.len() || (r.b[r.pos] & 0xF0) != 0xA0 {
        bail!("expected snmp pdu at {}", r.pos);
    }
    let pdu_tag = r.b[r.pos];
    let pdu = r.any_pdu()?;
    let mut pr = Reader { b: pdu, pos: 0 };
    let req_id = dec_int(pr.tlv(0x02)?)? as i32;
    let err_status = dec_int(pr.tlv(0x02)?)? as i16;
    let err_index = dec_int(pr.tlv(0x02)?)? as i16;
    let mut vbs = Reader { b: pr.tlv(TAG_SEQUENCE)?, pos: 0 };

    let mut out = Vec::new();
    while vbs.pos < vbs.b.len() {
        let vb = vbs.tlv(TAG_SEQUENCE)?;
        let mut vr = Reader { b: vb, pos: 0 };
        let oid = dec_oid(vr.tlv(0x06)?)?;
        if vr.pos >= vr.b.len() {
            out.push((oid, SnmpValue::Null));
            continue;
        }
        let tag = vr.b[vr.pos];
        match tag {
            0x02 => out.push((oid, SnmpValue::Int(dec_int(vr.tlv(0x02)?)?))),
            0x04 => out.push((oid, SnmpValue::Str(vr.tlv(0x04)?.to_vec()))),
            0x05 => {
                let _ = vr.tlv(0x05)?;
                out.push((oid, SnmpValue::Null));
            }
            0x06 => out.push((oid, SnmpValue::Oid(dec_oid(vr.tlv(0x06)?)?))),
            TAG_END_OF_MIB_VIEW => {
                let _ = vr.tlv(TAG_END_OF_MIB_VIEW)?;
                out.push((oid, SnmpValue::EndOfMibView));
            }
            _ => {
                let _ = vr.skip_any();
                out.push((oid, SnmpValue::Other));
            }
        }
    }
    Ok(SnmpMessage {
        request_id: req_id,
        error_status: err_status,
        non_repeaters: err_status,
        max_repetitions: err_index,
        pdu_tag,
        varbinds: out,
    })
}

/// Parse a RESPONSE message into (request_id, error_status, varbinds).
pub fn parse_response(buf: &[u8]) -> Result<(i32, i16, VarBinds)> {
    parse_message(buf).map(|m| (m.request_id, m.error_status, m.varbinds))
}

// ------------------------------------------------------------------ client

/// Issue one SNMPv2c GET against `target`; returns varbinds from the response.
pub fn get(
    target: SocketAddr,
    community: &str,
    oids: &[&str],
    timeout_ms: u64,
    request_id: i32,
) -> Result<VarBinds> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(target)?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    let req = build_get_v2c(community, oids, request_id)?;
    sock.send(&req)?;
    let mut buf = [0u8; 65535];
    let n = sock.recv(&mut buf)?;
    let (rid, err, vbs) = parse_response(&buf[..n])?;
    if rid != request_id {
        bail!("request id mismatch");
    }
    if err != 0 {
        bail!("snmp error-status {err}");
    }
    Ok(vbs)
}

/// Safety cap so a misbehaving agent cannot keep [`getbulk`] iterating
/// forever; far above any real MIB-II subtree size.
const GETBULK_MAX_VARS: usize = 65_535;

/// Walk `root_oid` with repeated SNMPv2c GETBULK (FR-PRF-003): each round asks
/// for up to `max_repetitions` lexicographic successors of the cursor.
/// Traversal stops when the agent leaves the subtree, reports `endOfMibView`,
/// fails to advance (non-monotonic guard), an empty batch arrives, or
/// [`GETBULK_MAX_VARS`] varbinds were collected. Fresh UDP socket per request —
/// same Windows WSAECONNRESET rationale as `engine::snmpprobe`.
pub fn getbulk(
    target: SocketAddr,
    community: &str,
    root_oid: &str,
    timeout_ms: u64,
    request_id: i32,
    max_repetitions: i32,
) -> Result<VarBinds> {
    let root = parse_arcs(root_oid)?;
    let mut out = Vec::new();
    let mut cursor = root_oid.to_string();
    while out.len() < GETBULK_MAX_VARS {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        sock.connect(target)?;
        sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
        let rid = request_id.wrapping_add(out.len() as i32);
        let req = build_getbulk_v2c(community, &cursor, rid, 0, max_repetitions)?;
        sock.send(&req)?;
        let mut buf = [0u8; 65535];
        let n = sock.recv(&mut buf)?;
        let msg = parse_message(&buf[..n])?;
        if msg.request_id != rid {
            bail!("request id mismatch");
        }
        if msg.error_status != 0 {
            bail!("snmp error-status {}", msg.error_status);
        }
        if msg.varbinds.is_empty() {
            break;
        }
        let mut done = false;
        for (oid, val) in msg.varbinds {
            if val == SnmpValue::EndOfMibView || !within_subtree(&root, &oid) {
                done = true;
                break;
            }
            if cmp_oid(&oid, &cursor) != Ordering::Greater {
                done = true; // non-monotonic agent: never loop forever
                break;
            }
            cursor = oid.clone();
            out.push((oid, val));
        }
        if done {
            break;
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------ walk

/// Numeric arc vector for decoder-produced OID strings (best-effort).
fn arcs(oid: &str) -> Vec<u32> {
    oid.split('.').filter_map(|p| p.parse::<u32>().ok()).collect()
}

/// Strict arc parse for caller-supplied OID strings.
fn parse_arcs(oid: &str) -> Result<Vec<u32>> {
    oid.split('.')
        .map(|p| p.parse::<u32>().map_err(|_| anyhow!("bad oid part '{p}'")))
        .collect()
}

/// SNMP lexicographic OID ordering: per-arc numeric, shorter prefix first.
fn cmp_oid(a: &str, b: &str) -> Ordering {
    arcs(a).cmp(&arcs(b))
}

/// True when `oid` is a strict descendant of `root_arcs` (arc-boundary aware,
/// so `1.3.6.1.2` does NOT match `1.3.6.1.20.x`).
fn within_subtree(root_arcs: &[u32], oid: &str) -> bool {
    let o = arcs(oid);
    o.len() > root_arcs.len() && o.starts_with(root_arcs)
}

/// Walk `root_oid` with repeated SNMPv2c GETNEXT (FR-PRF-003 v0). Traversal is
/// lexicographic and stops when the agent leaves the subtree, reports
/// `endOfMibView`, fails to advance, or `max_rows` varbinds were collected.
/// Fresh UDP socket per request — same Windows WSAECONNRESET rationale as
/// `engine::snmpprobe`.
pub fn walk(
    target: SocketAddr,
    community: &str,
    root_oid: &str,
    timeout_ms: u64,
    max_rows: usize,
) -> Result<VarBinds> {
    let root = parse_arcs(root_oid)?;
    let mut out = Vec::new();
    let mut cursor = root_oid.to_string();
    while out.len() < max_rows {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        sock.connect(target)?;
        sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
        let request_id = out.len() as i32 + 1;
        let req = build_getnext_v2c(community, &cursor, request_id)?;
        sock.send(&req)?;
        let mut buf = [0u8; 65535];
        let n = sock.recv(&mut buf)?;
        let msg = parse_message(&buf[..n])?;
        if msg.request_id != request_id {
            bail!("request id mismatch");
        }
        if msg.error_status != 0 {
            bail!("snmp error-status {}", msg.error_status);
        }
        let Some((oid, val)) = msg.varbinds.into_iter().next() else {
            bail!("empty varbind list in response");
        };
        if val == SnmpValue::EndOfMibView || !within_subtree(&root, &oid) {
            break;
        }
        if cmp_oid(&oid, &cursor) != Ordering::Greater {
            break; // non-monotonic agent: never loop forever
        }
        cursor = oid.clone();
        out.push((oid, val));
    }
    Ok(out)
}

// ------------------------------------------------------------------ ifTable

/// ifName column root (ifXTable).
pub const COL_IF_NAME: &str = "1.3.6.1.2.1.31.1.1.1.1";
/// ifHighSpeed column root (ifXTable, Mbps).
pub const COL_IF_HIGH_SPEED: &str = "1.3.6.1.2.1.31.1.1.1.15";
/// ifAdminStatus column root (ifTable).
pub const COL_IF_ADMIN_STATUS: &str = "1.3.6.1.2.1.2.2.1.7";
/// ifOperStatus column root (ifTable).
pub const COL_IF_OPER_STATUS: &str = "1.3.6.1.2.1.2.2.1.8";
/// ifPhysAddress column root (ifTable).
pub const COL_IF_PHYS_ADDRESS: &str = "1.3.6.1.2.1.2.2.1.6";

/// One interface row decoded from the MIB-II ifTable/ifXTable (FR-DISC-003).
#[derive(Debug, Clone, PartialEq)]
pub struct IfaceEntry {
    pub if_index: i64,
    pub name: Option<String>,
    /// Bits per second (ifHighSpeed Mbps × 1_000_000).
    pub speed_bps: Option<i64>,
    /// `up | down | testing`
    pub admin_status: Option<String>,
    /// `up | down | testing`
    pub oper_status: Option<String>,
    /// Lowercase colon-separated hex (`aa:bb:..`).
    pub mac: Option<String>,
}

fn column_map(col_root: &str, rows: VarBinds) -> BTreeMap<i64, SnmpValue> {
    let mut m = BTreeMap::new();
    for (oid, val) in rows {
        let idx = oid
            .strip_prefix(col_root)
            .and_then(|s| s.strip_prefix('.'))
            .and_then(|s| s.parse::<i64>().ok());
        if let Some(idx) = idx {
            m.insert(idx, val);
        }
    }
    m
}

fn decode_name(v: &SnmpValue) -> Option<String> {
    match v {
        SnmpValue::Str(b) => std::str::from_utf8(b)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        _ => None,
    }
}

fn decode_speed(v: &SnmpValue) -> Option<i64> {
    match v {
        SnmpValue::Int(mbps) if *mbps >= 0 => mbps.checked_mul(1_000_000),
        _ => None,
    }
}

/// RFC 2863 ifStatus integers we surface: 1 up, 2 down, 3 testing.
fn decode_status(v: &SnmpValue) -> Option<String> {
    match v {
        SnmpValue::Int(n) => match n {
            1 => Some("up"),
            2 => Some("down"),
            3 => Some("testing"),
            _ => None,
        }
        .map(str::to_string),
        _ => None,
    }
}

fn decode_mac(v: &SnmpValue) -> Option<String> {
    match v {
        SnmpValue::Str(b) if !b.is_empty() => Some(
            b.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        ),
        _ => None,
    }
}

/// Interface inventory convenience walk (FR-DISC-003): walks each
/// ifName/ifHighSpeed/ifAdminStatus/ifOperStatus/ifPhysAddress column subtree
/// separately and joins rows by ifIndex (single-arc instance suffix, per
/// MIB-II). Results are ordered by ascending ifIndex.
pub fn walk_if_table(
    target: SocketAddr,
    community: &str,
    timeout_ms: u64,
    max_ifaces: usize,
) -> Result<Vec<IfaceEntry>> {
    let names = column_map(
        COL_IF_NAME,
        walk(target, community, COL_IF_NAME, timeout_ms, max_ifaces)?,
    );
    let speeds = column_map(
        COL_IF_HIGH_SPEED,
        walk(target, community, COL_IF_HIGH_SPEED, timeout_ms, max_ifaces)?,
    );
    let admins = column_map(
        COL_IF_ADMIN_STATUS,
        walk(target, community, COL_IF_ADMIN_STATUS, timeout_ms, max_ifaces)?,
    );
    let opers = column_map(
        COL_IF_OPER_STATUS,
        walk(target, community, COL_IF_OPER_STATUS, timeout_ms, max_ifaces)?,
    );
    let macs = column_map(
        COL_IF_PHYS_ADDRESS,
        walk(target, community, COL_IF_PHYS_ADDRESS, timeout_ms, max_ifaces)?,
    );

    let mut indexes: BTreeSet<i64> = BTreeSet::new();
    for m in [&names, &speeds, &admins, &opers, &macs] {
        indexes.extend(m.keys().copied());
    }

    Ok(indexes
        .into_iter()
        .map(|idx| IfaceEntry {
            if_index: idx,
            name: names.get(&idx).and_then(decode_name),
            speed_bps: speeds.get(&idx).and_then(decode_speed),
            admin_status: admins.get(&idx).and_then(decode_status),
            oper_status: opers.get(&idx).and_then(decode_status),
            mac: macs.get(&idx).and_then(decode_mac),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
    const SYS_UPTIME: &str = "1.3.6.1.2.1.1.3.0";

    fn mock_table() -> HashMap<String, SnmpValue> {
        let mut table = HashMap::new();
        table.insert(
            SYS_DESCR.to_string(),
            SnmpValue::Str(b"RouterOS 7.14 test bench".to_vec()),
        );
        table.insert(SYS_UPTIME.to_string(), SnmpValue::Int(123_456_700));
        table
    }

    #[test]
    fn oid_codec_roundtrip() {
        for oid in ["1.3.6.1.2.1.1.1.0", "1.3", "1.3.6.1.4.1.9"] {
            let enc = enc_oid(oid).unwrap();
            let mut r = Reader { b: &enc, pos: 0 };
            let dec = dec_oid(r.tlv(0x06).unwrap()).unwrap();
            assert_eq!(dec, oid);
        }
        assert!(enc_oid("banana").is_err());
    }

    #[test]
    fn int_encoding_minimal_two_complement() {
        assert_eq!(enc_int(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(enc_int(127), vec![0x02, 0x01, 0x7f]);
        assert_eq!(enc_int(128), vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn get_roundtrip_against_mock_agent() {
        let a = mock::spawn("public", mock_table()).unwrap();
        let vbs = get(a.addr, "public", &[SYS_DESCR, SYS_UPTIME], 500, 42).unwrap();
        assert_eq!(vbs.len(), 2);
        assert_eq!(vbs[0].0, SYS_DESCR);
        assert_eq!(
            vbs[0].1,
            SnmpValue::Str(b"RouterOS 7.14 test bench".to_vec())
        );
        assert_eq!(vbs[1].1, SnmpValue::Int(123_456_700));
    }

    #[test]
    fn unknown_oid_returns_null_varbind() {
        let a = mock::spawn("public", mock_table()).unwrap();
        let vbs = get(a.addr, "public", &["1.3.6.1.9.9.9"], 500, 7).unwrap();
        assert_eq!(vbs[0].1, SnmpValue::Null);
    }

    // ------------------------------------------------ ifTable walk fixtures

    /// System scalars + a 2-interface MIB-II table:
    /// eth0 = index 1, gigE, admin up / oper up; eth1 = index 2, 100 Mbps,
    /// admin up / oper down.
    fn if_table_fixture() -> HashMap<String, SnmpValue> {
        const COL_IF_INDEX: &str = "1.3.6.1.2.1.2.2.1.1";
        let mut t = mock_table();
        type Row = (i64, &'static [u8], i64, i64, i64, [u8; 6]);
        let rows: [Row; 2] = [
            (1, b"eth0", 1000, 1, 1, [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]),
            (2, b"eth1", 100, 1, 2, [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02]),
        ];
        for (idx, name, mbps, admin, oper, mac) in rows {
            t.insert(format!("{COL_IF_INDEX}.{idx}"), SnmpValue::Int(idx));
            t.insert(format!("{COL_IF_NAME}.{idx}"), SnmpValue::Str(name.to_vec()));
            t.insert(format!("{COL_IF_HIGH_SPEED}.{idx}"), SnmpValue::Int(mbps));
            t.insert(format!("{COL_IF_ADMIN_STATUS}.{idx}"), SnmpValue::Int(admin));
            t.insert(format!("{COL_IF_OPER_STATUS}.{idx}"), SnmpValue::Int(oper));
            t.insert(format!("{COL_IF_PHYS_ADDRESS}.{idx}"), SnmpValue::Str(mac.to_vec()));
        }
        t
    }

    #[test]
    fn oid_ordering_and_subtree_helpers() {
        assert!(matches!(
            cmp_oid("1.3.6.1.2.1.2.2.1.7.1", "1.3.6.1.2.1.2.2.1.7.2"),
            Ordering::Less
        ));
        assert!(matches!(
            cmp_oid("1.3.6.1.2.1.2.2.1.7.10", "1.3.6.1.2.1.2.2.1.7.2"),
            Ordering::Greater
        ));
        assert!(!within_subtree(&parse_arcs("1.3.6.1.2").unwrap(), "1.3.6.1.20.1"));
        assert!(within_subtree(
            &parse_arcs("1.3.6.1.2.2.1").unwrap(),
            "1.3.6.1.2.2.1.6.1"
        ));
        assert!(!within_subtree(
            &parse_arcs("1.3.6.1.2.2.1").unwrap(),
            "1.3.6.1.2.2.1"
        ));
    }

    #[test]
    fn getnext_walk_returns_interface_names_in_order() {
        let a = mock::spawn("public", if_table_fixture()).unwrap();
        let rows = walk(a.addr, "public", COL_IF_NAME, 500, 10).unwrap();
        assert_eq!(
            rows,
            vec![
                (format!("{COL_IF_NAME}.1"), SnmpValue::Str(b"eth0".to_vec())),
                (format!("{COL_IF_NAME}.2"), SnmpValue::Str(b"eth1".to_vec())),
            ]
        );
    }

    #[test]
    fn walk_stops_when_leaving_subtree() {
        // Global successor of the last ifAdminStatus row is ifOperStatus.1 —
        // outside the admin column subtree — so traversal must stop at 2 rows
        // even though more table OIDs exist.
        let a = mock::spawn("public", if_table_fixture()).unwrap();
        let rows = walk(a.addr, "public", COL_IF_ADMIN_STATUS, 500, 100).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .all(|(o, _)| o.starts_with(&format!("{COL_IF_ADMIN_STATUS}."))));
    }

    #[test]
    fn walk_max_rows_caps_iteration() {
        let a = mock::spawn("public", if_table_fixture()).unwrap();
        // 8 rows live under the whole ifTable column family
        // (index/physAddr/admin/oper × 2 interfaces); the ifXTable branch
        // (1.3.6.1.2.1.31.*) sorts above this subtree and is never entered.
        let rows = walk(a.addr, "public", "1.3.6.1.2.1.2.2.1", 500, 5).unwrap();
        assert_eq!(rows.len(), 5);
        let full = walk(a.addr, "public", "1.3.6.1.2.1.2.2.1", 500, 100).unwrap();
        assert_eq!(full.len(), 8);
        assert_eq!(full.last().unwrap().0, format!("{COL_IF_OPER_STATUS}.2"));
    }

    #[test]
    fn walk_if_table_joins_columns_by_index() {
        let a = mock::spawn("public", if_table_fixture()).unwrap();
        let ifs = walk_if_table(a.addr, "public", 500, 50).unwrap();
        assert_eq!(
            ifs,
            vec![
                IfaceEntry {
                    if_index: 1,
                    name: Some("eth0".into()),
                    speed_bps: Some(1_000_000_000),
                    admin_status: Some("up".into()),
                    oper_status: Some("up".into()),
                    mac: Some("aa:bb:cc:00:00:01".into()),
                },
                IfaceEntry {
                    if_index: 2,
                    name: Some("eth1".into()),
                    speed_bps: Some(100_000_000),
                    admin_status: Some("up".into()),
                    oper_status: Some("down".into()),
                    mac: Some("aa:bb:cc:00:00:02".into()),
                },
            ]
        );
    }

    // ------------------------------------------------------ wire fixtures

    /// Codec change fixture (rule: every codec change asserts exact bytes):
    /// v2c response carrying `endOfMibView` for OID 1.3.
    #[test]
    fn end_of_mib_view_wire_fixture() {
        let bytes =
            build_response_v2c("public", 9, &[("1.3".to_string(), SnmpValue::EndOfMibView)])
                .unwrap();
        let expected: Vec<u8> = vec![
            0x30, 0x1f, // SEQUENCE, msg len 31
            0x02, 0x01, 0x01, // version 2c
            0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // community
            0xa2, 0x12, // Response PDU, len 18
            0x02, 0x01, 0x09, // request-id 9
            0x02, 0x01, 0x00, // error-status 0
            0x02, 0x01, 0x00, // error-index 0
            0x30, 0x07, // varbind list
            0x30, 0x05, // varbind
            0x06, 0x01, 0x2b, // OID 1.3
            0x82, 0x00, // endOfMibView
        ];
        assert_eq!(bytes, expected);
        let m = parse_message(&bytes).unwrap();
        assert_eq!(m.pdu_tag, TAG_PDU_RESPONSE);
        assert_eq!(m.varbinds[0].1, SnmpValue::EndOfMibView);
    }

    /// Mock agent serves GETNEXT successors and reports endOfMibView past the
    /// last varbind.
    #[test]
    fn mock_getnext_serves_successors_then_end_of_mib_view() {
        let a = mock::spawn("public", if_table_fixture()).unwrap();
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

        let req = build_getnext_v2c("public", "1.3.6.1.2.1.2.2.1.1", 33).unwrap();
        sock.send_to(&req, a.addr).unwrap();
        let mut buf = [0u8; 1500];
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        let m = parse_message(&buf[..n]).unwrap();
        assert_eq!(m.pdu_tag, TAG_PDU_RESPONSE);
        assert_eq!(m.request_id, 33);
        assert_eq!(
            m.varbinds[0],
            (
                "1.3.6.1.2.1.2.2.1.1.1".to_string(),
                SnmpValue::Int(1)
            )
        );

        // ifHighSpeed.2 is the lexicographically last key in the table, so
        // GETNEXT past it reports endOfMibView.
        let req = build_getnext_v2c("public", &format!("{COL_IF_HIGH_SPEED}.2"), 34).unwrap();
        sock.send_to(&req, a.addr).unwrap();
        let n = sock.recv(&mut buf).unwrap();
        let m = parse_message(&buf[..n]).unwrap();
        assert_eq!(m.varbinds[0].1, SnmpValue::EndOfMibView);
    }

    // -------------------------------------------------- GETBULK fixtures

    /// Wire fixture (rule: every codec change asserts exact bytes):
    /// v2c GetBulkRequest for `1.3.6.1.2.1.2.2.1`, request-id 7,
    /// non-repeaters 0, max-repetitions 10 (PDU tag 0xA5).
    #[test]
    fn getbulk_wire_fixture() {
        let bytes = build_getbulk_v2c("public", "1.3.6.1.2.1.2.2.1", 7, 0, 10).unwrap();
        let expected: Vec<u8> = vec![
            0x30, 0x26, // SEQUENCE, msg len 38
            0x02, 0x01, 0x01, // version 2c
            0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // community
            0xa5, 0x19, // GetBulkRequest PDU, len 25
            0x02, 0x01, 0x07, // request-id 7
            0x02, 0x01, 0x00, // non-repeaters 0
            0x02, 0x01, 0x0a, // max-repetitions 10
            0x30, 0x0e, // varbind list, len 14
            0x30, 0x0c, // varbind, len 12
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, // OID
            0x05, 0x00, // NULL value
        ];
        assert_eq!(bytes, expected);
        let m = parse_message(&bytes).unwrap();
        assert_eq!(m.pdu_tag, TAG_PDU_GETBULK);
        assert_eq!(m.request_id, 7);
        assert_eq!(m.non_repeaters, 0);
        assert_eq!(m.max_repetitions, 10);
        assert_eq!(
            m.varbinds,
            vec![("1.3.6.1.2.1.2.2.1".to_string(), SnmpValue::Null)]
        );
    }

    /// Mock agent serves GETBULK: up to `max_repetitions` lexicographic
    /// successors per repeated varbind, echoing the request id, with
    /// `endOfMibView` filling past the end of the varbind table and
    /// `non_repeaters` varbinds behaving like GETNEXT.
    #[test]
    fn mock_getbulk_caps_at_max_repetitions_then_end_of_mib_view() {
        let a = mock::spawn("public", if_table_fixture()).unwrap();
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buf = [0u8; 1500];

        // Ten repetitions from the ifName root cross into the ifHighSpeed
        // column (global lexicographic order) then exhaust the MIB: the
        // response holds exactly max_repetitions varbinds.
        let req = build_getbulk_v2c("public", COL_IF_NAME, 55, 0, 10).unwrap();
        sock.send_to(&req, a.addr).unwrap();
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        let m = parse_message(&buf[..n]).unwrap();
        assert_eq!(m.pdu_tag, TAG_PDU_RESPONSE);
        assert_eq!(m.request_id, 55);
        assert_eq!(m.varbinds.len(), 10); // repetition cap enforced
        assert_eq!(
            m.varbinds[0],
            (format!("{COL_IF_NAME}.1"), SnmpValue::Str(b"eth0".to_vec()))
        );
        assert_eq!(m.varbinds[1].0, format!("{COL_IF_NAME}.2"));
        assert_eq!(m.varbinds[2].0, format!("{COL_IF_HIGH_SPEED}.1"));
        assert_eq!(
            m.varbinds[3],
            (format!("{COL_IF_HIGH_SPEED}.2"), SnmpValue::Int(100))
        );
        assert!(m.varbinds[4..].iter().all(|(_, v)| *v == SnmpValue::EndOfMibView));

        // Starting at the lexicographically last key, every repetition is
        // endOfMibView.
        let req =
            build_getbulk_v2c("public", &format!("{COL_IF_HIGH_SPEED}.2"), 56, 0, 3).unwrap();
        sock.send_to(&req, a.addr).unwrap();
        let n = sock.recv(&mut buf).unwrap();
        let m = parse_message(&buf[..n]).unwrap();
        assert_eq!(m.request_id, 56);
        assert_eq!(m.varbinds.len(), 3);
        assert!(m.varbinds.iter().all(|(_, v)| *v == SnmpValue::EndOfMibView));

        // non_repeaters = 1: the sole varbind gets ONE successor instead of a
        // repetition chain.
        let req = build_getbulk_v2c("public", COL_IF_NAME, 57, 1, 4).unwrap();
        sock.send_to(&req, a.addr).unwrap();
        let n = sock.recv(&mut buf).unwrap();
        let m = parse_message(&buf[..n]).unwrap();
        assert_eq!(m.request_id, 57);
        // The response carries exactly ONE varbind (a GETNEXT-style single
        // successor), proving the agent honored non_repeaters instead of
        // returning the 4-repetition chain.
        assert_eq!(m.varbinds.len(), 1);
        assert_eq!(m.varbinds[0].0, format!("{COL_IF_NAME}.1"));
    }

    /// Client wrapper: GETBULK walk covers the whole ifTable column family in
    /// batches and matches the GETNEXT [`walk`] result exactly.
    #[test]
    fn getbulk_walk_matches_getnext_walk() {
        let a = mock::spawn("public", if_table_fixture()).unwrap();
        let bulk = getbulk(a.addr, "public", "1.3.6.1.2.1.2.2.1", 500, 900, 3).unwrap();
        let next = walk(a.addr, "public", "1.3.6.1.2.1.2.2.1", 500, 100).unwrap();
        assert_eq!(bulk, next);
        assert_eq!(bulk.len(), 8);
    }

    /// Client wrapper roundtrip vs mock: traversal exits the requested column
    /// subtree mid-batch (out-of-subtree successors are discarded) and small
    /// repetition caps only mean more rounds — never lost or extra rows.
    #[test]
    fn getbulk_subtree_exit_and_repetition_cap_roundtrip() {
        let a = mock::spawn("public", if_table_fixture()).unwrap();

        // Each batch would return up to 10 successors spanning several
        // columns; only the 2 admin-status rows may be kept.
        let rows = getbulk(a.addr, "public", COL_IF_ADMIN_STATUS, 500, 70, 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .all(|(o, _)| o.starts_with(&format!("{COL_IF_ADMIN_STATUS}."))));

        // Cap of one repetition degenerates to GETNEXT-per-round yet still
        // yields the complete subtree.
        let rows = getbulk(a.addr, "public", COL_IF_NAME, 500, 71, 1).unwrap();
        assert_eq!(
            rows,
            vec![
                (format!("{COL_IF_NAME}.1"), SnmpValue::Str(b"eth0".to_vec())),
                (format!("{COL_IF_NAME}.2"), SnmpValue::Str(b"eth1".to_vec())),
            ]
        );
    }
}
