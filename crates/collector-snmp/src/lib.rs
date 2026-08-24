//! Minimal SNMP v2c client (GET only) with hand-rolled BER/ASN.1 codec.
//! Verified against an in-process mock UDP agent (see mock/tests). This is the
//! seed of FR-PRF-003; GETBULK/walks land next.

pub mod mock;

use anyhow::{anyhow, bail, Result};
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
const TAG_PDU_RESPONSE: u8 = 0xA2;

#[derive(Debug, Clone, PartialEq)]
pub enum SnmpValue {
    Int(i64),
    Str(Vec<u8>),
    Oid(String),
    Null,
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

/// Parse a RESPONSE message into (request_id, error_status, varbinds).
pub fn parse_response(buf: &[u8]) -> Result<(i32, i16, VarBinds)> {
    let mut top = Reader { b: buf, pos: 0 };
    let msg = top.tlv(TAG_SEQUENCE)?;
    let mut r = Reader { b: msg, pos: 0 };
    let _version = dec_int(r.tlv(0x02)?)?;
    let _community = r.tlv(0x04)?;
    let pdu = r.any_pdu()?;
    let mut pr = Reader { b: pdu, pos: 0 };
    let req_id = dec_int(pr.tlv(0x02)?)? as i32;
    let err_status = dec_int(pr.tlv(0x02)?)? as i16;
    let _err_index = dec_int(pr.tlv(0x02)?)?;
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
            _ => {
                let _ = vr.skip_any();
                out.push((oid, SnmpValue::Other));
            }
        }
    }
    Ok((req_id, err_status, out))
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
}
