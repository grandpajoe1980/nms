//! Configuration snapshot store + diff engine (FR-CFG-002, FR-CFG-003).
//!
//! Snapshots live in a content-addressed object-store layout:
//! `<out_dir>/configs/<device_ip>/<yyyy-mm-dd>/<sha256>.cfg` with a
//! `.cfg.meta.json` sidecar (`{collected_ts, sha256}`) beside each snapshot.
//! Saving is idempotent: identical content hashes are never rewritten.
//! Diffs are deterministic: same inputs produce the same output lines.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One collected device configuration (raw text as received).
#[derive(Clone, Debug)]
pub struct ConfigSnapshot {
    pub device_ip: String,
    pub collected_ts: i64,
    pub raw_sha256: String,
    pub content: String,
}

/// Sidecar metadata stored as `<hash>.cfg.meta.json` next to each snapshot.
#[derive(Serialize, Deserialize)]
struct SnapshotMeta {
    collected_ts: i64,
    sha256: String,
}

fn content_sha256(content: &str) -> String {
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    hex_encode(&h.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Reject path-hostile device identifiers (traversal, separators, empties).
/// IPv4 dotted-quad and bare IPv6 literals pass.
fn sanitized_component(name: &str) -> Option<String> {
    if name.is_empty()
        || name.starts_with('.')
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_'))
    {
        return None;
    }
    Some(name.to_string())
}

fn date_dir_name(collected_ts: i64) -> String {
    Utc.timestamp_opt(collected_ts, 0)
        .single()
        .unwrap_or_else(|| {
            Utc.timestamp_opt(0, 0)
                .single()
                .expect("unix epoch is a valid timestamp")
        })
        .format("%Y-%m-%d")
        .to_string()
}

/// Store a snapshot under the content-addressed layout and return its path.
///
/// Idempotent: if the content hash was already written, neither `.cfg` nor
/// sidecar is rewritten. If `snap.raw_sha256` is non-empty it must match the
/// hash of `snap.content` (integrity guard; empty means "compute for me").
pub fn save_snapshot(out_dir: &Path, snap: &ConfigSnapshot) -> Result<PathBuf> {
    let device = sanitized_component(&snap.device_ip)
        .with_context(|| format!("invalid device identifier {:?}", snap.device_ip))?;
    let day = date_dir_name(snap.collected_ts);
    let sha = content_sha256(&snap.content);
    if !snap.raw_sha256.is_empty() && snap.raw_sha256 != sha {
        bail!(
            "declared raw_sha256 {} does not match content hash {}",
            snap.raw_sha256,
            sha
        );
    }
    let dir = out_dir.join("configs").join(device).join(day);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;

    let path = dir.join(format!("{sha}.cfg"));
    if !path.exists() {
        fs::write(&path, &snap.content)
            .with_context(|| format!("write snapshot {}", path.display()))?;
    }
    let meta_path = dir.join(format!("{sha}.cfg.meta.json"));
    if !meta_path.exists() {
        let meta = SnapshotMeta {
            collected_ts: snap.collected_ts,
            sha256: sha,
        };
        fs::write(&meta_path, serde_json::to_string(&meta)?)
            .with_context(|| format!("write sidecar {}", meta_path.display()))?;
    }
    Ok(path)
}

/// Newest snapshot for a device, by `collected_ts` from sidecar metadata.
/// Ties broken deterministically by sha256. Returns `None` when the device
/// has no snapshots.
pub fn latest_snapshot_path(out_dir: &Path, device_ip: &str) -> Result<Option<PathBuf>> {
    let Some(device) = sanitized_component(device_ip) else {
        return Ok(None);
    };
    let dev_dir = out_dir.join("configs").join(device);
    if !dev_dir.is_dir() {
        return Ok(None);
    }
    let mut best: Option<(i64, String, PathBuf)> = None;
    for date in fs::read_dir(&dev_dir).with_context(|| format!("read {}", dev_dir.display()))? {
        let date = date?;
        if !date.file_type()?.is_dir() {
            continue;
        }
        for entry in fs::read_dir(date.path())? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(stem) = name.strip_suffix(".cfg.meta.json") else {
                continue;
            };
            let Ok(text) = fs::read_to_string(entry.path()) else {
                continue;
            };
            let Ok(meta) = serde_json::from_str::<SnapshotMeta>(&text) else {
                continue;
            };
            let cfg = date.path().join(format!("{stem}.cfg"));
            if !cfg.is_file() {
                continue;
            }
            let better = match &best {
                None => true,
                Some((ts, sha, _)) => {
                    meta.collected_ts > *ts
                        || (meta.collected_ts == *ts && meta.sha256 > *sha)
                }
            };
            if better {
                best = Some((meta.collected_ts, meta.sha256, cfg));
            }
        }
    }
    Ok(best.map(|(_, _, p)| p))
}

// --------------------------------------------------------------- diff core

/// One edit operation over the line stream. `Equal`/`Delete` carry an index
/// into the old lines, `Insert` an index into the new lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Equal(usize),
    Delete(usize),
    Insert(usize),
}

/// Longest-common-subsequence line ops, with common prefix/suffix trimmed
/// first so the DP table stays small for typical config drift.
fn line_ops(old: &[&str], new: &[&str]) -> Vec<Op> {
    let mut p = 0;
    while p < old.len() && p < new.len() && old[p] == new[p] {
        p += 1;
    }
    let mut s = 0;
    while s < old.len() - p && s < new.len() - p && old[old.len() - 1 - s] == new[new.len() - 1 - s]
    {
        s += 1;
    }

    let mut ops: Vec<Op> = Vec::new();
    for i in 0..p {
        ops.push(Op::Equal(i));
    }

    let mo = &old[p..old.len() - s];
    let mn = &new[p..new.len() - s];
    let (n, m) = (mo.len(), mn.len());
    // dp[i*(m+1)+j] = LCS length of mo[i..] vs mn[j..].
    let mut dp = vec![0u32; (n + 1) * (m + 1)];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i * (m + 1) + j] = if mo[i] == mn[j] {
                dp[(i + 1) * (m + 1) + (j + 1)] + 1
            } else {
                dp[(i + 1) * (m + 1) + j].max(dp[i * (m + 1) + (j + 1)])
            };
        }
    }
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if mo[i] == mn[j] {
            ops.push(Op::Equal(p + i));
            i += 1;
            j += 1;
        } else if dp[(i + 1) * (m + 1) + j] >= dp[i * (m + 1) + (j + 1)] {
            ops.push(Op::Delete(p + i));
            i += 1;
        } else {
            ops.push(Op::Insert(p + j));
            j += 1;
        }
    }
    while i < n {
        ops.push(Op::Delete(p + i));
        i += 1;
    }
    while j < m {
        ops.push(Op::Insert(p + j));
        j += 1;
    }

    for k in 0..s {
        ops.push(Op::Equal(old.len() - s + k));
    }
    ops
}

/// Minimal unified diff of two texts. Identical inputs yield no output at
/// all; otherwise output is `--- old`, `+++ new`, then one hunk per cluster
/// of changes:
///
/// ```text
/// @@ -<old_start>[,<old_len>] +<new_start>[,<new_len>] @@
/// ```
///
/// with `context` unchanged lines around each change (`,len` omitted when
/// len is 1, per GNU convention). Deterministic for identical inputs.
pub fn unified_diff(old: &str, new: &str, context: usize) -> Vec<String> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let ops = line_ops(&a, &b);
    if ops.iter().all(|op| matches!(op, Op::Equal(_))) {
        return Vec::new();
    }

    // Ops within `context` positions of any change belong to a hunk.
    let is_change = |op: &Op| !matches!(op, Op::Equal(_));
    let mut included = vec![false; ops.len()];
    for (k, op) in ops.iter().enumerate() {
        if is_change(op) {
            let lo = k.saturating_sub(context);
            let hi = (k + context + 1).min(ops.len());
            for inc in &mut included[lo..hi] {
                *inc = true;
            }
        }
    }

    let mut out = vec!["--- old".to_string(), "+++ new".to_string()];
    let (mut oi, mut ni) = (0usize, 0usize);
    let mut k = 0usize;
    while k < ops.len() {
        if !included[k] {
            match ops[k] {
                Op::Equal(_) => {
                    oi += 1;
                    ni += 1;
                }
                Op::Delete(_) => oi += 1,
                Op::Insert(_) => ni += 1,
            }
            k += 1;
            continue;
        }
        let mut end = k;
        while end < ops.len() && included[end] {
            end += 1;
        }
        let (oi0, ni0) = (oi, ni);
        let mut old_len = 0usize;
        let mut new_len = 0usize;
        let mut body = Vec::new();
        for op in &ops[k..end] {
            match *op {
                Op::Equal(x) => {
                    body.push(format!(" {}", a[x]));
                    oi += 1;
                    ni += 1;
                    old_len += 1;
                    new_len += 1;
                }
                Op::Delete(x) => {
                    body.push(format!("-{}", a[x]));
                    oi += 1;
                    old_len += 1;
                }
                Op::Insert(x) => {
                    body.push(format!("+{}", b[x]));
                    ni += 1;
                    new_len += 1;
                }
            }
        }
        let old_start = if old_len == 0 { oi0 } else { oi0 + 1 };
        let new_start = if new_len == 0 { ni0 } else { ni0 + 1 };
        out.push(format!(
            "@@ -{} +{} @@",
            range_part(old_start, old_len),
            range_part(new_start, new_len)
        ));
        out.append(&mut body);
        k = end;
    }
    out
}

fn range_part(start: usize, len: usize) -> String {
    if len == 1 {
        format!("{start}")
    } else {
        format!("{start},{len}")
    }
}

/// Number of changed lines between two texts: deletions + insertions from
/// the same op stream that feeds [`unified_diff`].
pub fn changed_lines_count(old: &str, new: &str) -> usize {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    line_ops(&a, &b)
        .iter()
        .filter(|op| !matches!(op, Op::Equal(_)))
        .count()
}

// ------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn save_then_latest_roundtrip() {
        let out = tempfile::tempdir().unwrap();
        let t1 = 1_700_000_000; // 2023-11-14 UTC
        let t2 = 1_700_086_400; // 2023-11-15 UTC
        let s1 = ConfigSnapshot {
            device_ip: "10.0.0.1".into(),
            collected_ts: t1,
            raw_sha256: String::new(),
            content: "hostname r1\nversion 15\n".into(),
        };
        let p1 = save_snapshot(out.path(), &s1).unwrap();
        assert_eq!(
            p1.parent().unwrap().file_name().unwrap().to_string_lossy(),
            date_dir_name(t1)
        );
        assert_eq!(fs::read_to_string(&p1).unwrap(), s1.content);

        let mut s2 = s1.clone();
        s2.collected_ts = t2;
        s2.content = "hostname r1\nversion 17\n".into();
        let p2 = save_snapshot(out.path(), &s2).unwrap();

        let latest = latest_snapshot_path(out.path(), "10.0.0.1")
            .unwrap()
            .expect("latest exists");
        assert_eq!(latest, p2);
        assert_eq!(fs::read_to_string(&latest).unwrap(), s2.content);

        // Sidecar carries {collected_ts, sha256}.
        let meta_text =
            fs::read_to_string(p2.with_file_name(format!("{}.meta.json", p2.file_name().unwrap().to_string_lossy())))
                .unwrap();
        let meta: SnapshotMeta = serde_json::from_str(&meta_text).unwrap();
        assert_eq!(meta.collected_ts, t2);
        assert_eq!(meta.sha256, content_sha256(&s2.content));

        assert!(latest_snapshot_path(out.path(), "203.0.113.9")
            .unwrap()
            .is_none());
    }

    #[test]
    fn double_save_is_idempotent() {
        let out = tempfile::tempdir().unwrap();
        let s = ConfigSnapshot {
            device_ip: "10.0.0.2".into(),
            collected_ts: 1_700_000_000,
            raw_sha256: String::new(),
            content: "interface Gi1/0/1\n switchport mode access\n".into(),
        };
        let p1 = save_snapshot(out.path(), &s).unwrap();
        let m1 = fs::metadata(&p1).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let p2 = save_snapshot(out.path(), &s).unwrap();
        let m2 = fs::metadata(&p2).unwrap().modified().unwrap();
        assert_eq!(p1, p2);
        assert_eq!(m1, m2, "second save must not rewrite the file");
        assert_eq!(fs::read_to_string(&p2).unwrap(), s.content);
    }

    #[test]
    fn declared_hash_mismatch_is_rejected_and_correct_hash_accepted() {
        let out = tempfile::tempdir().unwrap();
        let bad = ConfigSnapshot {
            device_ip: "10.0.0.3".into(),
            collected_ts: 1_700_000_000,
            raw_sha256: "deadbeef".into(),
            content: "x".into(),
        };
        assert!(save_snapshot(out.path(), &bad).is_err());

        let good_sha = content_sha256("x");
        let ok = ConfigSnapshot {
            raw_sha256: good_sha,
            ..bad
        };
        assert!(save_snapshot(out.path(), &ok).is_ok());

        let hostile = ConfigSnapshot {
            device_ip: "../escape".into(),
            ..ok.clone()
        };
        assert!(save_snapshot(out.path(), &hostile).is_err());
    }

    #[test]
    fn diff_detects_insertion_and_deletion_with_context() {
        let old = "a\nb\nc\nd\ne";
        // Insert X after b: context 1 keeps one line on each side.
        let new = "a\nb\nX\nc\nd\ne";
        assert_eq!(
            unified_diff(old, new, 1),
            vec![
                "--- old",
                "+++ new",
                "@@ -2,2 +2,3 @@",
                " b",
                "+X",
                " c",
            ]
        );
        // Context 0 collapses to the pure-insert hunk form (GNU anchoring:
        // zero-length old range sits after old line 2; X is new line 3).
        assert_eq!(
            unified_diff(old, new, 0),
            vec!["--- old", "+++ new", "@@ -2,0 +3 @@", "+X"]
        );

        // Remove b entirely.
        let removed = "a\nc\nd\ne";
        assert_eq!(
            unified_diff(old, removed, 1),
            vec![
                "--- old",
                "+++ new",
                "@@ -1,3 +1,2 @@",
                " a",
                "-b",
                " c",
            ]
        );
    }

    #[test]
    fn diff_merges_close_changes_into_one_hunk() {
        let old = "a\nb\nc\nd\ne\nf\ng\nh";
        let new = "a\nc\nd\ne\nf\nh"; // remove b and g
                                      // ctx=1: hunks stay apart.
        let d1 = unified_diff(old, new, 1);
        assert_eq!(&d1[2], "@@ -1,3 +1,2 @@");
        assert_eq!(&d1[6], "@@ -6,3 +5,2 @@");
        // ctx=2: windows overlap -> single hunk spanning everything.
        assert_eq!(
            unified_diff(old, new, 2),
            vec![
                "--- old",
                "+++ new",
                "@@ -1,8 +1,6 @@",
                " a",
                "-b",
                " c",
                " d",
                " e",
                " f",
                "-g",
                " h",
            ]
        );
    }

    #[test]
    fn diff_identical_inputs_produce_no_output() {
        let text = "hostname r1\n!\nend\n";
        assert!(unified_diff(text, text, 3).is_empty());
    }

    #[test]
    fn changed_lines_count_math() {
        assert_eq!(changed_lines_count("", ""), 0);
        assert_eq!(changed_lines_count("a\nb\nc", "a\nb\nc"), 0);
        assert_eq!(changed_lines_count("a\nb", "a\nb\nc"), 1);
        assert_eq!(changed_lines_count("a\nb\nX", "a\nb\nY"), 2);
        assert_eq!(changed_lines_count("", "l1\nl2\nl3"), 3);
        assert_eq!(changed_lines_count("l1\nl2\nl3", ""), 3);
        // Trailing newline must not count as an extra line.
        assert_eq!(changed_lines_count("a\n", "a"), 0);
    }
}
