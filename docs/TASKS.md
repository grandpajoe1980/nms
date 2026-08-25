# TASKS — subagent work queue

Lead picks the highest-priority OPEN card, dispatches the listed agent, gates
the result (tester + prd-reviewer), then moves the card to DONE with its commit
hash. One card = one increment = one commit. Cards reference PRD §13 milestones.

Statuses: OPEN | IN-PROGRESS | DONE (<commit>) | BLOCKED (<reason>)

---

## M1 — Hardening (finishing)

### T-001 · ServiceNow e2e verification · agent: integrations-builder · **BLOCKED**
- FRs: INTG-001a. AC: AC-INTG-SNOW.
- Needs: a reachable SNOW instance + service account from the user. Code is
  complete (direct Basic-auth mode shipped); only verification is blocked.

## M2 — StableNet core parity (current milestone)

### T-002 · SSH transport for config backups · agent: config-builder · OPEN
- FRs: CFG-002/003. Scope: `crates/engine/src/cfgmod.rs` + new driver module;
  add `russh` (or `ssh2`) behind a Cargo feature; wire into discovery-enriched
  devices with `snmp`-style opt-in flag `--config-backup`.
- AC: recorded-session fixture test pulls a fake config, stores snapshot,
  produces unified diff vs previous; no credentials in logs.

### T-003 · GETBULK consumers in engine · agent: snmp-collector-builder · OPEN
- FRs: PRF-003, DISC-003. Scope: replace per-column ifTable walks with
  `getbulk()` when agent supports it (bulk walk detection), keep GETNEXT
  fallback; expose `engine::snmpprobe::walk_interfaces_bulk()`.
- AC: equivalence test bulk-vs-getnext on mock agent; ≤50% fewer packets.

### T-004 · Neighbors → topology graph edges · agent: topology-builder · OPEN
- FRs: TOP-002, DISC-004. Depends: T-002 not required.
- Scope: promote `neighbors` rows to versioned graph edges w/ provenance
  (source=lldp|cdp, confidence, validity interval) via new `graph.rs`;
  device-page panel reads edges instead of raw rows.

### T-005 · Capacity trend v0 · agent: reports-sla-builder · OPEN
- FRs: PRF-007 (RTT-trend proxy until counters exist). Scope:
  `reports.rs` linear regression over daily rollups → days-to-threshold JSON
  on `/api/report/capacity.json`; Reports page table column.

## M3 — NetBrain context

### T-006 · Diagnostic bundles ("runbooks lite") · agent: automation-builder · NEXT
- FRs: PTH-003, FLT-007. Scope: YAML bundle schema (`steps: [ping-burst,
  trace, tcp-scan, config-diff]`), executor in engine, attach results to
  incident timeline; auto-run binding for critical alarms.
- AC: bundled run on simulated down-device attaches trace+diag evidence rows.

### T-007 · Intent checks v0 · agent: alarm-rca-builder · OPEN
- FRs: INT-001/002. Scope: declarative assertions evaluated post-cycle;
  violations emit `intent_violation` events; compliance % per site.

### T-008 · Map time-travel scrubber · agent: console-builder · OPEN
- FRs: TOP-003 partial. Scope: snapshot model.json history (hourly) +
  slider to render past topology snapshots.

## M4+ — queued (see PRD §13)

- T-009 Flow ingest spike (flow-builder, IPFIX fixture harness)
- T-010 gNMI dial-out prototype (snmp-collector-builder pair)
- T-011 Prometheus Alertmanager-receiver (integrations-builder)
- T-012 Multi-tenant scoping spikes (security-builder)
- T-013 WASM plugin contract spike (data-platform-builder)

---

## Done (recent)
- ✅ Interface inventory via ifTable walks (FR-DISC-003)
- ✅ LLDP/CDP neighbor collection + UI (FR-DISC-004)
- ✅ ServiceNow direct mode + transform layer (FR-INTG-001a code-complete)
- ✅ GETBULK protocol support (FR-PRF-003 partial)
- ✅ Config snapshot store + diff core (FR-CFG-002/003 store half)
- ✅ Panic-proof job lifecycle + structured logging (reliability hardening)

## Blocked
- ❌ ServiceNow e2e verification — needs live instance + creds from user.
