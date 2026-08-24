# PROGRESS — autonomous build checkpoint file

Updated at the end of every increment. Newest entry first.
Rules of engagement: docs/PRD.md is source of truth; AGENTS.md workflow applies
(test + clippy + release + docs same-changeset; tester/prd-reviewer gates;
commit cites FR/NFR/§ IDs; push every completed increment).

## Session: overnight autonomous run (started 2026-08-24 ~00:30 local) — WRAP-UP

**Result: 8 commits pushed, M1 effectively complete, four M2 starters landed.**
Production instance restarted on v0.2.0 release (monitoring on, health ok).

**What to know when you wake up:**
1. Every commit on GitHub main is green (tests+clippy+release verified per increment).
2. `crates/collector-snmp` is a real SNMPv2c GET client (BER codec written from
   scratch) proven against an in-process mock UDP agent — the foundation for
   SNMP polling without needing physical devices in CI.
3. Flap-damping had a latent bug (events could never clear during silence);
   found by the new fixture suite and fixed with `stable_cycles` tracking.
4. ServiceNow GA remains blocked pending a SNOW instance for verification.
5. Honest note: PRD §19 sizes full M2–M8 at 245–425 person-months — "complete"
   means continued milestone-by-milestone sessions. Next session should start
   with wiring collector-snmp into discovery (sysName/sysDescr → hostname/
   vendor/OS), then GETBULK ifTable walks.

**Remaining M2 backlog (in order):** SNMP→discovery integration · ifTable
interface inventory · LLDP/CDP neighbor topology · SSH config backup + diff ·
triage-wizard config-diff panel · scheduled reports PDF · scale test AC-NFR-01.

**Directive:** iterate M1-closeout then M2+ slices, auto-commit/push each pass,
keep this file updated, do not pause for confirmation.

**Baseline state at start:** main @ 59618d1 (workspace split). M1 open items:
fixture-based tests, ServiceNow GA. M2–M8 untouched.

### Plan for this run (locally-verifiable increments)

| # | Increment | PRD refs | Status |
|---|---|---|---|
| A | Dependency-suppression + alarm-lifecycle fixture suite (closes "fixture-based tests") | FR-FLT-004/005, AC-FLT-004, §12 | pending |
| B | Prometheus exposition `/metrics` | FR-INTG-003 | pending |
| C | Triage wizard page `/triage?ip=` | FR-UX-005 v0 | pending |
| D | SLA targets per site + attainment in reports | FR-REP-002 v0 | pending |
| E | Global device search API + palette | FR-UX-004 v0 | pending |
| F | SNMP v2c poller core w/ mock-agent BER fixtures (M2 starter) | FR-PRF-003 v0 | pending |
| G+ | Continue down M2 list as budget allows | §13 | — |

**Blocked / deferred (not stoppable by me):**
- ServiceNow GA (FR-INTG-001a) — needs a live SNOW instance for AC-INTG-SNOW.

---

## Session log

### ✅ Increment A — alarm fixture suite + flap-clearing fix (2026-08-24)
- `crates/engine/tests/alarm_fixtures.rs`: AC-FLT-004 scenario (router failure →
  exactly 1 critical incident w/ impacted=3, children `unreachable`, auto-clear on
  recovery) + flap damping scenario (1 warning raised, cleared after stability).
- **Bug found & fixed:** flap events could never clear during silence because
  clearing keyed off a windowed count that doesn't decay; added
  `devices.stable_cycles` (additive migration) = consecutive healthy sweeps,
  clear requires ≥ flap_threshold stable sweeps. Also flap detection now keys
  off effective-state changes (catches topology-driven churn), not sweep
  transitions.
- Model derives Clone (+Default impl for clippy). tempfile dep added (dev).
- Battery: 26 tests pass (22 engine + 2 core-api + 2 fixtures), clippy -D clean,
  release build ok. Committed: see git log "engine: alarm lifecycle fixtures…".

| # | Increment | PRD refs | Status |
|---|---|---|---|
| A | Alarm fixture suite | FR-FLT-004/005, AC-FLT-004 | ✅ done |
| B | Prometheus exposition `/metrics` | FR-INTG-003 | next |
| C | Triage wizard `/triage?ip=` | FR-UX-005 v0 | pending |
| D | SLA targets per site + attainment | FR-REP-002 v0 | ✅ done |
| E | Global device search API + palette | FR-UX-004 v0 | ✅ done |
| F | SNMP v2c poller w/ mock BER agent | FR-PRF-003 v0 | ✅ done |

### ✅ Session log

**B** `/metrics` Prometheus gauges (commit 4c9d1c0) — labeled-series spacing bug caught by test, fixed.
**C** Triage wizard `/triage?ip=` (1c9dfa7) — causal chain walk, impact list, inline diagnostics (FR-UX-005 v0).
**D** SLA targets + met/missed in reports HTML/CSV (84d21e8) — `sla_target_pct` setting (FR-REP-002 v0).
**E** Global search API + nav search box (1b9ecf6) — verified live: 18 devices matched (FR-UX-004 v0).
**F** `crates/collector-snmp` (this commit) — hand-rolled BER codec, GET builder, response parser
(accepts any context PDU tag so client+agent share one decoder), UDP client w/ timeout + request-id
match; **mock SNMP agent fixture** answering from a varbind table; 4 tests incl. end-to-end UDP
roundtrip and unknown-OID→Null. Test totals now **31 passing**, clippy clean, release builds.
**Next up:** wire SNMP poller into discovery (sysName/sysDescr/sysUpTime → hostname/vendor/OS),
then GETBULK ifTable walk for interface inventory (FR-DISC-003).

**Blocked / deferred (not stoppable by me):**
- ServiceNow GA (FR-INTG-001a) — needs a live SNOW instance for AC-INTG-SNOW.
