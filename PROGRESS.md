# PROGRESS - autonomous build checkpoint file

## Session: CONTINUATION 7 (2026-08-24)

### Increment K2 - topology graph edges + config backup UI (multi-lane)
| Lane | Agent | Status |
|---|---|---|
| Graph module (graph.rs: BFS, edge promotion, stale decay) | Lead | done |
| Config backup panel on device pages | config-builder subagent | done |
| MTTA verification on Reports page | reports-sla-builder subagent | confirmed existing |
| UI audit fixes (runbooks, inspect, intents, vault, triage, search) | console-builder subagent | done |

Battery: 151 tests passing; clippy clean; release built. Instance restarted.
Next: GETBULK in engine - SSH transport driver - capacity forecast v0.

### Increment K - lockup hotfix (commit ec6b4fa)
Root cause: panics in run_job left job slot stuck + poisoned engine_lock.
Fix: catch_unwind wrapper, always-release job slot, poison-tolerant locks.
max_devices=0 now means all devices (was silently inspecting only 1).

# PROGRESS - autonomous build checkpoint file

## Session: overnight run - CONTINUATION 6 (2026-08-24) - HOTFIX

### Increment K - lockup root-cause fix
**Root cause:** any panic inside run_job left the job slot stuck on the failed
job AND poisoned engine_lock, so every later click panicked too -> UI frozen.
Trigger: Inspect on the live network; plus max_devices=0 silently inspected
only ONE device due to .max(1).

**Fixes:** run_job now runs under catch_unwind; job slot ALWAYS released;
panics become readable messages; locks poison-tolerant (into_inner);
max_devices=0 = all devices; mojibake cleaned.
Verified: inspect completes, check runs right after, pages responsive.
86 tests green; clippy clean; release built; instance restarted.

---

## Session: overnight run - CONTINUATION 4 (2026-08-24)

### ? Increment I ? neighbor/topology foundations (multi-lane, 6 subagents)

**Phase 0 (Lead):** `neighbors` table contract + replace/list helpers (+test).
**Batch 1 (parallel, disjoint scopes):**
- topology-builder ? `engine::neighbors::collect()`: LLDP-MIB + legacy CDP-MIB walks decoded to NeighborRow; 6 tests incl. mock-agent roundtrips for both protocols
- console-builder ? "Discovered neighbors" panel on device pages (+2 tests)
- reports-sla-builder ? `db::mtta_secs_window` Mean-Time-To-Acknowledge metric (+test)
- integrations-builder ? `engine::snow` ServiceNow transform layer: nms.event v1 ? incident body (severity?impact/urgency matrix, correlation_id nms-{id}) + resolve patches for recovery kinds; 6 tests. HTTP delivery wiring deferred (needs instance).
**Batch 2:** Lead wired neighbor collection into the discovery enrichment pass (persisted per device alongside interfaces).

Reviewer PASS-WITH-NOTES applied: docs same-changeset (README/PRD ?13 M3 marker), multi-lane commit citation.
Battery: **80 tests passing** workspace-wide; clippy clean; release built; instance restarted.

| Lane | Agent | Status |
|---|---|---|
| neighbors collect | topology-builder | ? |
| neighbors UI | console-builder | ? |
| MTTA | reports-sla-builder | ? |
| SNOW transform | integrations-builder | ? (delivery pending instance) |
| GETBULK | snmp-collector-builder | ? deferred to next pass |
| discovery wiring | Lead | ? |

**Next up:** GETBULK protocol op ? SSH config backup drivers ? capacity forecast v0.

---
# PROGRESS ? autonomous build checkpoint file

Updated at the end of every increment. Newest entry first.
Rules of engagement: docs/PRD.md is source of truth; AGENTS.md workflow applies
(test + clippy + release + docs same-changeset; tester/prd-reviewer gates;
commit cites FR/NFR/? IDs; push every completed increment).

## Session: overnight run ? CONTINUATION 3 (2026-08-24)

### ? Increment H ? agent workforce expansion + interface inventory (multi-lane)
**Agent team grew to 18**: `lead` primary orchestrator + 10 new specialist
builders (snmp-collector, config, topology, flow, alarm-rca, reports-sla,
security, data-platform, automation, cloud-k8s) + **ideator** (read-only
imagination lane producing ranked idea cards) + existing tester/prd-reviewer/
implementer/engine/console/integrations builders. Lead's routing table updated.

**Multi-lane build (7 subagents dispatched, 5 parallel):**
| Lane | Agent | Delivered |
|---|---|---|
| 1 | snmp-collector-builder | GETNEXT walk + walk_if_table + EndOfMibView + wire fixture (11 snmp tests) |
| 2 | console-builder | Interfaces panel on device page + 5 unit tests |
| 3 | integrations-builder | nms_interfaces_total / oper_up gauges |
| 4 | alarm-rca-builder | storm-suppression fixture: 5? site blackout ? exactly one root critical per episode, zero endpoint storms |
| 5 | security-builder | login brute-force throttling (6 fails/10min ? 429, audited, open-mode exempt; 12?17 core-api tests incl. adversarial) |
| 6 | Lead (direct) | interfaces table migration + store helpers; discovery?walk?persist wiring; mapping seam test |

Reviewer verdict PASS-WITH-NOTES ? all notes applied: docs same-changeset
(README/PRD), commit cites every lane, mapping seam extracted + unit-tested.
Battery: **56 tests passing**, clippy clean, release built. Instance restarted.

**Next up:** GETBULK (real bulk protocol op) ? LLDP/CDP neighbor topology ?
SSH config backup drivers (config-builder lane now staffed).

### ? Increment G ? SNMP identity enrichment wired into discovery
- New `engine::snmpprobe`: `probe_identity(addr, community, timeout)` over the
  collector-snmp client (3 attempts, fresh ephemeral socket each attempt ?
  Windows caches ICMP unreachables per destination ? plus `classify_os()`
  vendor/OS rules covering MikroTik/Cisco/Aruba/Fortinet/pfSense/UniFi/Juniper/
  Linux/Windows).
- `discover` now probes every live host with sysName/sysDescr/sysUpTime when
  `--snmp-community` is set (default **public**; empty disables). sysName fills
  hostname; sysDescr adds `[SNMP] Vendor OS` hints. Web-panel discovery passes
  community automatically. Verified end-to-end against mock agent (hostname
  core-sw, RouterOS classification).
- Battery: **34 tests passing** workspace-wide (4 snmp + 26 engine + 2 core-api +
  2 fixtures); clippy `-D warnings` clean; release built.

**Next up:** GETBULK ifTable walk ? interface inventory table + per-interface
metric seeds (completes FR-DISC-003 / advances FR-PRF-003), then LLDP/CDP.

---

## Session: overnight autonomous run ? WRAP-UP of first pass

**Result: 8 commits pushed, M1 effectively complete, M2 starters landed.**
Production instance runs the v0.2.0 release (monitoring on, health ok).

Key notes:
1. Every commit on GitHub main is green (tests+clippy+release verified per increment).
2. `crates/collector-snmp` = real SNMPv2c GET client, BER codec from scratch,
   proven against an in-process mock UDP agent (no physical devices needed in CI).
3. Latent bug fixed: flap events could never clear during silence ? now uses
   consecutive-stability tracking (`stable_cycles`).
4. ServiceNow GA blocked pending a SNOW instance for AC-INTG-SNOW.
5. Full M2?M8 is sized 245?425 person-months in PRD ?19 ? completion means
   continued milestone-by-milestone sessions like this one.

## Earlier increments this run

| # | Increment | PRD refs | Status |
|---|---|---|---|
| A | Alarm fixture suite (+ flap fix) | FR-FLT-004/005, AC-FLT-004 | ? |
| B | Prometheus `/metrics` gauges | FR-INTG-003 | ? |
| C | Triage wizard `/triage?ip=` | FR-UX-005 v0 | ? |
| D | SLA targets + attainment in reports | FR-REP-002 v0 | ? |
| E | Global search API + nav box | FR-UX-004 v0 | ? |
| F | collector-snmp crate + mock agent | FR-PRF-003 v0 | ? |
| G | SNMP enrichment wired into discovery | FR-DISC-002/PRF-003 | ? |

**Blocked / deferred (not stoppable by me):**
- ServiceNow GA (FR-INTG-001a) ? needs a live SNOW instance for AC-INTG-SNOW.
