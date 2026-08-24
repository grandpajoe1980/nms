# PRD — Open-Source Network Management Platform ("nms-ng")

**Version:** 1.0 · **Status:** Approved for build · **Audience:** AI programmers / implementers
**Goal:** Clean-sheet rebuild of *Infosim StableNet* (unified fault/performance/config/inventory management) and *NetBrain* (network context model: Device–Topology–Path–Intent, runbooks, triggered diagnostics) as one **free, open-source platform**, better than both.
**Reference deployment target:** 850 sites · ~3,000 routers · ~50,000 endpoints · detection-to-notification ≤ 2 minutes.

> **How to read this document.** Every requirement has an ID (`FR-<DOMAIN>-<nnn>`), a priority
> (**P0** = MVP must-have, **P1** = next, **P2** = differentiator, **P3** = later), and is written to be
> directly implementable and testable. "MVP" = Milestone M2 (§13). When this PRD conflicts with
> marketing language of the reference products, this PRD wins.

---

## 0. Executive Summary

Build a single, modular, API-first network observability + automation platform that unifies:

| Pillar | From StableNet | From NetBrain |
|---|---|---|
| Discovery & Inventory | multi-vendor auto-discovery, unified data model | device context model (150+ vendors) |
| Fault & RCA | alarm lifecycle, dependency-aware root cause | triggered diagnostics on every alarm |
| Performance | KPI/SLA polling at scale | data views on live maps |
| Configuration | vendor-independent backup/compliance/change | config drift + golden configs |
| Path | — | L2/L3 path computation + verification ("Path Doctor") |
| Automation | workflow engine | no-code runbooks/intents, closed-loop remediation |
| Intelligence | BI reporting, baselines | agentic AI assistant over a knowledge graph |

**Core thesis:** StableNet's weakness is closedness/cost; NetBrain's weakness is complexity/cost.
We win by making the *unified data model* open (documented schemas, APIs), the *collector* tiny and
fast (single static binary), the *automation* declarative (YAML intents/runbooks in Git), and the
*intelligence* pluggable (local-first ML + optional LLM).

---

## 1. Personas & Jobs-To-Be-Done

| Persona | JTBD |
|---|---|
| NOC operator (L1) | "Something broke — tell me what, where, who's impacted, and what to check first, in <2 min." |
| Network engineer (L2/L3) | "Show me the path, the config delta since yesterday, and run my standard diagnostic bundle." |
| Network architect | "Is the network conforming to design intent? What drifted? Capacity outlook?" |
| IT manager | "Availability/SLA per site, MTTR trends, evidence for leadership." |
| MSP operator | "Run many customer networks isolated from each other." (P2) |
| Home-lab user | `nms serve` → working map + monitoring in 60 s, zero config. |

---

## 2. Non-Goals (explicit)

- Not a SIEM/log lake replacement (syslog correlation only).
- Not a packet broker / full PCAP retention store (on-demand captures only, size-capped).
- Not a configuration *editor*/push-first tool (read + verify + guarded remediation only).
- No SaaS-only mode; everything must run self-hosted/air-gapped.

---

## 3. System Architecture

### 3.1 Topology of components

```
┌─────────────────────────────────────────────────────────────┐
│ Control Plane (core)                                        │
│  REST/gRPC API · Scheduler · Alarm/RCA Engine · Runbook     │
│  Engine · RBAC/Authn (optional mode) · Web Console          │
├─────────────────────────────────────────────────────────────┤
│ Data Plane                                                  │
│  Message bus (NATS JetStream) — topics: metrics, events,    │
│  states, topology, configs, flows, traces                   │
├──────────────┬──────────────┬───────────────────────────────┤
│ Collector(s) │ Flow Collector│ Ingest Workers               │
│ (Rust agent, │ (IPFIX/sFlow) │ normalize→store              │
│  regional)   │              │                               │
└──────────────┴──────────────┴───────────────────────────────┘
Storage tier:
  • TSDB: VictoriaMetrics or ClickHouse (metrics, flows)
  • Graph: embedded (initially SQLite tables → later Apache AGE/
    Kuzu) for Device–Interface–Link–Path–Intent entities
  • Object store (S3-compatible/local FS): configs, pcaps, reports
  • Relational: PostgreSQL (inventory, alarms, audit) — SQLite for
    single-binary mode
```

### 3.2 Deployment modes (all first-class)

- **FR-PLAT-001 (P0) Single binary:** `nms serve` runs control plane + 1 collector + SQLite + embedded UI. Zero external services. This is today's repo behavior, kept forever as "lab mode."
- **FR-PLAT-002 (P1) Scale-out:** collectors are separate processes/hosts registering to core; Postgres + VictoriaMetrics/ClickHouse + NATS via config file or env vars.
- **FR-PLAT-003 (P2) HA:** active/standby core; collector fan-out to two cores; idempotent ingestion.
- **FR-PLAT-004 (P0) Air-gap:** no telemetry home, all features work offline; optional offline docs bundled.

---

## 4. Domain Modules & Functional Requirements

Priority key: P0 MVP · P1 fast-follow · P2 differentiator · P3 roadmap.

### 4.1 Discovery & Inventory (DISC)

- **FR-DISC-001 (P0)** ICMP sweep discovery: subnet seeds from local interfaces/routes + CLI/API-provided CIDRs; randomized order; token-bucket rate cap; configurable budget/deadline.
- **FR-DISC-002 (P0)** Persistent inventory entity `Device`: ip(s), mac(s), hostname (reverse-DNS + SNMP sysName when available), vendor/model/OS (SNMP sysDescr parsing), role (router/switch/wap/server/host/printer/IoT…), site, parent/dependency links, tags, lifecycle state (`new|active|absent|retired|maintenance`), first/last seen.
- **FR-DISC-003 (P0)** Interface inventory per managed device (ifIndex, name, speed, admin/oper status, MAC) via SNMP/LLDP.
- **FR-DISC-004 (P1)** Neighbor discovery: LLDP, CDP, ARP, FDB (bridge MIB), routing-table scraping → topology edges with source confidence.
- **FR-DISC-005 (P0)** Endpoint profiling: reverse DNS, OUI vendor DB (offline, updatable), TCP fingerprint ports, TTL heuristics → device class + confidence score.
- **FR-DISC-006 (P1)** Scheduled re-discovery with diff events (`device added`, `role changed`, `os upgraded`) into the event bus + audit log.
- **FR-DISC-007 (P0)** Lifecycle hygiene: absence-based retirement window (default 30 d, configurable); manual delete API/UI; retirement writes an audit record and keeps historical metrics/events queryable by IP.
- **FR-DISC-008 (P2)** Cloud/resource discovery adapters: VMware, Proxmox, Docker hosts, AWS/Azure/Azure-edge read-only inventory.
- **FR-DISC-009 (P3)** Wireless controller integration (Cisco WLC, UniFi, Aruba Central) for true AP↔client association.

### 4.2 Topology & Knowledge Graph (TOP)

- **FR-TOP-001 (P0)** Dependency graph: endpoint→WAP→gateway/router chains; used for root-cause suppression and impact analysis (already in current repo — keep semantics).
- **FR-TOP-002 (P1)** Unified graph model: nodes `Device, Interface, Site, Segment/VLAN, Path, Service, Intent`; edges `connects_to, member_of, depends_on, carries, verifies`. Versioned; every edge records source+confidence+last-verified timestamp.
- **FR-TOP-003 (P1)** Live map UI: zoomable canvas, physical (site/rack-lite) and logical (L3) layers, filter by state/class/site, time-travel scrubber (topology as-of T).
- **FR-TOP-004 (P2)** Automatic L2 path computation between any two endpoints from LLDP/FDB/STP data; show hop-by-hop with interface names/speeds.
- **FR-TOP-005 (P2)** Path Doctor (NetBrain parity): given A→B, compute intended path, actively verify each hop (ping/TTL, ifSpeed, errors), flag mismatches, offer remediation runbook.

### 4.3 Fault Management / Availability (FLT)

- **FR-FLT-001 (P0)** Check types: ICMP echo (primary), TCP connect (per-port service checks), HTTP(S) probe (status/latency/TLS expiry), DNS resolve, UDP echo (later). Per-device check bundles by class (e.g., printer: icmp+tcp9100; nas: icmp+tcp445).
- **FR-FLT-002 (P0)** Sweep scheduler: global rate limiter across collectors; per-class cadence (routers/waps 60 s default; endpoints 180–300 s at scale); jittered scheduling; deadline guard; progress introspection API (live % complete).
- **FR-FLT-003 (P0)** State machine per check: `up|down|unreachable|degraded|unknown` with confirm-down re-probes (N=1 default), flap damping (transitions/window threshold → suppress + flag), hysteresis timers.
- **FR-FLT-004 (P0)** Dependency suppression: if ancestor down ⇒ descendants become `unreachable`, inherit root-cause ID, impacted-count rolls up to root incident. Never page per-child.
- **FR-FLT-005 (P0)** Alarm/incident lifecycle: `open → acknowledged → resolved` (+`suppressed`); severity model `critical|major|warning|info`; dedupe key `(device, kind)`; auto-resolve on recovery; ack identity recorded; snooze/maintenance windows.
- **FR-FLT-006 (P1)** Root-cause engine beyond tree deps: correlate alarms within window using topology distance + timing order (e.g., BGP-down + interface-down same box ⇒ merge under interface cause); emit `probable_cause` field with explanation string.
- **FR-FLT-007 (P1)** Triggered diagnostics (NetBrain parity): every critical/major alarm can auto-run a bound diagnostic bundle (trace path, port scan, recent RTT chart, config diff, syslog tail) and attach results to the incident.
- **FR-FLT-008 (P2)** Synthetic transaction checks: multi-step HTTP login flows; scheduled end-to-end site probes (e.g., ping gateway + DNS + captive portal URL per site).
- **FR-FLT-009 (P0)** Notification fan-out: webhook (JSON schema below), e-mail SMTP, Slack/Teams webhook, generic exec hook; per-severity routing rules; retry queue with backoff (5 tries) and delivery ledger.

Webhook payload contract (v1, already implemented in current repo — freeze it):

```json
{ "type": "nms.event", "ts": "RFC3339",
  "event": { "id", "kind", "severity", "message", "details": {}, "created_ts" },
  "device": { "ip", "role", "site", "tags": [] } }
```

### 4.4 Performance Management (PRF)

- **FR-PRF-001 (P0)** Time-series storage of every probe result (rtt, loss) with hourly/daily rollups (probes, ups, rtt sum/min/max/p95, jitter) — implemented; generalize to metric registry.
- **FR-PRF-002 (P0)** Metric catalog: `icmp.rtt_ms, icmp.loss_pct, tcp.connect_ms, http.ttfb_ms, snmp.ifInOctets/ifOutOctets(ifHC*), cpu.load5, mem.used_pct, disk.used_pct, temp.celsius, wlan.client_count, bgp.session_up…`
- **FR-PRF-003 (P1)** SNMP v2c/v3 polling framework: bulk walks (GETBULK), per-vendor profiles (YAML), dynamic interface instance discovery; rate/delta computation server-side; counter-wrap safe.
- **FR-PRF-004 (P1)** Streaming telemetry ingest: gNMI dial-out (Subscribe ON_CHANGE + SAMPLE), Cisco MDT, OpenTelemetry metrics endpoint; treat as just another metric producer.
- **FR-PRF-005 (P0)** Thresholds: static warn/crit per metric+class; per-device override; maintenance-aware evaluation.
- **FR-PRF-006 (P2)** Adaptive baselines: rolling 14-day hour-of-week mean±k·σ; anomaly score emitted as its own metric; no cloud calls required (simple EWMA/quantile model first).
- **FR-PRF-007 (P2)** Forecasting: linear + seasonal-naive projection for capacity (link ≥70 % by date X); surfaced on link pages.
- **FR-PRF-008 (P1)** Golden signals dashboards per site/device (latency, traffic, errors, saturation).

### 4.5 Flow Analysis (FLW)

- **FR-FLW-001 (P1)** Ingest NetFlow v5/v9, IPFIX, sFlow v5; decode to common record; aggregate in ClickHouse.
- **FR-FLW-002 (P1)** Views: top talkers, site↔site matrix, protocol mix, new-destination alerts (first-seen src→dst pair), DSCP distribution.
- **FR-FLW-003 (P2)** Path overlay: draw flow volumes onto topology map edges.
- **FR-FLW-004 (P2)** Security hooks: Internet-exposed port report, beaconing heuristic (regular-interval outbound), blacklist hits.

### 4.6 Configuration Management (CFG)

- **FR-CFG-001 (P0)** Credential vault: encrypted-at-rest store (age/XChaCha20, master key from env/file), never logged, never returned by API (write-only).
- **FR-CFG-002 (P1)** Config backup: SSH/CLI + NETCONF/RESTCONF drivers; schedule + on-change trigger (via syslog commit messages where supported); store normalized text + raw; object-store layout `configs/<device>/<yyyy-mm-dd>/<hash>.cfg`.
- **FR-CFG-003 (P1)** Diff engine: line diff vs previous, vs golden, vs compliance rule; visual side-by-side in UI; change events correlated to alarm timeline ("what changed before it broke").
- **FR-CFG-004 (P2)** Compliance packs: YAML rules (e.g., `no telnet lines`, `ntp servers == [pool]`, `snmp community != public`); pass/fail per device; drift alerting; export CSV.
- **FR-CFG-005 (P2)** Golden config templates + drift detection (Jinja2-style rendering with per-device variables).
- **FR-CFG-006 (P3)** Guarded push: generated command set → human approval → apply via driver → post-check verification → rollback script ready. Everything audited.

### 4.7 Path Analysis & Diagnostics (PTH)

- **FR-PTH-001 (P0)** On-demand ICMP traceroute from collector to target with inventory-enriched hops (role/site/class) — implemented in current repo; move behind API versioning.
- **FR-PTH-002 (P1)** Bidirectional + scheduled path tests between site pairs; store history; alert on path change (different hop set).
- **FR-PTH-003 (P1)** Diagnostic bundles ("runbooks lite"): named YAML lists of steps (ping burst, trace, tcp-scan, config-diff, show-commands) runnable ad-hoc, on alarm, or scheduled; results attached to incident timeline.
- **FR-PTH-004 (P2)** MPLS/overlay awareness: VRF-aware traceroute, VXLAN/EVPN topology hints (from LLDP + config parse).

### 4.8 Intent-Based Verification (INT)

- **FR-INT-001 (P1)** Intent objects: declarative assertions evaluated against live data:
  ```yaml
  - id: branch-wan-redundancy
    scope: site.role == branch
    assert: count(device[role=router].interfaces[role=wan, oper=up]) >= 2
    severity: major
  ```
- **FR-INT-002 (P1)** Continuous evaluation engine (every poll cycle / on topology change); violations create alarms referencing the intent ID; compliance % per site over time.
- **FR-INT-003 (P2)** Intent templates library shipped with product (redundancy, NTP, DNS, MTU consistency, unused ports shutdown, firmware currency).
- **FR-INT-004 (P3)** Natural-language → draft intent (LLM assist, local model option), human-approved before activation.

### 4.9 Automation & Runbooks (AUT)

- **FR-AUT-001 (P1)** Runbook format: YAML DAG of steps; step types = diagnostic (read-only), notification, HTTP call, SSH command-list (requires vault credential + approval policy), wait/condition.
- **FR-AUT-002 (P1)** Execution engine with dry-run mode, timeout/kill, full stdout/stderr capture to object store, audit trail entry per step.
- **FR-AUT-003 (P2)** Closed-loop remediation: alarm matches rule → runbook executes → verification step must pass → else escalate to human. Guardrails: max concurrent executions, blast-radius tag (device/site), approval gates for write actions.
- **FR-AUT-004 (P2)** No-code builder UI generating the same YAML (Git-friendly; round-trip editing).
- **FR-AUT-005 (P3)** Agentic mode: LLM planner proposes diagnosis steps from knowledge-graph context; executes only read-only steps automatically; writes require approval. All agent actions logged as structured traces.

### 4.10 Events, Alarms, Incidents & Audit (EVT)

- **FR-EVT-001 (P0)** Single append-only event log (JSON lines → table) consumed by alarms, reports, and integrations. Kinds enumerated in §11.
- **FR-EVT-002 (P0)** Incident = grouped open alarms with same root-cause ID; timeline view merges: state changes, related metric spikes, config diffs, diagnostics, comments.
- **FR-EVT-003 (P0)** Audit log for every mutation (who/what/when/target/details JSON); actor types: `web:<user>|token:<id>|cli|system|runbook:<name>`; exportable; tamper-evident hash chain (P2).
- **FR-EVT-004 (P1)** Maintenance windows: one-off + recurring schedules, per device/site/tag; suppressed alarms still recorded with `suppressed=true`.
- **FR-EVT-005 (P2)** On-call: escalation policies (ack timeout → next), calendar import (ICS), PagerDuty-compatible Events API v2 *emulation* so existing tooling works unchanged.

### 4.11 Reporting & Business View (REP)

- **FR-REP-001 (P0)** Availability % per site/device/window (24h/7d/30d/custom), MTTR/MTTA, incident counts, worst-offender tables; HTML + CSV — implemented; add PDF via headless print CSS (no heavy deps).
- **FR-REP-002 (P1)** SLA definitions: target uptime % per service/site group; monthly attainment with error-budget burn-down chart.
- **FR-REP-003 (P1)** Scheduled delivery: cron-defined reports e-mailed/webhook-posted/stored (daily availability snapshot exists — extend).
- **FR-REP-004 (P2)** Capacity report: top-N interfaces trending toward saturation with forecast dates.
- **FR-REP-005 (P2)** Executive digest: weekly summary email (incidents, changes, SLA, capacity flags).

### 4.12 Console UX (UX)

- **FR-UX-001 (P0)** Pages: Map, Console(dashboard), Devices(+detail), Events, Reports, Audit, Settings — implemented; keep URLs stable.
- **FR-UX-002 (P0)** Map: live in-place refresh (no page reloads), progress bar for jobs, node detail drawer, dependency highlighting (click router → descendants dim/highlight).
- **FR-UX-003 (P0)** Device page: state/uptime/RTT sparkline/timeline, diagnostics (burst ping score, trace path, port/service list incl. expected-vs-open), actions (ack, maintenance, site assign, remove), impact list, config diffs (when CFG on).
- **FR-UX-004 (P1)** Global search: IP/hostname/MAC/tag/site → jump anywhere (⌘K palette).
- **FR-UX-005 (P1)** Triage wizard: from any critical alarm, one screen showing root-cause candidate, impacted list, map excerpt, last changes, and "Run diagnostics" — the NetBrain "one-click diagnosis" experience.
- **FR-UX-006 (P2)** Saved views/dashboards per user; embeddable panels (iframe token).
- **FR-UX-007 (P0)** Accessibility: keyboard navigable tables/dialogs, WCAG AA contrast on dark theme.

### 4.13 Integrations (INTG)

- **FR-INTG-001 (P0)** Outbound webhooks + inbound webhook receiver (generic → event pipeline).
- **FR-INTG-001a (P0)** ServiceNow: incident creation on critical/major (mapping table: severity→impact/urgency, site→location/CMDB CI lookup by IP or serial), updates on state change, resolve on close; bi-directional sync of ack state; config-driven, test button, delivery ledger. *(Primary enterprise target.)*
- **FR-INTG-002 (P1)** ChatOps: Slack/Teams notifications; slash-command `/nms status <ip>`, `/nms diag <ip>` (runs read-only bundle).
- **FR-INTG-003 (P1)** Prometheus exposition of key gauges (`nms_devices_up`, `alarms_open{severity}`) + Alertmanager-compatible webhook receiver.
- **FR-INTG-004 (P2)** Grafana datasource plugin (or native Prometheus/ClickHouse recipes documented).
- **FR-INTG-005 (P2)** Ticketing adapters beyond ServiceNow: Jira Service Management, Freshservice, OTRS/Znuny.
- **FR-INTG-006 (P1)** Full OpenAPI 3 spec served at `/api/openapi.json`; generated clients (TS, Python, Go) published per release.

### 4.14 Platform, Security & Multi-tenancy (PLAT)

- **FR-PLAT-005 (P0)** Auth modes: `open` (default, loopback-oriented lab/home use — current behavior) and `hardened` (local users w/ Argon2id hashes, session cookies, API tokens, RBAC roles `viewer|operator|admin|automation`). Mode selected in settings; hardened enforced automatically when binding non-loopback.
- **FR-PLAT-006 (P1)** TLS termination guidance + built-in Let's Encrypt option; HSTS in hardened mode.
- **FR-PLAT-007 (P2)** Multi-tenancy: tenant-scoped inventory/alarms/reports; collector tags pin devices to tenants; cross-tenant admin.
- **FR-PLAT-008 (P1)** Backup/restore: single archive command (config + DB dumps + object store manifest); documented RPO/RTO.
- **FR-PLAT-009 (P0)** Upgrades: forward-compatible migrations, rollback-safe (never destructive without backup marker); `nms migrate status`.

---

## 5. Protocol Support Matrix

| Protocol | Use | Priority |
|---|---|---|
| ICMP echo/traceroute | reachability, latency, path | P0 (done) |
| ARP / FDB | L2 mapping | P1 |
| SNMPv2c/v3 (GETBULK, traps/informs) | metrics, inventory, alarms | P1 (v3 authPriv required in hardened mode) |
| LLDP / CDP | neighbor/topology | P1 |
| SSH/CLI (vendor drivers) | config backup, diagnostics | P1 |
| NETCONF / RESTCONF (+YANG) | config, state, telemetry-capable devices | P2 |
| gNMI / MDT | streaming telemetry | P2 |
| NetFlow v5/v9, IPFIX, sFlow | traffic analytics | P1/P2 |
| Syslog (RFC 5424) | event enrichment, on-change triggers | P1 |
| HTTP(S) probes, DNS | synthetic service checks | P0/P1 |
| TWAMP/OWAMP | advanced latency SLAs | P3 |
| OpenTelemetry (OTLP) | metrics ingest bridge | P2 |
| DHCP snooping/IPAM reads | endpoint tracking | P3 |

---

## 6. Data Architecture

- **Metrics:** table-per-kind wide schema in VictoriaMetrics/ClickHouse: labels `{tenant, site, device_ip, device_id, iface, class}`; raw resolution 60 s × 36 h → 5 m × 14 d → 1 h × 400 d (config keys already exist; mirror defaults).
- **Events/alarms/audit:** relational (Postgres prod / SQLite lab), append-only event log + materialized `alarms_open` view.
- **Graph:** start with normalized tables + recursive CTEs (sufficient to 50 k nodes); swap-in embedded graph engine behind `TopologyStore` trait when queries need variable-length paths.
- **Object store:** local FS with S3 adapter trait; content-addressed blobs (sha256) for configs/pcaps/reports.
- **Schema governance:** every bus message and API object has a versioned schema (`schema.v1.*`); breaking changes bump topic/schema name — never mutate in place.
- **Idempotency:** producers attach `(source, seq)` dedupe keys; storage upserts.

## 7. Scale & Performance NFRs (reference estate: 850 sites / 3 k routers / 50 k endpoints)

| ID | Requirement |
|---|---|
| NFR-01 | Full 50 k-target ICMP sweep ≤ 90 s at ≤ 5 000 pps/collector; default steady-state ≤ 25 % of that budget. |
| NFR-02 | Detection-to-alarm ≤ 120 s for down transitions (incl. confirm probe). |
| NFR-03 | Alarm/notification dispatch latency ≤ 5 s after decision (p99). |
| NFR-04 | Console dashboard p95 server render ≤ 300 ms; device page ≤ 500 ms @ 50 k devices. |
| NFR-05 | Ingest sustain 100 k metrics/s single core-node (VictoriaMetrics-class) without loss. |
| NFR-06 | Collector memory ≤ 512 MB RSS at 50 k targets (single binary lab mode ≤ 128 MB). |
| NFR-07 | Storage ≤ 250 GB/year for reference estate at default retention tiers. |
| NFR-08 | Core restart recovery ≤ 30 s; collectors buffer ≥ 15 min of results offline (spool-on-disk). |
| NFR-09 | Zero data loss on graceful shutdown; at-least-once with dedupe everywhere. |
| NFR-10 | All long jobs expose progress (0–100 %) via API within 1 s of start. |

## 8. Quality Attributes

- **Reliability:** crash-only design; every component restart-safe; WAL/journal everything.
- **Operability:** single-command install/upgrade/backup; health endpoint `/api/health` with component states; structured logs (JSON) with trace IDs.
- **Testability:** unit + integration suites in CI; protocol fixtures (pcap/SNMP walks) replayable; chaos job kills random components nightly in dev stack.
- **Portability:** Linux (glibc+musl static), Windows (collector + lab core), macOS (lab). ARM64 builds.
- **i18n/l10n:** UTF-8 everywhere; date/number formatting locale-aware (P2).

## 9. Technology Choices (recommended, arguable per module)

| Layer | Choice | Why |
|---|---|---|
| Collector/engine | **Rust** (existing codebase seed) | perf + safety, single static binary, low-memory sweep at scale |
| Control plane API | Rust (axum) initially; isolate behind OpenAPI | one-language velocity now; split later along trait seams |
| Flow/streaming workers | Go or Rust | ecosystem libs (goflow/gNMI) mature |
| Web console | TypeScript + SvelteKit (or React) | fast, small bundle; API-first means replaceable |
| Metrics store | VictoriaMetrics (default), ClickHouse (flows/aggregation) | proven at our scale, OSS licenses OK |
| Bus | NATS JetStream | lightweight, exactly-once-ish, clustering |
| Relational | PostgreSQL; SQLite embedded mode | same SQL, two runtimes |
| Graph | SQL CTEs → Kuzu/Apache AGE behind trait | defer until needed |
| Plugin sandbox | WASM (wasmtime) | safe third-party check/alert/normalize plugins |
| ML/AIOps | Python sidecar (optional) exposing gRPC; local models (ONNX runtime) | keep core dependency-free |

**License:** Apache-2.0 (core). Keep vendor drivers/plugins loadable under other licenses; never link GPL into core binaries.

**OSS to study/borrow ideas (not code unless license-compatible):** LibreNMS (poller layout, device groups), Zabbix (item/trigger model), Observium (portability of vendor profiles), Oxidized/RANCID (config backup UX), Netdisco (ARP/FDB topology), ntopng (flow views), Telegraf (input plugin surface), Prometheus/Alertmanager (alert semantics), Grafana (dashboard ergonomics), NetBrain (context model, runbooks, Path Doctor concept), Kentik (flow+synthetic fusion).

---

## 10. Event & Alarm Taxonomy (canonical kinds)

```
availability: device_down, device_up, unreachable_set/cleared,
              service_down(<port>), http_check_failed
performance : latency_warn, latency_crit, loss_warn, jitter_warn,
              utilization_warn(≥80%), utilization_crit(≥95%)
topology    : neighbor_added/removed, path_changed, site_isolated,
              redundancy_lost
config      : config_changed, config_diff_failed, compliance_violation,
              golden_drift
inventory   : device_added, device_removed, device_retired,
              role_changed, os_changed
system      : collector_offline, poll_backlog, storage_pressure,
              webhook_delivery_failed, auth_failure
intelligence: anomaly_score_high, forecast_breach, intent_violation
```

Severity mapping default: `critical` = total outage/root; `major` = redundant-path loss, intent violation on WAN; `warning` = degraded/perf; `info` = informational/auto-closed.

## 11. Repository / Module Layout (target monorepo)

```
nms-ng/
  crates/
    core-api/        # axum REST+gRPC, auth, settings
    engine/          # scheduler, sweeps, state machine, RCA (today's ops/check/engine/db)
    proto/           # schema.v1 protobufs + JSON schemas
    collector-snmp/ collector-flow/ collector-config/(ssh/netconf)
    stores/{sqlite,pg,victoria,ch,objfs,s3}/
    ui/              # SvelteKit app (built → embedded assets)
    cli/             # today's CLI verbs, thin over crates
  deploy/ (compose, k8s helm, systemd units)
  docs/ (this PRD, ADRs, api/, runbooks/)
  fixtures/ (snmp walks, pcap samples, device sims)
```

Migration note: current repo modules map — `db.rs→stores/sqlite`, `ops.rs/check.rs/engine.rs/discover.rs→engine`, `server.rs/ui.rs/report.rs→core-api+ui(v0)`, `jobs.rs→engine/jobs`, `profile.rs/diag.rs/trace.rs→engine/diagnostics`. Keep CLI verb compatibility (`discover|check|monitor|serve|map|routes|ifaces|ping`).

---

## 12. Acceptance Criteria (samples — every FR gets similar)

- AC-FLT-004: Simulate router failure with 40 downstream endpoints ⇒ exactly **one** `critical` incident with `details.impacted == 40`; zero child down-notifications sent; children shown `unreachable` within one cycle.
- AC-INTG-SNOW: Critical alarm creates ServiceNow incident within 30 s carrying correct CI mapping; acking in NMS updates SNOW worknote; resolving closes ticket; webhook outage queues and delivers after recovery with `tries` visible.
- AC-NFR-01: 50 000 synthetic targets (loopback ranges) swept in ≤ 90 s with progress API reporting monotonic %.
- AC-CFG-002: Cisco IOS-XE + Aruba AOS-CX simulators: nightly backup stored, change detected within 5 min, diff rendered, audit entries present.
- AC-INT-001: Removing a WAN uplink on a branch sim fires `intent_violation(redundancy)` within one evaluation cycle; dashboard site card shows red intent badge.

## 13. Milestones

| M | Theme | Contents |
|---|---|---|
| **M0 (done)** | Seed | ICMP discover/check/monitor/map/console, SQLite ops store, events/audit/outbound webhooks, profiling, diagnostics, trace, removal/retirement (current repo ≈ v0.2) |
| **M1** | Hardening | Split crates per §11; OpenAPI spec; auth modes; spool-on-disk collectors; health endpoint; fixture-based tests; ServiceNow integration GA |
| **M2 = MVP** | StableNet core parity | + SNMP v2c/v3 polling & interface inventory; LLDP/CDP topology; config backup+diff (SSH); scheduled reports PDF; triage wizard; scale test passing AC-NFR-01/02 |
| **M3** | NetBrain context | Graph-backed topology; L2 path computation; diagnostic bundles/runbooks (read-only); intents v1 + violation alarms; map time-travel |
| **M4** | Flows + streaming | IPFIX/sFlow ingest & views; gNMI ingest; utilization golden signals; capacity forecasts |
| **M5** | Automation + AI | Write-guarded remediation; no-code runbook builder; baselines/anomaly scoring; NL assistant (local-model option); multi-tenant |
| **M6** | Ecosystem | WASM plugin SDK; Grafana recipe/plugin; HA mode; TWAMP; wireless controllers |

## 14. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Scope explosion (two products' feature sets) | Milestone gating; P0 lists frozen; PRD changes via ADR |
| Vendor CLI fragmentation (config mgmt) | Start with 3 driver families (IOS-XE, AOS-CX, Fortinet); simulator fixtures in CI |
| Single-mutex SQLite habits block scale | Trait seams (`InventoryStore`, `MetricsStore`) defined at M1; PG/VM implementations behind them |
| Alarm storms at 850 sites | Dedupe keys + dependency suppression + per-site rate ceilings + storm-mode (auto-suppress info/warning) |
| LLM hype trap | Agent features are P3 and gated behind read-only defaults; deterministic engines deliver value first |
| License contamination | Apache-2.0 core; dependency license CI gate |

## 15. Glossary

**RCA** root-cause analysis · **MTTR/MTTA** mean time to restore/acknowledge · **SLA/SLO/SLI** service level agreement/objective/indicator · **Intent** declarative assertion of desired network state · **Golden config** approved template · **DVT/DataView** NetBrain terms for contextual data/diagnostic views · **Runbook** executable diagnostic/remediation procedure · **IPFIX/sFlow** flow telemetry · **gNMI** gRPC network management interface · **TWAMP** two-way active measurement protocol.

---

*End of PRD v1.0. Implementation questions resolve in favor of: correctness under scale > simplicity > features.*
