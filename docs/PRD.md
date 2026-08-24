# PRD — Open-Source Network Management Platform ("nms-ng")

**Version:** 1.1 · **Status:** Approved for build · **Audience:** AI programmers / implementers
**Goal:** Clean-sheet rebuild of *Infosim StableNet* (unified fault/performance/config/inventory management) and *NetBrain* (network context model: Device–Topology–Path–Intent, runbooks, triggered diagnostics) as one **free, open-source platform**, better than both.
**Reference deployment target:** 850 sites · ~3,000 routers · ~50,000 endpoints · detection-to-notification ≤ 2 minutes (Enterprise tier; see §7 scale tiers).

> **How to read this document.** Every requirement has an ID (`FR-<DOMAIN>-<nnn>`), a priority
> (**P0** = MVP must-have, **P1** = next, **P2** = differentiator, **P3** = later), and is written to be
> directly implementable and testable. "MVP" = Milestone M2 (§13). When this PRD conflicts with
> marketing language of the reference products, this PRD wins.

> **v1.1 changelog.** Incorporates `docs/research/2026-08-deep-research-report.md` per
> ADR-0001: dual-track collector plane (Rust seed + Go adapters), Kafka/PostgreSQL/ClickHouse
> scale-out defaults (SQLite+NATS stay as lab mode), three design scale tiers (§7), new domains
> §4.15–4.20 (capture, security, cloud/K8s/mesh/microseg/zero-trust, edge, migration,
> governance), expanded protocol matrix §5, canonical event envelope & adapter contract §6.1–6.2,
> KPIs §16, testing program §17, migration pipeline §18, staffing/effort §19, governance §20,
> collection strategy principles §21.

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
│  Enterprise/Large tiers: Kafka (durable, replayable)        │
│  Lab mode: in-process channels / embedded NATS              │
│  Topics: metrics, events, states, topology, configs,        │
│  flows, traces, captures                                    │
├──────────────┬──────────────┬───────────────────────────────┤
│ Collector(s) │ Flow Collector│ Ingest Workers               │
│ Rust seed    │ Go adapters   │ normalize→enrich→dedupe      │
│ (ICMP/diag)+ │ (GoFlow2/     │ →store                       │
│ Go protocol  │  pmacct)      │                              │
│ adapters     │              │                               │
└──────────────┴──────────────┴───────────────────────────────┘
Storage tier:
  • Relational: PostgreSQL (inventory, alarms, audit, policy)
    — SQLite for single-binary lab mode
  • Analytics: ClickHouse (metrics, flows, events; materialized
    rollups + TTL retention policies)
  • Graph: temporal model in PostgreSQL first (recursive CTEs);
    dedicated engine only if profiling demands it
  • Object store (S3-compatible/local FS): configs, pcaps,
    reports, model artifacts
  • Optional OpenSearch for full-text/log workloads only where
    justified; never a default sink for metrics/flows
```

Separation of concerns is fixed: **collection → transport → normalization →
state/modeling → analytics → action → presentation**. No collector writes its
own bespoke schema; everything crosses the bus in the canonical envelope (§6.1).

### 3.1.1 Monitoring vs observability — "progressively deep" collection

Monitoring answers *known indicators vs known thresholds*; observability lets an
operator **explain** an unexpected condition by joining telemetry with topology,
configuration, paths, changes, dependencies and identity. The core
differentiator is therefore a **temporal network knowledge graph plus an
evidence-based diagnostic engine**: every entity, relationship, state and
conclusion carries provenance (`source`, `observed_at`, `confidence`) and time
validity. An incident must be explainable as a chain:

`service degradation → path changed → BGP next-hop changed → config commit → policy difference → affected links/interfaces → corroborating latency/loss/flow evidence`

Collection is **progressively deep** — cheap signals run continuously, expensive
collection activates on evidence:

`counters/state continuously → sampled/aggregated flows continuously → transaction metadata selectively → header ring-buffers at sensitive points → bounded full-packet capture only during investigations`

Triggered escalation closes the loop (SpiderMon-pattern): symptom → RCA engine
queries the graph for probable scope → targeted high-rate polling / gNMI
subscription / flow query / optional bounded capture → evidence with provenance
attaches to the incident → ranked hypotheses with supporting AND contradicting
evidence go to the operator.

### 3.2 Deployment modes (all first-class)

- **FR-PLAT-001 (P0) Single binary:** `nms serve` runs control plane + 1 collector + SQLite + embedded UI. Zero external services. This is today's repo behavior, kept forever as "lab mode."
- **FR-PLAT-002 (P1) Scale-out:** collectors are separate processes/hosts registering to core; PostgreSQL + ClickHouse + Kafka via config file or env vars (ADR-0001).
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

### 4.15 Packet Capture (CAP)

- **FR-CAP-001 (P1)** Bounded on-demand capture: ring buffers, BPF filters, triggered by alarm/runbook/manual; headers-only default; hard bandwidth/disk quotas; PCAP/PCAPNG export; fails safely under overload.
- **FR-CAP-002 (P2)** Distributed capture agents at collectors/edge; centralized job orchestration with per-agent placement.
- **FR-CAP-003 (P1)** Capture privacy modes: `metadata-only → L2-L4 headers → app metadata → full payload`, progressively privileged; full payload never a default retention tier; retention/hold policy + audit per capture. Zeek/Suricata enrichment adapters consume live traffic or stored PCAP.

### 4.16 Security Monitoring (SEC)

- **FR-SEC-001 (P2)** Ingest IDS/firewall/auth findings (Zeek logs, Suricata EVE, firewall syslog) into the event pipeline; correlate with flows, topology and identity.
- **FR-SEC-002 (P2)** East-west analytics: observed conversation matrices, segmentation-violation detection (observed vs allowed policy), first-seen destination alerts.
- **FR-SEC-003 (P3)** Zero-trust posture reporting: identity/policy coverage of privileged paths (NIST SP 800-207 alignment); advisory only — no automatic blocking.

### 4.17 Cloud, Kubernetes & Service Mesh (CLD)

- **FR-CLD-001 (P2)** Cloud inventory/routes/security ingestion: AWS VPC/TGW (+ flow logs), Azure VNet/VNet flow logs, GCP VPC Flow Logs; read-only IAM; account/subscription/project discovery; incremental sync with API-throttle awareness.
- **FR-CLD-002 (P2)** Kubernetes networking: watch nodes/pods/services/EndpointSlices/NetworkPolicies via K8s API (least-privilege SA); CNI state; optional Hubble/eBPF flow visibility; Secrets never ingested.
- **FR-CLD-003 (P3)** Service mesh: Istio/Envoy telemetry for service graph, mTLS identity, L7 latency/retries; correlate L7 signals with L3 path/loss evidence.
- **FR-CLD-004 (P3)** Microsegmentation analytics: normalized policy model, observed-vs-allowed matrices, reachability simulation, overbroad-policy findings — advisory mode only.
- **FR-CLD-005 (P2)** Hybrid stitching: VPN/SD-WAN/transit/tunnel/overlay edges join physical, cloud and K8s domains in one graph with explicit confidence where correlation is inferred.

### 4.18 Edge Collectors (EDGE)

- **FR-EDGE-001 (P2)** Store-and-forward edge collector: local probes continue during WAN loss; compressed spool; backfill on reconnect with dedupe; bounded local storage; remote upgrade/policy.
- **FR-EDGE-002 (P3)** MQTT 5 transport option for constrained sites; mutual identity; signed updates.

### 4.19 Legacy Migration Tooling (MIG)

- **FR-MIG-001 (P2)** Import/export adapters for NetBrain/NMSaaS-class exports: inventory ("inventory-of-inventory"), maps→`MapView`, intents/diagnostics→`Intent+Workflow`, golden paths→`Baseline/PathSnapshot`, integrations→connectors; every record tagged `converted|partially_converted|manual_review_required`; original exports preserved as immutable evidence.
- **FR-MIG-002 (P2)** Dual-run support: parallel observation before parallel action; avoid double-polling sensitive devices (designate primary heavy collector, ingest the other's outputs); cutover acceptance = topology/inventory/metric/event/config-backup parity checks plus HA/restore exercise. Automation cutover lags observability: read-only diagnostics → lab prechecks → production shadow → approved low-risk writes.

### 4.20 Governance & Community (GOV)

- **FR-GOV-001 (P0)** DCO 1.1 for all contributions; public ADR/RFC process (this repo's `docs/adr/`).
- **FR-GOV-002 (P3)** TSC model: architecture maintainers, subsystem maintainers, security response team, release managers, vendor SIGs; merit-based election w/ term limits as ecosystem matures.
- **FR-GOV-003 (P0)** No feature-gated proprietary edition: HA, RBAC, multi-tenancy, security and APIs always ship in the open core.

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
| BMP | BGP session/RIB visibility | P1 |
| BGP-LS | link-state/TE topology feed | P2 |
| PCEP/PCEPS | computed/controlled TE paths | P3 |
| MQTT 5 | constrained edge/IoT telemetry | P2 |
| eBPF / Hubble | workload flow visibility, microsegmentation evidence | P1/P2 |
| Kubernetes API + CNI | workloads, services, NetworkPolicy watch | P1 |
| Cloud APIs + flow logs (AWS VPC/TGW, Azure VNet, GCP) | cloud inventory/routes/traffic | P1 |
| Vendor REST APIs (controllers, Meraki-style) | inventory/state/events | P0 |

---

## 6. Data Architecture

- **Metrics:** ClickHouse wide tables: labels `{tenant, site, device_ip, device_id, iface, class}`; raw resolution 60 s × 36 h → 5 m × 14 d → 1 h × 400 d (config keys already exist; mirror defaults). **Rollups must retain min/max/sum/count and p95/p99 (or mergeable quantile state), not averages** — a 1-minute saturation spike must survive a 5-minute rollup.
- **Events/alarms/audit:** relational (Postgres prod / SQLite lab), append-only event log + materialized `alarms_open` view.
- **Graph:** temporal model in PostgreSQL first — every entity/relationship carries provenance fields `source`, `observed_at`, `valid_from`, `valid_to`, `confidence`; recursive CTEs for paths; swap-in dedicated engine behind `TopologyStore` trait only if profiling demands.
- **Object store:** local FS with S3 adapter trait; content-addressed blobs (sha256) for configs/pcaps/reports.
- **Schema governance:** every bus message and API object has a versioned schema (`schema.v1.*`); breaking changes bump topic/schema name — never mutate in place. Keep raw/minimally-normalized streams for a bounded window so reprocessing after schema evolution is possible.
- **Idempotency:** producers attach `(source, seq)` dedupe keys; storage upserts. Every record distinguishes `observed_at` from `ingested_at`; collectors report clock-sync health so RCA can reason over skew windows.
- **Cardinality is a budget:** every telemetry schema declares estimated cardinality, allowed dimensions, retention class and aggregation behavior; high-cardinality facts live in analytical tables, never as per-combination series.

### 6.1 Canonical event envelope (v1)

Semantic model shared across all transports; wire format may be Protobuf where JSON overhead is unacceptable.

```json
{
  "schema": "network.telemetry.v1",
  "tenant_id": "t-123",
  "source": { "collector_id": "col-17", "protocol": "gnmi", "device_id": "dev-456" },
  "observed_at": "2026-08-24T14:03:17.123456Z",
  "ingested_at": "2026-08-24T14:03:17.231991Z",
  "sequence": 9817261,
  "kind": "interface.counter",
  "entity": { "type": "interface", "id": "if-789" },
  "payload": { "name": "in_octets", "value": 19482736192, "unit": "bytes" },
  "quality": { "counter_reset": false, "confidence": 1.0 }
}
```

### 6.2 Device adapter contract

Adapters expose **capabilities**, not vendor methods. Every method returns
canonical structures plus `raw_source` references and a capability declaration;
a device that cannot do atomic config replacement must say so.

```
get_inventory() get_interfaces() get_neighbors() get_routes()
get_bgp_state() get_config() get_environment()
subscribe(paths)
validate_config(candidate) diff_config(candidate)
stage_config(candidate) commit() rollback()
run_command(read_only_command)
```

## 7. Scale & Performance NFRs

**Design/test tiers** (PRD targets, not measured promises):

| Tier | Planning target | Deployment |
|---|---|---|
| Community | ≤1 k devices · ≤50 k interfaces · ~10 k samples/s | single server / small HA |
| Enterprise | ≈10 k devices · ≈500 k interfaces · ~100 k samples/s + flows | distributed on-prem/private cloud |
| Large/MSP | ≈100 k devices · millions of interfaces · ~1 M samples/s | sharded multi-cluster |

The program's named reference estate (850 sites / 3 k routers / 50 k endpoints)
sits in the Enterprise tier.

| ID | Requirement |
|---|---|
| NFR-01 | Full 50 k-target ICMP sweep ≤ 90 s at ≤ 5 000 pps/collector; default steady-state ≤ 25 % of that budget. |
| NFR-02 | Detection-to-alarm ≤ 120 s for down transitions (incl. confirm probe). |
| NFR-03 | Alarm/notification dispatch latency ≤ 5 s after decision (p99). |
| NFR-04 | Console dashboard p95 server render ≤ 300 ms; device page ≤ 500 ms @ 50 k devices. |
| NFR-05 | Ingest sustain 100 k metrics/s per core-node via ClickHouse pipeline without loss. |
| NFR-06 | Collector memory ≤ 512 MB RSS at 50 k targets (single binary lab mode ≤ 128 MB). |
| NFR-07 | Storage ≤ 250 GB/year for reference estate at default retention tiers. |
| NFR-08 | Core restart recovery ≤ 30 s; collectors buffer ≥ 15 min of results offline (spool-on-disk); edge collectors store-and-forward with bounded local storage. |
| NFR-09 | Zero data loss on graceful shutdown; at-least-once with dedupe everywhere. |
| NFR-10 | All long jobs expose progress (0–100 %) via API within 1 s of start. |
| NFR-11 | Backpressure is a feature: bounded queues + priority shedding during storms — order: control/audit & config transactions > alerts/state transitions > high-priority streaming state > ordinary counters > raw flows > optional deep enrichment. |
| NFR-12 | HA targets (same-region): RPO < 1 min critical state, RTO < 15 min; DR default RPO ≤ 15 min / RTO ≤ 4 h, policy-configurable. |

## 8. Quality Attributes

- **Reliability:** crash-only design; every component restart-safe; WAL/journal everything.
- **Operability:** single-command install/upgrade/backup; health endpoint `/api/health` with component states; structured logs (JSON) with trace IDs.
- **Testability:** unit + integration suites in CI; protocol fixtures (pcap/SNMP walks) replayable; chaos job kills random components nightly in dev stack.
- **Portability:** Linux (glibc+musl static), Windows (collector + lab core), macOS (lab). ARM64 builds.
- **i18n/l10n:** UTF-8 everywhere; date/number formatting locale-aware (P2).

## 9. Technology Choices (v1.1 — dual-track per ADR-0001)

| Layer | Default | Alternatives / reuse | Trade-off |
|---|---|---|---|
| Sweep/diagnostic engine (seed) | **Rust** (existing codebase) | — | perf + safety, single static binary lab mode |
| Protocol adapters (SNMP, gNMI, config drivers) | **Go** preferred for new adapters | Rust where packet-level perf dominates; Python for slow adapters | Go networking ecosystem velocity; per-component ADR decides |
| gNMI/OpenConfig | **gNMIc** reuse/integration initially | native client later | Apache-2.0, Capabilities/Get/Set/Subscribe |
| CLI/config automation | **scrapli + Nornir/NAPALM** adapters | Ansible collections | unified multivendor methods; capability modeling |
| Flow collector | **GoFlow2**; pmacct where richer integration needed | OpenNMS telemetry components | lean high-volume NetFlow/IPFIX/sFlow normalization |
| Packet/NDR enrichment | **Zeek + Suricata** adapters | eBPF/XDP custom agents | transaction metadata + IDS without building an IDS |
| Network verification | **Batfish** service | custom path engine later | modeled reachability/diff vs observed state |
| Source-of-truth interop | canonical model + **NetBox import/sync** | Nautobot | optional SoT without forcing one inventory model |
| Config archive | native object-store snapshots + diffs; optional **Oxidized** bridge | RANCID-style | broad NOS coverage early |
| Control plane API | Rust (axum) now; isolate behind OpenAPI | split later along trait seams | one-language velocity today |
| Web console | TypeScript + SvelteKit (or React) | Grafana embeds for ad-hoc charts | incident/topology UX stays native |
| Metrics/flows analytics | **ClickHouse** | Prometheus+Thanos for Prometheus-semantics needs | materialized rollups + TTL fit retention tiers |
| Bus | **Kafka** (Enterprise/Large); in-process/NATS (lab) | Redpanda-compatible ops | durable replay enables reprocessing after schema evolution |
| Relational | PostgreSQL; SQLite embedded mode | — | recursive SQL, row-level security, JSONB |
| Full-text search | Optional OpenSearch | ClickHouse text filtering | only when a workload justifies another cluster |
| Identity | Keycloak-compatible OIDC/OAuth2/SAML | direct enterprise IdP | federation + MFA out of scope of core |
| Authorization policy | app RBAC + **OPA** for ABAC | native-only | policy-as-code for network-specific decisions |
| Secrets | **OpenBao** references | cloud KMS/vault | secrets never in configs/logs/prompt payloads |
| Self-observability | OpenTelemetry Collector + Prometheus | — | vendor-neutral pipeline, standard metrics model |
| Plugin sandbox | out-of-process gRPC contract first | WASM (wasmtime) for constrained extensions | isolation + language freedom over in-proc risk |
| ML/AIOps | Python sidecar (gRPC), interpretable stats first | ONNX local models | evidence-grounded AI; graceful no-LLM mode |

**License:** Apache-2.0 core + DCO 1.1 contributions; SPDX metadata and dependency-license CI gate; never link GPL into core binaries. HA/RBAC/multi-tenancy/APIs are never proprietary editions.

**Compatibility targets & comparative suites:** OpenNMS/LibreNMS/Zabbix (polling/alarm edge cases as test baselines), NetBox (SoT model), Oxidized, SuzieQ (state normalization precedent), Batfish (verification), NetBrain (context model, Path Doctor), Kentik (flow+synthetic fusion). Each supported vendor/NOS release gets a machine-readable compatibility matrix: `discover / poll / inventory / topology / config-read / config-write / gNMI / flows / routing / tested-version / last-certified`.

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
- AC-CAP-001: Triggered capture during a simulated flap stores headers-only PCAP under quota with audit record and privacy-mode metadata; payload capture requires elevated role.
- AC-CLD-001: AWS sandbox account sync produces VPC/route-graph nodes with provenance within one incremental cycle; flow-log records join existing conversations by tuple+time window.
- AC-MIG-001: Sample NetBrain export imports with per-record conversion tags and zero silent drops; reconciliation report lists unmatched objects.

## 13. Milestones

| M | Theme | Contents | Research-stage mapping (§19) |
|---|---|---|---|
| **M0 (done)** | Seed | ICMP discover/check/monitor/map/console, SQLite ops store, events/audit/outbound webhooks, profiling, diagnostics, trace, removal/retirement (current repo ≈ v0.2) | — |
| **M1** | Hardening | Split crates per §11; OpenAPI spec ✅ *(v0 served at `/api/openapi.json`)*; auth modes ✅ *(open/hardened, Argon2id users, sessions, bearer tokens, RBAC v0 — FR-PLAT-005)*; spool-on-disk collectors ✅ *(v0: cycle results spooled on store failure, replayed at startup — NFR-08)*; health endpoint ✅ *(`/api/health`)*; fixture-based tests; ServiceNow integration GA | Foundation + start of Discovery alpha |
| **M2 = MVP** | StableNet core parity | + SNMP v2c/v3 polling & interface inventory; LLDP/CDP topology; config backup+diff (SSH); scheduled reports PDF; triage wizard; scale test passing AC-NFR-01/02 | Discovery/Core NMS alpha → Enterprise beta |
| **M3** | NetBrain context | Graph-backed topology (temporal/provenance model §6); L2 path computation; diagnostic bundles/runbooks (read-only); intents v1 + violation alarms; map time-travel | Diagnostics & digital twin |
| **M4** | Flows + streaming | IPFIX/sFlow ingest (GoFlow2) & views; gNMI ingest (gNMIc); utilization golden signals; capacity forecasts; edge collectors (FR-EDGE-001) | Enterprise beta → cloud-native start |
| **M5** | Automation + AI | Write-guarded remediation w/ approvals; no-code runbook builder; baselines/anomaly ensemble; grounded NL assistant (local-model option); multi-tenant + RBAC via OIDC/OPA | Safe automation/compliance + AIOps start |
| **M6** | Ecosystem & scale | Plugin contract (gRPC out-of-process; WASM optional); Grafana recipes; HA mode; TWAMP; wireless controllers; 10k-device validation, DR drills, accessibility/localization framework | Scale/security GA |
| **M7** | Hybrid domains | Cloud/K8s/mesh/microsegmentation graph + flow logs (FR-CLD-*); security-monitoring enrichment (Zeek/Suricata); Batfish verification integration | Cloud-native/hybrid |
| **M8** | Large-scale program | 100k-device tier sharding, BMP/BGP-LS feeds, advanced RCA ensemble, migration tooling GA (FR-MIG-*) | Advanced AIOps / very-large scale |

Sequencing rules carried from research: **do not build AI before the evidence substrate**; do not build custom graph DB before profiling PostgreSQL; do not build flow decoders before evaluating GoFlow2/pmacct; do not build an IDS before integrating Zeek/Suricata; do not hand-write vendor drivers where NAPALM/scrapli already cover the interface.

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

**RCA** root-cause analysis · **MTTR/MTTA** mean time to restore/acknowledge · **SLA/SLO/SLI** service level agreement/objective/indicator · **Intent** declarative assertion of desired network state · **Golden config** approved template · **DVT/DataView** NetBrain terms for contextual data/diagnostic views · **Runbook** executable diagnostic/remediation procedure · **IPFIX/sFlow** flow telemetry · **gNMI** gRPC network management interface · **TWAMP** two-way active measurement protocol · **BMP** BGP Monitoring Protocol · **BGP-LS** BGP Link-State distribution · **PCEP** Path Computation Element Protocol · **CNI** Container Network Interface · **SoT** source of truth.

## 16. Product KPIs (operational outcomes, not vanity metrics)

| KPI | Target direction |
|---|---|
| Discovery precision/recall | ↑ toward validated 99 %+ in certified scenarios |
| Collection freshness/completeness | ↑ |
| Stream/flow decode failure rate | ↓ |
| Mean time to detect / to identify likely cause / to repair | ↓ |
| Alerts per actionable incident | ↓ |
| RCA top-3 precision; operator acceptance of hypotheses | ↑ |
| False anomaly rate | ↓ |
| Config backup freshness; change success & rollback success | ↑ |
| Modeled-vs-observed path agreement | ↑ |
| SLO measurement coverage | ↑ |
| Polling/telemetry load per device at equivalent visibility | ↓ |
| Storage cost per monitored entity | ↓ (rollups/sampling/TTL) |
| UI incident task-completion time | ↓ |
| Cross-tenant security defects; unauthorized automated changes; critical a11y defects | zero |

## 17. Testing Program

| Class | Required coverage |
|---|---|
| Protocol unit/fuzz | SNMP ASN.1, NetFlow/IPFIX templates, sFlow, syslog, gNMI payloads, CLI parser fuzzing, malformed inputs |
| Golden fixtures | Recorded vendor replies per NOS/version with normalized expected output (`fixtures/`) |
| Virtual NOS + hardware lab | boot/configure/discover/poll/stream/change/rollback; certification matrix per §9 |
| Topology/path correctness | synthetic graphs w/ LAG/MLAG/STP/VRF/MPLS/VPN/overlays/ECMP; modeled-vs-probed agreement |
| Scale | sustained poll/telemetry/flow/event/query loads at tier targets (§7); step-load soak to 2× nominal |
| Chaos | collector death, broker loss, DB node loss, packet loss, WAN partitions, clock skew |
| Security | RBAC matrix, tenant escape, API abuse (OWASP API top risks), plugin sandbox, secret leakage, SBOM/supply chain |
| Automation safety | dry-run, approvals, partial commit, lost connectivity, rollback, split-brain |
| ML/RCA | labeled incident corpus, false-correlation tests, drift, evidence-grounding checks |
| UX/accessibility | operator task scenarios, keyboard/screen-reader, large-topology workflows; WCAG 2.2 AA as release criterion |
| Upgrade/DR | rolling upgrades, migration windows, restore-from-backup drills (quarterly) |

## 18. Migration Pipeline (from NetBrain / NMSaaS-class systems)

`export/API adapters → staging canonical model → validation/reconciliation → open NMS read-only → dual-run monitoring → shadow diagnostics → approved write automation → cutover → legacy archive`

Requirements: FR-MIG-001/002. First artifact is the *inventory-of-inventory* (devices, addresses, vendors/NOS, sites, credential references, circuits, maps, templates, thresholds, reports, incidents, integrations, config backups, policy rules, scripts). Acceptance for monitoring cutover = parity across topology, inventory, counters, event detection, config backups, alert routing, reports/SLO plus a successful HA/restore exercise.

## 19. Team Shape & Effort (planning guidance only)

Peak program ≈ 18–24 people; MVP start ≈ 10–14. Effort estimate 245–390 person-months (contingency 265–425) across platform/API, discovery/polling, topology/path, storage/query, config/automation, cloud/K8s/security, UI/reports, HA/perf workstreams. ±40 % uncertainty until device counts and migration volumes are measured. AI coding assistants accelerate application CRUD/UI — not multivendor normalization, protocol edge cases or hardware-lab QA.

## 20. Governance

Apache-2.0 core (see §9). DCO 1.1 sign-off on every commit. Public ADR/RFC process (`docs/adr/`). TSC, subsystem maintainers, security response team, release managers and vendor SIGs introduced as ecosystem grows (FR-GOV-002). Semantic versioning for APIs/SDKs; documented migration windows; LTS releases; machine-readable deprecations.

## 21. Collection Strategy Principles

1. Pull is the reconciliation mechanism; push is the freshness mechanism. A trap/syslog saying "link down" triggers a targeted state refresh — it is an event, not durable truth.
2. Agentless by default where standards expose the data (SNMPv3, gNMI, NETCONF/RESTCONF, SSH, flows, syslog, BMP, BGP-LS); agents only where the control plane cannot see (packet capture, eBPF, synthetic probes, host metrics, K8s flow context).
3. Capability-driven protocol support: choose the least expensive source meeting required freshness/accuracy.
4. Sampling hierarchy over global toggles (§3.1.1); cost metrics (`bytes_ingested`, `samples_per_entity`, `flow_rows_per_tenant`, `query_cpu_seconds`, retention cost) are first-class dashboard citizens.
5. Privacy by design: masking/hashing options, payload suppression, geographic storage restrictions, evidence retained only for its operational/legal purpose (GDPR data-minimization alignment).

## 22. RCA & AIOps Architecture (deterministic first)

RCA combines, in order: deterministic state/threshold logic → dependency-graph propagation → temporal event/change correlation → differential config/path analysis → statistical anomaly & peer groups → active verification → probabilistic ranking → LLM explanation of already-grounded evidence. Every conclusion carries hypothesis + supporting AND contradicting evidence IDs with confidence labels.

AI sits above deterministic tools, never beneath them: `question → authorization → planning → read-only tools → structured evidence → analytics → cited answer → optional proposed workflow → policy/approval → execution`. Statements must trace to evidence ("BGP caused it" is unacceptable; "config change on R17 at 14:03:22; adjacency dropped 4.2 s later; 83 prefixes withdrawn; path changed; latency rose immediately — confidence 0.91, alternative: upstream carrier" is the standard). Prompt-injection isolation, least-privilege tools, secret filtering, tenant-scoped retrieval; unsafe-action target = zero.

---

*End of PRD v1.1. Implementation questions resolve in favor of: correctness under scale > simplicity > features.*
