# nms

A quiet, ICMP-first **network management system** written in Rust — free, open
source, and built for operations at scale: **850 sites · 3,000 routers ·
50,000 endpoints**, with minutes-level fault detection.

It crawls your network with single pings (randomized order, rate-limited),
discovers subnets from local interfaces and the routing table, classifies
routers / wireless APs / endpoints into a persistent inventory, then runs a
continuous monitoring engine that provides fault detection with root-cause
suppression, performance history, uptime accounting, event management, audit
logging, SLA-style reporting, and an outbound webhook queue ready for
ServiceNow.

No login, no accounts by design **in the default `open` mode** (loopback lab/home use).
Hardened mode is available when you expose the console beyond loopback — see below.

## Auth modes (open vs hardened)

- `nms serve` binds `127.0.0.1` and runs in **open** mode: every page and API is unauthenticated.
- Binding any non-loopback address (`nms serve --bind 0.0.0.0`) or setting
  `auth_mode=hardened` (Settings page, requires restart) enables **hardened mode**:
  - local users with Argon2id-hashed passwords, 7-day session cookies,
    API bearer tokens stored hashed;
  - roles `viewer` (read) < `operator` (run checks/diagnostics/ack) <
    `admin` (discover/settings/webhook/remove); plus role `automation`
    (API-token equivalent of operator, never console pages);
  - unauthenticated requests get `401` (APIs) or a redirect to `/login` (pages);
    `/api/health` and `/api/openapi.json` stay public for operability.
- Bootstrap an admin and a token:

```
nms user add joe --role admin        # prompts for password
nms token add ansible --role automation
nms serve --bind 0.0.0.0
```

## Feature map

Aligned with the classic NMS "pillars" (discovery & inventory, fault,
performance, configuration management):

| pillar | what nms does today |
|---|---|
| discovery & inventory | auto-crawl of interface subnets + scannable routes; device registry in SQLite (role, MAC, site, parent); **SNMP ifTable GETBULK walk → per-device interface inventory** (ifIndex/name/speed/admin/oper/MAC, surfaced on device pages + `/metrics`; GETNEXT fallback for legacy agents); **LLDP + CDP neighbor discovery** per device; sites auto-derived per /16 or /24; manual site assignment wins |
| **deep endpoint profiling** | `discover --deep` (default from the web panel) reverse-DNS names, light TCP port fingerprinting (14 common ports), OUI vendor hints, **SNMP v2c identity probes** (`--snmp-community public`; sysName→hostname, sysDescr→vendor/OS) → device class: printer / NAS / server / computer / mobile / IoT / TV / appliance |
| fault management | continuous sweeps; up/down/unreachable states; **dependency-aware root-cause suppression** (a downed router collapses all its endpoints into one incident with an impacted-device count); flapping detection & damping; maintenance windows; acknowledge workflow |
| performance management | RTT samples + hourly/daily rollups; latency warning/critical thresholds; rolling loss detection ("degraded"); jitter accounting |
| diagnostics | per-device burst ping: loss %, min/avg/max/p95 RTT, jitter, link-quality score 0-100 (ICMP responsiveness — not Mbps bandwidth); port/service list with **expected-service checks** per device class |
| wap association | manual endpoint→WAP binding from the map or device page; ICMP/ARP cannot infer radio association, so nothing is guessed automatically |
| path analysis | on-demand ICMP traceroute per device with inventory-enriched hops (role/site/class) |
| impact analysis | "depends on this device" listing straight on the device page |
| inventory hygiene | devices unseen for `absent_retire_days` (default 30) are retired automatically; explicit remove button keeps the map clean today |
| scheduled reporting | hourly 24h-availability snapshot + dated daily HTML and headless-print PDF under `output/reports/` when Edge/Chrome/Chromium is detected (90-day retention; override via `report_pdf_renderer` or `NMS_PDF_RENDERER`) |
| configuration management | opt-in `inspect --config-backup` SSH read-only snapshots for Cisco IOS-XE and Aruba AOS-CX (feature-gated), raw + normalized archives and unified diffs |
| reporting | per-site availability % (24h/7d/30d), MTTR, avg RTT; HTML tables + CSV exports (site-level and per-device) |
| audit | every user action (settings change, ack, site assign, maintenance toggle, webhook test) recorded with actor/time/details |
| integration | outbound webhook queue with retries; JSON payload schema designed for ServiceNow Incident creation; test button |

## Commands

```
nms discover [--subnets a.b.c.d/x,...] [options]   crawl + classify + build model + sync inventory
nms check    [--subnets ...]       [options]       one sweep -> ops DB (samples, events, alerts)
nms monitor  [--interval-secs 60]  [options]       loop checks forever (ops engine + exec hook)
nms inspect  [--config-backup --ssh-username USER --ssh-credential-ref REF --ssh-known-hosts PATH] [options]
nms serve    [--port 8765]                         web console + map + monitoring controls
nms map                                            regenerate output/map.html from model.json
nms routes | ifaces | ping <ip>                    debug helpers
```

Outputs live in `--out` (default `output/`):

| file | purpose |
|---|---|
| `model.json` | discovered topology snapshot (map source of truth) |
| `map.html`   | standalone interactive topology map |
| `ops.db`     | SQLite ops database: inventory, samples, rollups, segments, events, audit, outbound queue |
| `alerts.log` | append-only DOWN alert lines (bell-prefixed on console too) |

Config backup is deliberately opt-in and runs only during the dedicated
`inspect` enrichment pass. Build with `cargo build -p nms --features ssh`, then
write a key into the encrypted vault using `POST /api/credentials` as an admin;
the response contains only the opaque reference and status. Provide that
reference plus a username and known-hosts path to `inspect`. The master key is
read from `NMS_VAULT_KEY` (exactly 64 hex characters) or, when unset,
`NMS_VAULT_KEY_FILE`; it is never stored. Host keys must already be present
and match the supplied known-hosts file; unknown or changed keys fail closed.
Credential writes/deletes are admin-only and audited; there is no secret GET or
list endpoint. In open mode, bootstrap an admin bearer token with
`nms token add vault-admin --role admin` and send it as `Authorization: Bearer
...` for these mutations. No configuration push is implemented.

On Windows, the standard library cannot reliably validate NTFS DACLs for
`NMS_VAULT_KEY_FILE`; protect that file with an administrator-only ACL. Prefer
`NMS_VAULT_KEY` from a protected process environment when practical.

## The web console (`nms serve`)

`http://127.0.0.1:8765` — the map page keeps its original controls (Discover,
Check now, Monitor start/stop, Ping, Routes, Ifaces, WAP assignment) and now
links to the full console:

- **Console** — KPI cards (managed/up/down/unreachable/degraded/sites),
  network-wide availability chart (24h), slowest devices, latest events
- **Devices** — filterable inventory (state, ip/mac substring); drill-down per
  device shows uptime %, RTT sparkline, state timeline, recent events, and
  actions (acknowledge, maintenance window, assign site, managed/unmanaged)
- **Events** — alert list with severity/kind/state filters and ack/unack;
  events open when a condition starts and auto-close when it clears
- **Reports** — availability per site for 24h/7d/30d windows with MTTR and CSV; a daily PDF download appears when a valid renderer artifact exists
  downloads
- **Audit** — who did what, when (actor `web`, `system`)
- **Settings** — thresholds, flap window, retention, webhook URL/enable,
  poll interval, auto-site prefix; plus webhook connectivity test

### HTTP API (all unauthenticated)

```
GET  /api/status                 job state + last cycle stats
GET  /api/health                 component health: database probe, scheduler state, webhook queue depth (503 when degraded)
GET  /api/intents.json           intent compliance: loaded intents, pass/fail per site
GET  /api/openapi.json           OpenAPI 3.0 spec of the full API surface
GET  /api/dashboard.json         counts, trend, worst latency, event counters
GET  /api/devices.json           inventory rows
GET  /api/device/<ip>.json       one device record
GET  /api/events.json            event feed (filters via query)
GET  /api/report/availability.csv?hours=24|168|720
GET  /api/report/devices.csv?hours=&site=
GET  /api/report/availability.pdf?date=YYYY-MM-DD  (404 until that daily PDF artifact exists)
POST /api/event/ack              form: id=<n>&ack=1|0
POST /api/device                 form: ip=<ip>&action=maintenance|site|managed&value=...
POST /api/settings               form: key=value pairs (known keys only)
POST /api/webhook/test           sends a test payload to the configured URL
POST /api/discover | check | monitor/start | monitor/stop | ping | associate
GET  /api/model | routes | ifaces
```

## How the monitoring engine works

Each cycle (`check` or a monitor sweep):

1. **sweep** — one ICMP echo per target, randomized order, token-bucket rate cap
2. **persist** — samples `(device_id, ts, up, rtt)` into SQLite; hourly rollups
   recomputed for touched devices (probes, ups, rtt sum/min/max, jitter)
3. **resolve dependencies** — endpoint→WAP→router chains; any node whose parent
   chain contains a DOWN device becomes **unreachable** instead of raising its
   own incident; unreachable counts roll up to the root's event details
4. **segments** — effective-state changes open/close uptime segments
   (`state_segments` power uptime % and MTTR)
5. **events** — lifecycle-managed using the canonical PRD taxonomy:
   `device_down` (critical), `latency_warn`/`latency_crit`, `loss_warn`, and
   informational `device_up`; auto-clear on recovery; ack tracked separately.
   Flap damping remains persisted as transition counters and never creates a
   noncanonical event kind.
6. **maintenance** — devices inside a maintenance window still get probed but
   raise no alerting events
7. **delivery** — critical/warning events are queued as JSON payloads and
   delivered by the webhook worker with exponential retry backoff (maximum
   five attempts, then parked in the delivery ledger).

Canonical bus consumers use the separate `network.telemetry.v1` envelope from
PRD §6.1; notification webhooks continue to use the frozen v1 shape above.

### Deterministic sweep acceptance (FR-FLT-002, NFR-01, NFR-02)

The sweep boundary has a deterministic in-process probe backend for acceptance
tests. It exercises the same global limiter, worker concurrency, deadline, and
progress path as real ICMP; the normal CLI and production `check` path still
open the platform ICMP backend. Run the fast equivalent with:

```powershell
cargo test -p nms-engine --lib engine::tests::synthetic_scheduler_fast_equivalent
```

Run the explicit 50,000-target release acceptance with:

```powershell
cargo test -p nms-engine --release --lib engine::tests::ac_nfr_01_fifty_thousand_synthetic_targets -- --ignored --nocapture
```

Latest controlled Windows release run: 50,000/50,000 targets in 10.02 s;
the live reporter held approximately 4,988–5,000 probes/s and reached 100%.

The NFR-02 logical seam test drives a down probe, its deadline-bounded confirm
probe, and the alarm/outbound enqueue boundary. Sweep plus confirm is capped at
115 seconds (120-second NFR-02 budget minus a five-second persistence/alarm
reserve), even when a caller requests a larger budget:

```powershell
cargo test -p nms-engine --lib nfr02_synthetic_down_confirm_and_alarm_enqueue
```

## ServiceNow integration (ready now)

**Direct mode (Basic auth, no middleware):** open **Settings** and fill in
`snow_instance_url` (e.g. `https://yourinstance.service-now.com`),
`snow_username` + `snow_password` (a service account with
`incident` write access), set `snow_transform=1` and `webhook_enabled=1`,
then save. Critical/warning alerts POST straight to
`<instance>/api/now/table/incident` as incidents (severity→impact/urgency,
`correlation_id = nms-<event id>`); recovery events deliver as auto-resolved
closures. The password is write-only in the UI and never logged or returned.

**Middleware mode:** alternatively point `webhook_url` at a Business Rule /
IntegrationHub endpoint that accepts the raw JSON below.

1. Either way, press **send test payload** (raw mode) or watch the first real
   alert land as an incident.
2. Raw payload shape delivered per alert:

```json
{
  "type": "nms.event",
  "ts": "2026-08-23T18:20:11+00:00",
  "event": {
    "id": 42, "kind": "device_down", "severity": "critical",
    "message": "router 10.20.30.1 down — 118 dependent device(s) unreachable",
    "details": {"impacted":118,"maintenance":false},
    "created_ts": 1771885211
  },
  "device": { "ip": "10.20.30.1", "role": "router", "site": "10.20/16", "tags": [] }
}
```

3. Map `severity` → Impact/Urgency, `site` → CMDB location, `ip` → CI lookup.
   Recovery events arrive with `kind:"device_up"` so your flow can resolve the
   incident. Delivery uses the queue with retry/backoff (5 attempts).

## Sizing for 50k endpoints / 850 sites / 3k routers

- A full 65k-address sweep measured ~13 s at `--rate 5000` from one host; the
  default monitor cadence (60 s, configurable in Settings) leaves ample headroom.
- Storage: raw samples retained 36 h (~45 M rows/day at 50k targets — tune
  `poll_interval_secs` or retention to taste), hourly rollups 14 d, daily
  rollups 400 d. All three are Settings keys.
- Dashboards/reports read rollups, not raw samples, so pages stay fast.
- SQLite (WAL) comfortably handles this pilot scale on SSD. For multi-region
  deployments run one collector per region and aggregate via the webhook/API.

## Platform notes

- Windows: `IcmpSendEcho` (iphlpapi) — no admin rights needed.
- Linux/macOS: unprivileged datagram ICMP when permitted, else raw sockets.
- IPv4 only; hosts blocking ICMP show as down (single-ping policy).
- No login/no TLS: bind it to loopback or front it with your own proxy.

## Building

```
cargo build --release
cargo test
target/release/nms.exe serve
```

The repo is a Cargo workspace (PRD §11): `crates/engine` (sweeps, inventory,
ops pipeline, diagnostics — Rust domain core), `crates/core-api` (HTTP server +
web console), and `crates/nms` (the `nms` CLI binary, thin over both).

## Tuning checklist

| symptom | fix |
|---|---|
| check too slow | raise `--rate` and/or `--concurrency` |
| flaky downs | raise `--timeout-ms` or `confirm_down` |
| alert storm during maintenance | use device Actions → maintenance window |
| noisy chatty device | flap threshold/window in Settings damp it |
| huge unrouted space sampled | narrow with `--subnets`, keep default sampling |

## Roadmap (config-management pillar + beyond)

- SSH/SNMP configuration backup & diffing
- TCP service checks (is :443 actually answering?) alongside ICMP reachability
- SNMP polling for interface counters/utilization
- NetFlow/sFlow sampling for top-talkers
- Distributed collectors with central aggregation
