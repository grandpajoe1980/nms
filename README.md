# nms

A quiet ICMP-based network management system written in Rust.

It crawls your network with single pings (randomized order, rate-limited),
discovers subnets from local interfaces and the routing table, builds a model
of routers / wireless APs / endpoints, and renders an interactive HTML map.
A fast `check` command re-verifies up/down state for everything in the model.

## Commands

```
nms discover [--subnets a.b.c.d/x,...] [options]   crawl + classify + build map
nms check    [--subnets ...]       [options]       fast up/down sweep of the model
nms monitor  [--interval-secs 60]  [options]       loop checks forever + down alerts
nms serve    [--port 8765]                         web map + clickable NMS controls
nms map                                            regenerate map.html from model.json
nms routes                                         print IPv4 routing table (debug)
nms ifaces                                         print local interfaces (debug)
nms ping <ip> [--ttl n] [--engine]                 single probe (debug)
```

Outputs land in `--out` (default `output/`): `model.json` and `map.html`.

## Typical usage

```
nms serve               # opens http://127.0.0.1:8765 with all controls
```

The recommended workflow is now the web control panel. Press **Start NMS** to
run discovery and automatically start continuous monitoring. The page also has
buttons for Discover, Check now, Monitor/Stop monitor, Ping, Routes, and
Interfaces. Run `nms serve --no-open` when you do not want it to launch the
default browser.

The standalone `output\map.html` still works offline, but browsers do not allow
a `file://` page to start local programs. Its action buttons are therefore
disabled until the page is opened through `nms serve`.

## Web map

- The layout is flex-based: the canvas consumes all space left after the two
  command bars and optional device panel.
- **Hide panel** gives the canvas the full width.
- **Fit** recalculates the zoom from the currently available canvas dimensions.
- Active devices are selected by default; choose `all` or `down` as needed.
- The job pill shows `idle`, `discover...`, `check...`, or `monitoring`.
- The activity panel reports devices that are new, down, or recovered during
  the current server session, and the map refreshes after monitor sweeps.
- Endpoints can be manually assigned to a detected WAP from their detail panel.
  The assignment is persisted in `model.json` and reflected in topology links.

## Monitoring & alerting

`nms monitor` re-runs a full status sweep every `--interval-secs`, refreshes
model.json/map.html each cycle, and reports:

- `[ALERT ...] DOWN <role> <ip>` — terminal line prefixed with a bell
  character; also appended to `output/alerts.log`
- `[recovered]` / `[new]` informational lines for other transitions

Optional hook:

```
nms monitor --interval-secs 30 --exec "msg * device {ip} went down"
```

`{ip}`, `{role}`, `{subnet}`, `{state}` placeholders are substituted.

Because a single missed ping isn't proof of death, monitor defaults to
`--confirm-down 1`: any host that was up and just missed its ping is re-probed
once (twice with `--confirm-down 2`) before an alert is raised.

ICMP and ARP do not expose which wireless access point serves a client. WAP
membership is therefore manual unless a future controller or SNMP integration
provides authoritative association data.

## Performance targets

- Discovery finishes under **1 hour** by design:
  - hard deadline flag `--budget-mins` (default 45, must stay < 60)
  - subnets larger than `--big-threshold` hosts (default 4096) are sampled
    (`--sample` random addresses plus edge /24s) unless you pass `--full`
- Status checks comfortably handle **50k devices in under 2 minutes**:
  - defaults: 1500 probes/sec across 1024 workers (50k ≈ 33s)
  - measured on this machine: 65,534 addresses in ~13s at `--rate 5000`

## How discovery works (silent by design)

1. Seeds = local interface subnets + every scannable route prefix
   (private/CGNAT/link-local only) + any `--subnets` you add.
2. One ICMP echo per address, order randomized, global token-bucket rate cap.
3. ARP cache is harvested afterwards to attach MAC addresses.
4. TTL-hop walking ("traceroute-lite"): a few live hosts per subnet are probed
   with low TTLs; intermediate routers reveal themselves via Time Exceeded.
5. Classification heuristics (no SNMP, no port scans):
   - **router** — next-hops from the routing table, discovered mid-path hops,
     or responded `.1/.254` when nothing else claims the subnet
   - **wap** — MAC OUI matches known wireless vendors (Ubiquiti, Aruba,
     Meraki, Ruckus, TP-Link, Google Wifi, ...)
   - **endpoint** — everything else
   - reply-TTL vs OS-class baseline flags devices that appear to sit behind
     extra L3 hops

## Platform notes

- **Windows**: uses `IcmpSendEcho` from iphlpapi — no admin rights needed.
- **Linux/macOS**: unprivileged datagram ICMP if permitted
  (`sysctl net.ipv4.ping_group_range`), else falls back to raw sockets
  which need root/CAP_NET_RAW.
- IPv4 only. Hosts that block ICMP will simply show as down (single-ping policy).

## Tuning checklist

| symptom                          | fix                                             |
|----------------------------------|-------------------------------------------------|
| check too slow                   | raise `--rate` and/or `--concurrency`           |
| flaky down devices               | raise `--timeout-ms`                            |
| huge unrouted space being sampled| narrow scope with `--subnets`, keep default sampling |
| want exhaustive coverage         | `discover --full --budget-mins 59`              |
