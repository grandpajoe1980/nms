# ADR-0001: Adopt deep-research findings — stack revision, scale tiers, new domains

- Status: Accepted (2026-08-24)
- Inputs: `docs/research/2026-08-deep-research-report.md` (user-commissioned research), PRD v1.0
- Amends: `docs/PRD.md` → **v1.1**

## Context

PRD v1.0 was drafted before a commissioned deep-research pass over NetBrain,
NMSaaS/StableNet-class products, modern telemetry standards, and academic
network-measurement work. The research introduces capability domains absent from
v1.0 (packet capture, security monitoring, cloud/K8s/mesh/microsegmentation/zero
trust, edge collectors, migration tooling) and recommends different defaults for
several architecture choices.

## Decisions

1. **Collector plane becomes dual-track.** The existing Rust engine remains the
   seed ICMP/sweep/diagnostics core (single-binary lab mode forever). New
   protocol adapters (SNMP GETBULK framework, gNMI, flow ingest, config
   drivers) may be implemented in **Go** to leverage mature ecosystem
   components; Python is the automation/analytics/SDK layer. Rust-vs-Go per
   adapter is an implementation choice recorded in each component's ADR — the
   canonical model and wire contracts are language-neutral.
2. **Scale-out storage/bus defaults change:** Kafka (durable replay) replaces
   NATS as the default bus for enterprise/large tiers; **PostgreSQL** is
   authoritative inventory/control metadata; **ClickHouse** owns metrics/flows/
   events analytics; object store for blobs. NATS + SQLite remain supported as
   the lightweight "lab mode" pair. VictoriaMetrics drops from the default path
   (ClickHouse covers its role).
3. **Three design/test scale tiers** adopted (Community ≤1k devices,
   Enterprise ≈10k devices / 500k interfaces, Large ≈100k devices /
   ~1M samples/s). The original 850-site/3k-router/50k-endpoint estate remains
   the program's named reference deployment inside the Enterprise tier.
4. **New capability domains** enter the PRD with FR IDs: packet capture (CAP),
   security monitoring (SEC), cloud/K8s/service-mesh/microsegmentation/zero-trust
   (CLD), edge collectors (EDGE), legacy migration tooling (MIG), governance
   (GOV). Temporal provenance fields become mandatory on all graph/model objects.
5. **Component reuse posture:** gNMIc, GoFlow2/pmacct, Zeek/Suricata, Batfish,
   NetBox sync, Oxidized bridge, scrapli/Nornir/NAPALM, Keycloak-compatible
   IdP, OpenBao, OPA are preferred building blocks/compatibility targets rather
   than re-implementations.
6. **Governance/licensing:** Apache-2.0 core confirmed; add DCO 1.1, public
   ADR/RFC process, TSC model, compatibility-matrix certification contract.

## Consequences

- PRD §3/§5/§7/§9 amended; new sections 4.15–4.20, 16–22 added.
- M-milestones annotated with research-stage mapping; effort/staffing estimates
  recorded in PRD §19 as planning guidance only.
- No code changes in this amendment; existing frozen contracts unaffected.
