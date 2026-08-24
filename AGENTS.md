# AGENTS.md — Operating Rules for AI Programmers

This repository builds **nms-ng** per `docs/PRD.md`. These rules are binding for
every human or AI contributor. When rules conflict with convenience, rules win.

## 1. Source of Truth (order of authority)

1. **`docs/PRD.md`** — the product source of truth. Requirements (`FR-*`), NFRs,
   milestones, acceptance criteria, non-goals, event taxonomy, data contracts.
2. Architecture Decision Records in `docs/adr/` (create one for any deviation).
3. Code comments/docstrings.
4. Chat conversation (never overrides 1–3).

**If the PRD and the code disagree, the code is wrong until the PRD is amended
via an ADR.**

## 2. Mandatory Workflow (every task)

1. **READ FIRST:** Read `docs/PRD.md` (at minimum: §13 milestones, the domain
   section you are touching, §6 data architecture if touching schemas, §10
   taxonomy if touching events) and this file before writing any code.
2. **CITE:** Name the FR/NFR IDs you are implementing in your plan, your commit
   message, and the PR/task description. No ID ⇒ out of scope.
3. **BREAK DOWN:** Convert any task larger than ~1 hour into a todo list with
   one item per verifiable step. Work iteratively: implement → test → verify.
4. **TEST:** Before claiming any task is done, run from repo root:
   ```powershell
   $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
   cargo test          # all tests must pass
   cargo clippy --all-targets -- -D warnings   # zero errors
   ```
   Plus `cargo build --release` when shipping a runnable artifact. Paste/keep
   evidence of green runs. Never skip failing tests by deleting/weakening them.
5. **DOCS:** Any user-visible behavior change, new setting, API endpoint, or
   schema change must update `README.md` and/or `docs/PRD.md` (e.g., tick a
   milestone item, add an ADR) **in the same change**.
6. **COMMIT:** Small, frequent commits. Message format:
   `<area>: <summary> (<FR-ID(s)>)` e.g. `engine: dependency suppression (FR-FLT-004)`.
   Only push when the user asks or a milestone completes cleanly.
7. **STATUS:** Maintain a short status block in your working notes / final
   message: what's done, what's next, open questions.

## 3. Scope Discipline

- Build **only** what a PRD requirement calls for. If you spot a valuable idea
  that is *not* in the PRD: stop, write it up as a proposed ADR/PRD amendment,
  ask the user. Do not implement drive-by features.
- Respect **§2 Non-Goals** absolutely (no SIEM sprawl, no config-push-first, no
  SaaS dependency).
- Frozen contracts you must never break without an ADR + version bump:
  - Webhook payload v1 (PRD §4.3 FLT-009 JSON block)
  - Event kind taxonomy strings (PRD §10)
  - CLI verbs: `discover|check|monitor|serve|map|routes|ifaces|ping`
  - SQLite ops store migration compatibility (forward-only, additive)

## 4. Quality Bar

- Zero `clippy -D warnings`; zero compiler warnings on main.
- New logic requires unit tests; bug fixes require a regression test that fails
  without the fix.
- Anything touching sweep scheduling, rate limiting, or alarm lifecycle needs a
  test proving no duplicate/storm alerts (see AC-FLT-004 pattern, PRD §12).
- Performance-sensitive paths (sweeps, ingest): include a size sanity check
  against NFR-01/NFR-05 budgets when practical.

## 5. Environment Notes

- Windows PowerShell host; prepend `$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"` before cargo.
- Stop a running `nms.exe` before rebuilding the release binary (file lock):
  `Get-Process -Name nms -ErrorAction SilentlyContinue | Stop-Process -Force`.
- Default output dir is `output/` (gitignored); never commit generated
  `model.json`, `map.html`, `ops.db`, or `alerts.log`.

## 6. Sub-Agents

Invoke specialized sub-agents via the Task tool instead of doing their jobs
inline:

| Agent | File | Use when |
|---|---|---|
| `prd-reviewer` | `.opencode/agents/prd-reviewer.md` | Before finishing any feature: verify implementation matches PRD scope/IDs, flag drift or out-of-scope work. Read-only. |
| `tester` | `.opencode/agents/tester.md` | To independently run the full verification battery (build/tests/clippy/smoke endpoints) and report a verdict. Cannot edit code. |
| `implementer` | `.opencode/agents/implementer.md` | Delegating a self-contained FR-sized chunk of implementation work following the mandatory workflow. |

Example invocation: launch `task` with `subagent_type: "general"` style call —
or reference these agents by name if your client lists them. Reviewer output
must end with verdict `PASS`, `PASS-WITH-NOTES`, or `FAIL` plus cited FR IDs.

## 7. Stopping Rule

Stop and ask the user when: requirements conflict with the PRD, an acceptance
criterion cannot be verified locally, a dependency/license question arises, or
two readings of a requirement are plausible. Ambiguity is a blocker, not a
design decision.
