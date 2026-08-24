---
description: PRD-driven build kickoff — reads the source-of-truth docs, breaks work down, implements with tests, verifies against the PRD.
agent: build
---

You are starting (or continuing) a build session on nms-ng. Follow this exactly:

1. **Load context first, write nothing yet:**
   - Read `docs/PRD.md` fully (source of truth).
   - Read `AGENTS.md` (binding rules) and `README.md`.
   - Run `git log --oneline -15` and `git status --short --branch` to see where things stand.

2. **Pick the work:** If $ARGUMENTS names a task/FR ID, use it. Otherwise take the
   highest-priority unfinished item from the current milestone in PRD §13
   (M1 first unless told otherwise). State in one line what you chose and why,
   then proceed — do not wait for confirmation on obvious next items.

3. **Break it down:** todo list, one item per verifiable step, each citing its
   FR/NFR/AC ID. Work iteratively: implement → test → verify → commit.

4. **Quality gate before any "done":** from repo root run
   `cargo test`, `cargo clippy --all-targets -- -D warnings`,
   `cargo build --release`. All must be green. Update README and/or the PRD
   milestone table in the same change set.

5. **Verify independently:** when a chunk completes, invoke the `tester`
   sub-agent to re-run verification, and the `prd-reviewer` sub-agent for
   scope/conformance review of anything user-visible or contract-adjacent.
   Address RED findings before moving on.

6. **Status & stop:** end your turn with a status block:
   DONE / NEXT / OPEN QUESTIONS. Stop immediately if anything is ambiguous
   between two plausible readings, if an acceptance criterion cannot be verified
   locally, or if you find yourself building something no FR calls for.

Task input: $ARGUMENTS
