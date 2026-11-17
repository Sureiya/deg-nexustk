# DeG ↔ KazeTK: work split and status

> **Note (2026-11-17):** the `deg-nexustk` adapter crate no longer lives inside
> the DeG repository. It was moved to its own standalone repository (this one,
> alongside this doc), where it consumes the DeG core as a git dependency
> instead of being a workspace member. The split and status below are
> unchanged.

This file records the split between **generic DeG core extensions** and a
**NexusTK-specific adapter crate** (`deg-nexustk`), as decided from the
[applicability assessment](nexustk-emulator.md). Status is updated as lanes
merge.

## Bucket 1 — generic DeG core extensions

These benefit any RE project, not just KazeTK.

| Id | Extension | Why | Status |
|---|---|---|---|
| C1 | PE32/PE32+ section-aware `build` artifacts (`format: pe`) | address `.text`/`.rdata`/`.data` by VA without load-bias hacks; enables the client-anchor model directly | merged (`core-pe`) |
| C2 | `table` evidence (CSV/TSV/WS rows as facts, Deterministic parse) | reasoning over tabular manifests (opcode layouts, ID lists) | merged (`core-pe`) |
| C3 | Compiled-in evidence extension registry + `deg extensions` | domain crates add reviewed, trusted evidence kinds without forking the kernel | merged (`core-pe`) |
| C4 | `samples` evidence + `mean` claim (grouped numeric samples, n/CI/power, Observational) | mechanics metrics (KazeTK's 19 metrics, mob cadence, damage bands) | merged (`core-claims`) |
| C5 | `coverage` claim over a locked dataset (`covered/target`, missing IDs) | reproduce audits like 33/33 and 64/82 as an auditable claim, not a second count authority | merged (`core-claims`) |
| C6 | Generic conflicts between any two claims + hash-pinned `decision` files | the nine-artifact dossier and any human classification decision | merged (`core-claims`) |
| C7 | Generalized refutation via `contradicts(ev, rel, args)` facts | refute protocol/opcode hypotheses, not just RNG algorithms | merged (`core-claims`) |

## Bucket 2 — NexusTK-specific adapter (`deg-nexustk`)

A standalone crate that compiles into a second trusted binary. It registers
evidence kinds through C3 and consumes operator-local artifacts; nothing from
`nexustk-emulator` is copied into this repository.

| Id | Module | Purpose | Status |
|---|---|---|---|
| N1 | `codec` + `vectors` (`ntk_vector` evidence) | replay the documented 7.52 framing/cipher/tail/key-table against known-answer files; resolve the tail encode/decode ambiguity | merged (`ntk-adapter`) |
| N2 | `frames` + `bundle` (`ntk_frames`, `ntk_bundle` evidence) | read `frames.jsonl` and verified `kaze.bundle/v1` packages with redaction; hash-chain verification | merged (`ntk-adapter`) |
| N3 | `generate` CLI | convert the project's `opcode-layouts.json`/`opcode-artifacts.json`/`DISPATCHER-AUDIT.json` into `.dg` claims, proofs, conflicts, decisions, obligations, and a coverage claim | merged (`ntk-generate`) |
| N4 | examples/templates + crosscheck | a client-anchor template (like the local pilot), synthetic end-to-end fixtures for CI, and a local-only parity crosscheck against the project's validator counts | merged (`ntk-generate`) |

## Sequencing (complete)

1. Core lanes (`core-pe`, `core-claims`) — reviewed ×2, merged to `main`.
2. `deg-nexustk` crate (N1, N2) — reviewed ×2, merged.
3. Generator and docs (N3, N4) — reviewed ×2, merged.
4. Final integration: CI, `docs/nexustk-emulator.md` status update,
   published.

## Rules for the adapter

- No file from `/home/kin/nexustk-emulator` is copied or committed. Algorithm
  behavior is implemented from documentation only; fixtures are synthetic and
  generated in-repo.
- Client binaries, captures, key tables, and credentials stay operator-local.
- External analysis stays capped at Observational; only kernel-reviewed,
  compiled-in primitives may reach Deterministic/Exact.
- The KazeTK locked requirements contract and validator remain the policy
  authority; DeG reports, never re-decides, expected counts.
