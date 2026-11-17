# Applying DeG to KazeTK (`nexustk-emulator`)

> **Note (2026-11-17):** the `deg-nexustk` adapter crate no longer lives inside
> the DeG repository. It was moved to its own standalone repository (this one,
> alongside this doc: the adapter source is in `../src/`, its README is
> `../README.md`, and its tooling is in `../tools/`). The adapter consumes the
> DeG core as a git dependency instead of being a workspace member; the
> analysis and status below are unchanged.

**Status:** read-only assessment plus a local pilot. No file in
`/home/kin/nexustk-emulator` was modified. The pilot model lives outside both
repositories and references the operator-supplied client by absolute path, so
no client or capture bytes are committed.

**Assessment date:** 2026-11-17

**Short version:** DeG is a strong fit for KazeTK's **claim and evidence layer**,
not a replacement for its requirements validator. The project already does
content-addressed capture packaging, "no self-attestation", known-answer
vectors, opcode dossiers, and a locked expected-count contract. DeG can turn
that material into a uniform proof graph with strengths, support sets,
bottlenecks, conflicts, obligations, a seal, and cross-version porting. The
highest-value first pilots are **client anchoring** (already demonstrated),
**protocol known-answer vectors**, and an **opcode claim graph over verified
capture packages**. Replacing the validator or inventing new analysis is not the
recommended first step.

---

## 1. What KazeTK already has

The project's existing evidence discipline is unusually close to DeG's design:

| KazeTK mechanism | Where | DeG analogue |
|---|---|---|
| Content-addressed capture packages with manifests, blobs, and a hash-chained index | `docs/CAPTURE-PACKAGES.md`, `docs/CAPTURE-SCHEMA.md`, `scripts/capture-seal.py` | artifacts + evidence support |
| "No self-attestation": a JSON file written by an agent does not earn credit | `docs/CAPTURE-PACKAGES.md` §1 | external certificates capped at Observational |
| Known-answer frame/cipher/stream vectors | `server/internal/protocol/testdata/vectors/7.52.json`, `vectors_test.go`, `cipher_test.go` | kernel-replayed certificates (proposed `vector` primitive) |
| Opcode coverage and artifact dossier with an explicit human decision | `docs/OPCODE-COVERAGE-752.md`, `docs/OPCODE-ARTIFACT-DOSSIER-752.md`, `docs/analysis/opcodes/ARTIFACTS.md` | claims, conflicts, refutations, obligations, seal |
| Client identity, PE mapping, prologue/table byte checks | `docs/analysis/opcodes/TOOLKIT.md`, `docs/analysis/opcodes/DISPATCHER-AUDIT.md` | `build` + `scan`/`bytes` evidence (demonstrated below) |
| Locked 9-area / 31-check contract with expected counts | `docs/VANILLA-REQUIREMENTS.md`, `ops/conductor/scrape-gates.yaml` | policy layer above DeG; not a proof language concern |
| Observation labels (observed / inferred / unknown) and confidence | `docs/CLIENT-RE-752.md` §0, `ARTIFACTS.md` | strength lattice, with an explicit cap for unverified external work |
| Structural client tables and CMAP evidence | `docs/CLIENT-STRUCTURAL-EVIDENCE.md` | proposed `table`/`cmap` evidence or capped external certs |
| Packet evidence goals and decoder audit | `docs/audit/PACKET-EVIDENCE-GOALS.json`, `docs/PACKET-DECODER-AUDIT.md` | claim registry + coverage obligations |

This is important: DeG would not be introducing evidence discipline to a project
that lacks it. It would be giving the existing discipline a **uniform logical
form** and a **shareable seal**.

Current state observed while reading the tree (late 2026-11-16):

- Requirements: **2/9 areas, 14/31 checks**, 7/7 verified packages, 49 evidence
  rows downgraded, 0 dropped (`docs/CHECK-STATUS.md`).
- Opcode area: **33/33 observed**, **64/82 enumerated** in the last validated
  snapshot; the layout manifest has 80 layouts and a pending merge would count
  66/82, still failing on the missing candidates
  (`docs/OPCODE-COVERAGE-752.md`).
- Packet decoder: 100 base `(direction, opcode)` keys across 103 rows,
  74,148 frames, split 72 typed / 14 partial / 14 explicit unknown after the
  second gap pass (`docs/PACKET-DECODER-AUDIT.md`).
- Packet evidence goals: 87 goals in 25 categories
  (`docs/audit/PACKET-EVIDENCE-GOALS.json`).
- 7.52 protocol vectors: 11 cipher vectors, 37 frame vectors, 3 stream vectors,
  2 error vectors, plus key-table and temp-key vectors
  (`server/internal/protocol/testdata/vectors/7.52.json`).

---

## 2. The local pilot (already run)

I built a model outside both repositories against the operator's actual client:

```text
/home/kin/.local/share/kazetk/vanilla-client/NexusTK.exe
SHA-256 d6131bf581bf3ff4cf1bd9df4488fb204146fbf801fdb526d63d07cec9adbd45
PE32 i386, image base 0x400000, .text VA 0x401000 / file 0x400 / size 0x20b3bc
```

The model uses DeG's existing primitives only:

- `build ntk` with `load = 0x400C00` and
  `text = 0x401000..0x60B3BC`; for this PE, `.text` file offset is
  `VA - 0x400C00`, so the simple DeG address mapping works for `.text`.
- `dump ntk_file` with `base = 0` for file-relative `.rdata` and patch bytes.
- `scan(...)` for the documented prologues, with `|> unique`.
- `bytes(...)` for the documented dispatch range check, index table, patch
  range, and obfuscated static-key storage.

### What DeG proved

```console
$ deg check /tmp/opencode/ntk-deg/ntk.dg
deg check /tmp/opencode/ntk-deg/ntk.dg
  artifacts   2 (2 verified)
  evidence    7 (7 ok)
  claims      8 sealed, 0 provisional, 0 hypothesis, 0 failed/refuted
  obligations 1 open
  conflicts   0 (0 unresolved)
  threshold   deterministic

claims:
  ✓ P_wndproc                 sealed  deterministic  anchored(wndproc, 0x465EA0)
  ✓ P_mappane                 sealed  deterministic  anchored(mappane_onpacket, 0x507C10)
  ✓ P_userpane                sealed  deterministic  anchored(userpane_onpacket, 0x5A75D0)
  ✓ P_mappane_range           sealed  deterministic  range_check_ok(mappane)
  ✓ P_mappane_index           sealed  deterministic  index_table_ok(mappane_index)
  ✓ P_0x79_outside_mappane    sealed  deterministic  outside_mappane(0x79)
  ✓ P_patch_disable_update    sealed  deterministic  bytes_ok(e_patch, 0x1800AD)
  ✓ P_static_key_storage      sealed  deterministic  bytes_ok(e_static_key_storage, 0x223748)

obligations:
  O_stock_diff  open  stock_diff(ntk, "8dba297c…")

kernel: OK
```

The exact claims:

1. The documented `WndProc` prologue
   `55 8B EC 6A FF 68 27 A8 5F 00` occurs **uniquely** in `.text` at
   `0x465EA0`.
2. The documented `MapPane::OnPacket` prologue
   `55 8B EC 6A FF 68 50 24 60 00` occurs uniquely at `0x507C10`.
3. The documented `UserPane::OnPacket` prologue
   `55 8B EC 6A FF 68 B3 A8 60 00` occurs uniquely at `0x5A75D0`.
4. The MapPane range-check bytes at `0x507C4C` match
   `0F B6 07 83 C0 FD 83 F8 67 0F 87 0B 11 00`.
5. The 104-byte MapPane index table at `0x508E54` matches the documented table
   exactly (including the default `0x32` entries).
6. The specific candidate `0x79` is outside the MapPane range `0x03..0x6A`,
   derived from claim 4. This is one piece of the artifact dossier's argument,
   not the whole "not an opcode" proof.
7. The launch patch at `0x580CAD` is present: the patched bytes
   `C6 85 4F FF FF FF 01` (the stock form is `0F 94 85 4F FF FF FF`).
8. The obfuscated static-key storage `UrkcnItni`
   (`55 72 6B 63 6E 49 74 6E 69`) is present at file offset `0x223748`
   (VA `0x624F48`, `.rdata`).

### What it deliberately did not prove

The client in the repo-adjacent operator path is the **launch-patched** copy
(`d613…`), not the documented stock build (`8dba…`). The pilot leaves this as an
open, non-blocking obligation:

```text
O_stock_diff  open  stock_diff(ntk, "8dba297c…")
```

The project already records exactly this boundary: the four patch ranges
(`0x580CAD`, `0x62D464`, `0x62D498`, `0x580F1A`) do not overlap the cited
ranges, so the cited bytes are *expected* to match stock, but the stock file was
not available to diff (`docs/analysis/opcodes/ARTIFACTS.md` §0). DeG turns that
"inferred" step into a named open obligation instead of a footnote. This is the
single most important reason to use DeG here: it makes the boundary between
observed and assumed **machine-visible** and shareable.

It also does not prove:

- that the dispatch *semantics* of those bytes are what the labels say;
- that the static key is active (`UrkcnItni` is the obfuscated storage; the
  initializer that writes `#`/`7` is separate);
- that the MapPane range check is the only dispatcher relevant to `0x79`
  (UserPane/other tables and capture absence are separate evidence);
- anything about the stock build's bytes.

Those are correct follow-up claims, not failures of the pilot.

### Why the pilot matters

The project already has `tools/opcode/opcode_tool.py client-check` and
`byte-check`, which do overlapping checks. The pilot's value is not a new fact;
it is the **form**:

- every claim is bound to the client SHA-256 and a file offset/VA;
- the evidence is replayed by the kernel, not trusted from a script;
- the derivation and support set are inspectable (`deg explain`);
- the stock-versus-patched assumption is an obligation, not prose;
- the same model can be sealed and diffed across client builds.

---

## 3. Fit matrix

| Area | Fit | Why |
|---|---|---|
| Client identity, PE anchors, prologues, dispatch/cipher table bytes | **High** | DeG already has scan/bytes and a strength lattice; pilot demonstrates it. |
| Protocol known-answer frames/cipher/tail vectors | **High** | Natural `vector` evidence primitive; directly targets the unresolved tail encode/decode ambiguity and the 7.52 acceptance checklist. |
| Opcode claim graph and nine-artifact dossier | **High** | Claims, support, absence, conflicts, and obligations map one-to-one; needs a generic conflict/decision mechanism. |
| Capture-package opcode observations | **High conceptually, high effort** | Package format is already hash-addressed; needs a `package` artifact/evidence adapter and careful redaction. |
| Coverage counts / requirement gates | **Medium** | DeG can reproduce and explain the count, but the locked contract/validator should remain the policy authority. |
| Client structural tables (`ITEM.TBL`, `monster.dna`, CMAP) | **Medium** | Deterministic parsers exist in Go; DeG would need native `table`/`cmap` evidence or an external certificate (which caps at Observational). |
| Mechanics samples / confidence | **High** | DeG's statistical discipline (n, coverage, CI, power, Observational cap) fits the 19-metric area; needs a generic `samples` evidence over datasets. |
| Movement invariants and time-scoped behavior | **Medium** | DeG can express time/scope-limited claims, but the current evidence is JSONL frames, not pcap; needs a frame-series adapter. |
| Cross-profile porting (4.95 / 5.33 / 7.52) | **High** | `deg port` already re-anchors and demotes; needs PE-section-aware builds and a 32-bit client profile. |
| Source-level security/trust-boundary claims | **Low–Medium** | DeG has no Go source analyzer; external test/report certificates are Observational. The project's tests are the better authority. |
| Archive/package integrity | **Medium** | DeG verifies artifacts and can seal a package model, but it does not add a signature; the existing hash chain is already appropriate. |
| Content coverage (NPCs, items, spells, boards) | **Medium** | Depends on the capture/package and table adapters; the value is provenance and gaps, not new extraction. |

---

## 4. Integration design

Do **not** replace the requirements validator. Put DeG above the existing
evidence pipeline as a claim/evidence graph and audit artifact:

```text
                 existing KazeTK pipeline                      DeG layer
client / captures / client tables / vectors
        │
        ├── capture-seal.py ──► verified packages ──┐
        ├── client evidence ──► evidence.json ──────┤
        ├── opcode layouts ──► claims generator ────┤
        └── testdata vectors ──► vector adapter ────┤
                                                    ▼
                                         .dg claims + evidence
                                                    │
                                         deg check / seal / port
                                                    │
                                      report + lock + obligations
                                                    │
                                      human review / validator gate
```

The locked contract (`scrape-gates.yaml`, expected counts, exception ledger)
stays the **policy** authority. DeG answers a different question:

> For each claim, what exactly is the evidence, what is the weakest link, what
> is assumed, what conflicts, and what remains open?

### Proposed adapters (not implemented)

These are the gaps between the current DeG kernel and KazeTK's data:

1. **PE-aware build artifact.** The pilot uses the `.text` bias
   `load = 0x400C00` and a `dump` at `base = 0` for `.rdata`. That is readable
   but fragile. A `pe` build kind that maps sections by name
   (`.text`, `.rdata`, `.data`) would let one model address any section and
   support both 32-bit and 64-bit clients. This is a small, generic kernel
   extension.
2. **`vector` evidence.** Read a known-answer file, replay the declared
   frame/cipher/tail transform, and compare exact bytes. For NexusTK this
   requires a small codec adapter (key table, temp key, 3-stage XOR, tail
   encode/decode, frame assembly). It should be a **native, verified primitive**
   to reach Deterministic; an external Go-test certificate would be capped at
   Observational. The committed 7.52 vector file is the ideal first test.
   **Implemented** in the `deg-nexustk` adapter crate as the `ntk_vector`
   evidence kind (`../src/codec.rs` + `../src/vectors.rs`); see
   `../README.md`.
3. **`package` evidence.** Re-check a verified `kaze.bundle/v1` package: index
   hash, manifest hash, blob hashes, JSONL schema, redaction rules, and
   coverage. Emit bounded facts such as
   `frame(package, direction, opcode, channel, body_len, ts)`,
   `frame_field(...)`, and `coverage(package, window, opcodes)`.
   Byte-level facts can be Deterministic; semantic claims about the protocol
   remain Observational because the capture is an observation.
   **Implemented** in the `deg-nexustk` adapter crate as `ntk_bundle`
   (manifest digest, index pin, evidence file, blob verification;
   `../src/bundle.rs`) and `ntk_frames` (structural frame facts from a
   `frames.jsonl` dataset, Observational, bodies never emitted;
   `../src/frames.rs`); see `../README.md`.
4. **`coverage` claim kind.** A claim over a locked dataset and a set of sealed
   claims: `coverage(opcodes, 82)` returns the covered/missing IDs. This is how
   DeG can reproduce `33/33` or `64/82` without becoming a second expected-count
   authority; it reports the graph, and the validator remains the gate.
5. **Generic conflict and decision.** The nine-artifact dossier is a conflict
   between `opcode(id)` and `artifact(id)` with a human resolution. DeG's
   current conflict resolver only knows uniform-vs-biased, and refutation only
   supports RNG `algo(...)`. A general `contradicts` relation plus a
   hash-pinned/signed `decision` evidence would let the project express:
   - `conflict C : opcode(0x79) vs artifact(0x79) prefer artifact(0x79)`;
   - `decision D : accepted_by("operator", waiver_sha256)`.
   This is the most important language extension for KazeTK.
6. **`samples` evidence.** A generic numeric dataset with grouping, sample
   count, coverage, CI, and power, reusing `stats.rs`. This directly targets the
   19 mechanics metrics and per-mob cadence/damage work.
7. **`table` / `cmap` evidence.** Native parsers for `ITEM.TBL`, `monster.dna`,
   and `CMAP` would move those claims from Observational external evidence to
   Deterministic re-derived facts. The project already has well-tested Go
   parsers; porting the exact checks is feasible but is real work.

---

## 5. Concrete claim models

### 5.1 Client anchors (works today)

The pilot's model, shortened:

```dg
build ntk = binary("/…/NexusTK.exe",
  sha256: "d6131bf5…", arch: x86,
  load: 0x400C00, text: 0x401000..0x60B3BC);

dump ntk_file = dump("/…/NexusTK.exe", sha256: "d6131bf5…", base: 0, build: ntk);

fn wndproc in ntk at 0x465EA0;
fn mappane_onpacket in ntk at 0x507C10;

ev e_wndproc := scan(ntk, ".text", "55 8B EC 6A FF 68 27 A8 5F 00") |> unique;
ev e_mappane_range := bytes(ntk, at: 0x507C4C,
  expect: "0F B6 07 83 C0 FD 83 F8 67 0F 87 0B 11 00");

rule anchored_at:
  anchored(?f, ?a) if fn_addr(?f, ?a) and scan_hit(?e, ?a) and scan_unique(?e);

proof P_wndproc : anchored(wndproc, 0x465EA0) in ntk {
  evidence e_wndproc;
  rules anchored_at;
}

obligation O_stock_diff : stock_diff(ntk, "8dba297c…")
  priority: high;
```

The obligation is the key: a model can be `kernel: OK` while still carrying an
explicit assumption. `deg seal --strict` would refuse to lock it, and
`deg report` would show it.

### 5.2 Protocol vectors (proposed)

The 7.52 vector file already contains exact plaintext/ciphertext/tail/stream
cases. A native `vector` evidence could make claims such as:

```dg
vectorfile v752 = vector("…/testdata/vectors/7.52.json", suite: "7.52",
  sha256: "…");

ev e_cipher := vector(v752, suite: "ciphers", codec: ntk752);
ev e_tail := vector(v752, suite: "streams", codec: ntk752);

proof P_cipher_vectors : cipher_vectors_match(v752) in ntk {
  evidence e_cipher;
  rules ntk752_cipher_suite;
}
```

The unresolved tail issue is tailormade for refutation/conflict: encode the
candidate inverse functions as competing claims, use exact stream vectors to
refute the wrong one, and record the surviving direction/argument roles. That
is a more rigorous version of the manual experiment in `PROTOCOL-752.md` §2.1
and the acceptance checklist in §7.

### 5.3 Opcode claims (implemented by `deg-nexustk generate`)

This section's proposal is now implemented: `deg-nexustk generate` turns the
project's audit artifacts into the claim graph below (see
`../README.md`). The generator is deterministic, never copies project
data, and keeps the strength discipline: table bytes re-read from the client
and the vector-backed opcode proofs seal Deterministic, the artifact claims
are capped Observational, and everything unresolved stays an obligation or a
commented-out human decision.

```dg
// Generated from DISPATCHER-AUDIT.json + opcode-layouts.json + 7.52.json:
// one Deterministic proof per vector-exercised opcode.
proof P_op_0x30 : opcode(0x30) in ntk {
  evidence e_vec;
  rules opcode_from_vector, opcode_from_cipher;
}

// The nine-artifact decision stays a commented template until a human fills
// the decision file and its sha256.
// decision D_0x79 := decision("decisions/79.txt", sha256: "<sha256>",
//   prefer: P_art_79, over: P_op_79, signer: "OPERATOR");
// conflict C_0x79 : P_op_79 vs P_art_79 decision D_0x79 reason "body-field";

// The coverage claim reports the graph; DeG is not the count authority.
claim C_cov : coverage(ds_ops, target: 82) in ntk
  from P_op_00, P_op_02, …;   // one premise per vector-covered id
```

Against the real inputs this lane checks with 46 Deterministic sealed claims
(18 dispatch-table byte proofs + 28 vector opcode proofs), 10 hypotheses
(coverage `28/82` plus the nine capped artifact claims), and 54 open
`observe_opcode` obligations — the boundary between observed and assumed is
machine-visible. The validator remains the policy authority; DeG reports the
graph.

DeG does not decide the 82→73 policy change. It produces a support graph
that says which nine IDs are artifacts, which seven/nine candidates still lack
layouts, and what the human decision was and when.

### 5.4 Mechanics samples (proposed)

```dg
dataset atk := dataset("attack-samples.csv", sha256: "…");
ev e_atk := samples(atk, value: "damage", group: "same_weapon");
claim C_hit_band : mean(e_atk) ~ 42.0 ± 3.0 in b1
  by e_atk require samples >= 200, confidence >= 0.95;
```

This reuses DeG's existing statistical discipline. It is a more honest form
than a YAML placeholder or a single median: the claim names the sample set,
coverage, CI, and whether the test has power to distinguish the proposed band.

### 5.5 Cross-profile porting (proposed/partly works)

```dg
port from v752 to v495 {
  rebase wndproc by structural_similarity(64) min 0.55;
  rebase mappane_onpacket by structural_similarity(64) min 0.55;
}
```

The current `port` supports function/rng targets and structural rebases; with a
PE-aware build kind it would cover client binaries directly. Statistical claims
from captures would go stale and generate revalidation obligations, which is
exactly the project's “no 4.95 constants reachable from 7.52 without evidence”
rule.

---

## 6. What DeG does not solve

Be explicit about the boundary:

1. **It is not a new analysis engine.** No disassembler for 32-bit PE, no
   CMAP/ITEM.TBL/monster.dna parser, no JSONL package reader, no Go source
   analyzer. The pilot uses only bytes/scan. Each adapter above is real work.
2. **It does not replace the requirements validator.** Expected counts,
   source-class rules, waivers, and package credit are policy. DeG can verify
   and explain a count, but it should not become a second contract.
3. **It does not sign human decisions.** The current hash chain protects against
   an agent, not an operator who can rewrite the package and index
   (`docs/CAPTURE-PACKAGES.md` §1.1). A `decision` evidence would need a
   signature or an out-of-band pinned hash; DeG cannot make the policy choice.
4. **It does not make external certificates Deterministic.** The project's
   static snippets are often produced by scripts/objdump; unless the check is a
   native DeG primitive, it is capped at Observational. For KazeTK's
   observed/inferred/unknown labels, this is a useful mapping, but it is not a
   free upgrade.
5. **It does not solve the data/count problem.** The missing map, item, mob,
   NPC, spell, and mechanics evidence is still missing. DeG will make the gap
   explicit and portable; it will not create captures or licensed data.
6. **It has scale limits.** The fact store caps at 250,000 facts and 2,000
   rounds. A package adapter must project per-opcode/per-field facts, not one
   fact per byte or per 168k frame. The 7,977-row structural packages and 82
   opcodes are comfortably in range; a full raw-frame dump is not.
7. **It is a v0.1 prototype.** The kernel's conflict/refutation are narrow,
   there is no aggregate/coverage claim, no PE section model, no signed
   decisions, and no JSONL capture reader. These are the intentional
   extension points, not hidden features.

---

## 7. Recommended pilot sequence

Phases 0–2 are **done/available** in the adapter crate (see
`../README.md`); phases 3–5 remain future work. The commands for the
implemented phases:

```console
# Phase 0 (client identity, PE anchors) and Phase 2 (opcode claim graph):
$ deg-nexustk generate --out /tmp/opencode/ntk-gen \
    --client /home/kin/.local/share/kazetk/vanilla-client/NexusTK.exe \
    --dispatch docs/analysis/opcodes/DISPATCHER-AUDIT.json \
    --layouts  ops/conductor/opcode-layouts.json \
    --artifacts docs/analysis/opcodes/artifacts.json \
    --vectors  server/internal/protocol/testdata/vectors/7.52.json
$ deg-nexustk check /tmp/opencode/ntk-gen/model.dg

# Phase 1 (known-answer vectors) is exercised inside the same generated model;
# the standalone replay cross-check is:
$ NTK_VECTORS=server/internal/protocol/testdata/vectors/7.52.json \
    cargo test --lib -- ntk_real_vectors --ignored

# Operator-local parity crosscheck over all of the above (never in CI):
$ tools/crosscheck.sh
```

### Phase 0 — client identity (done, low effort)

Formalize the existing `client-check`/`byte-check` procedure as a `.dg` model:
client SHA, `.text`/`.rdata` anchors, dispatch range, index table, patch range,
static-key storage. Seal it with the stock-diff obligation. **Value:** one
reviewable artifact that distinguishes observed bytes from the assumed stock
equivalence. This is already demonstrated above, and `deg-nexustk generate`
now emits the PE-mapped build plus the dispatch-table byte checks and anchor
proofs directly from `DISPATCHER-AUDIT.json` and an `--anchors` file.

### Phase 1 — protocol known-answer vectors (done, highest value)

The native vector/codec adapter for the committed 7.52 vectors is the
`ntk_vector` evidence kind: cipher vectors (static and name-table), temp-key
vectors, frame assembly/stream splitting, error cases, and tail encode/decode
on both directions all replay against the real 7.52 file (57 vectors), and the
per-vector facts carry direction and opcode so the generator can turn them
into ground `opcode` claims. **Success criterion met:** `deg check` reproduces
the vector suite exactly; `deg explain` shows which transform/key path each
vector used.

### Phase 2 — opcode claim graph (done for the static lane)

The claim generator from `ops/conductor/opcode-layouts.json` plus the dispatch
audit and artifact dossier exists as `deg-nexustk generate` (see §5.3):
Deterministic for table bytes and vector replay, Observational for
generator-authored interpretation, open obligations for the uncovered ids, and
commented human decisions for the nine artifacts. The capture-package opcode
observations are still future work (`ntk_frames`/`ntk_bundle` read packages,
but the per-package opcode claims are not yet generated). **Success
criterion:** the DeG report names the same covered/missing ids as the layout
manifest and explains each artifact classification as a capped claim plus a
decision template.

### Phase 3 — mechanics samples

Add a generic `samples` evidence over CSV/JSON datasets with grouping, n,
coverage, CI, and power. Model the 19 mechanics metrics and per-mob cadence from
the existing mechanics YAML and capture-derived samples. Statistical claims stay
Observational/provisional; the report names the weakest metric.

### Phase 4 — PE-aware builds and profile porting

Add a PE section-aware build kind and port the client-anchor/vector claims
across 4.95, 5.33, and 7.52. This is where DeG's `port` becomes more than a
nicety: it makes "do not assume 4.95 constants in 7.52" executable.

### Phase 5 — structural tables and maps (optional)

Native `table`/`cmap` evidence for ITEM.TBL, monster.dna, and CMAP. This is
attractive because those are deterministic structural facts, but the Go
parsers already exist; evaluate whether a native port or a capped external
certificate is the better cost/benefit.

---

## 8. Risks and ownership

- **Two sources of truth.** The locked contract/validator owns expected counts,
  source classes, and waivers. DeG must generate its claim set from those
  manifests, not fork them. Define a single review entry point and a comparison
  test that fails if the counts diverge.
- **Duplicate evidence parsing.** `capture-seal.py` already verifies packages
  and re-derives map/packet facts. A DeG package adapter would be a second
  parser; keep it independent for verification, or feed the existing verifier's
  signed output as a certificate. Independence is valuable only if the second
  parser is tested against the same fixtures.
- **Legal and privacy.** The client and raw captures are operator-local. DeG
  models must not commit them, key tables, credentials, or map cell data. Use
  absolute/operator-local paths for local checks and templates in the repo.
  Redaction stays at the capture edge.
- **Performance.** Project facts, not frames. The kernel's 250k-fact cap is
  deliberate; a full 168k-frame session needs aggregation (counts, coverage,
  per-opcode facts) rather than one fact per frame.
- **Human decisions.** The nine-artifact/73-ID decision is a policy call. DeG
  must record it and require a signed/pinned waiver; it must not infer it from
  a heuristic.
- **Naming/ownership.** The project's `TOOLKIT` and validator are the
  established procedures. A DeG integration should extend them, not create a
  parallel lane with a different vocabulary.

---

## 9. Bottom line

**Yes, DeG applies — but as a claim/evidence layer, not a replacement for the
validator.**

The best immediate uses are:

1. **Client identity and static anchors** (demonstrated: 8 Deterministic
   claims, 1 explicit stock-diff obligation).
2. **Protocol known-answer vectors** (self-contained, committed data, directly
   targets the tail/cipher/frame questions).
3. **The opcode/artifact claim graph** (turn the 64/82, nine-artifact, and
   seven-candidate state into support sets, conflicts, and obligations).
4. **Mechanics statistics** (reuse the strength/coverage/CI discipline).
5. **Cross-profile porting** (make the 4.95 → 5.33 → 7.52 rule executable).

The project's existing evidence culture is the hard part, and it is already
there. DeG's contribution is to make the **strength, support, assumptions,
conflicts, and gaps** uniform and machine-checkable, and to produce a seal that a
reviewer can diff. Start with Phase 0/1; do not attempt a full replacement of
the requirements pipeline.

---

### Appendix: relevant KazeTK files

| Topic | Path |
|---|---|
| Project and clean-room scope | `README.md` |
| Architecture and trust boundaries | `docs/ARCHITECTURE.md` |
| Capture schema and packages | `docs/CAPTURE-SCHEMA.md`, `docs/CAPTURE-PACKAGES.md`, `scripts/capture-seal.py` |
| Requirements contract and status | `docs/VANILLA-REQUIREMENTS.md`, `docs/CHECK-STATUS.md`, `ops/conductor/scrape-gates.yaml` |
| Protocol and cipher notes | `docs/PROTOCOL-752.md`, `server/internal/protocol/README.md`, `server/internal/protocol/cipher.go` |
| Known-answer vectors | `server/internal/protocol/testdata/vectors/7.52.json`, `vectors_test.go`, `cipher_test.go` |
| Opcode coverage and dossier | `docs/OPCODE-COVERAGE-752.md`, `docs/OPCODE-ARTIFACT-DOSSIER-752.md`, `docs/analysis/opcodes/ARTIFACTS.md`, `ops/conductor/opcode-layouts.json` |
| Client identity and dispatch toolkit | `docs/analysis/opcodes/TOOLKIT.md`, `docs/analysis/opcodes/TOOLKIT.json`, `docs/analysis/opcodes/DISPATCHER-AUDIT.md` |
| Client structural tables/maps | `docs/CLIENT-STRUCTURAL-EVIDENCE.md` |
| Packet workbench/decoder audit | `docs/PACKET-DECODER-AUDIT.md`, `server/internal/packetworkbench/testdata/observed-shapes.json` |
| Packet evidence goals | `docs/audit/PACKET-EVIDENCE-GOALS.json`, `docs/schemas/kaze.packet-evidence-goals.v1.schema.json` |
| Movement evidence | `docs/MOVEMENT-INVARIANTS.md`, `docs/MOVEMENT-FREEZE-RE.md` |
| Client patch ranges | `client/launch/README.md`, `client/launch/patch_client.py` |

### Appendix: pilot commands

The pilot model is intentionally not committed. To reproduce it locally, create
a model referencing the operator's client by absolute path and run:

```bash
deg check /tmp/opencode/ntk-deg/ntk.dg
deg seal  /tmp/opencode/ntk-deg/ntk.dg --out /tmp/opencode/ntk-deg/ntk.lock.json
deg explain /tmp/opencode/ntk-deg/ntk.dg P_wndproc
deg report /tmp/opencode/ntk-deg/ntk.dg
```

Do not commit the client, its derived `.text`/`.rdata` extracts, key tables, or
capture bytes. The public DeG repository contains only the language, tooling,
and synthetic fixtures.
