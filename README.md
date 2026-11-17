# deg-nexustk — the NexusTK 7.52 adapter for DeG

`deg-nexustk` is a standalone crate that consumes the [DeG proof
checker](https://github.com/Sureiya/deg) as a library (git dependency, `main`
branch). It compiles three reviewed evidence extensions into a second trusted
binary (`deg-nexustk`) that extends the kernel with NexusTK-specific checks,
and it adds the `generate` lane that turns the project's audit artifacts into
a checked model. The core `deg` binary is unchanged and registers none of
them: a model that names `ntk_vector` under the core binary fails loudly with

```text
evidence kind `ntk_vector` is not registered; registered: [...]
```

while `deg-nexustk extensions` lists exactly `ntk_bundle`, `ntk_frames`,
`ntk_vector`.

Everything here is implemented from the documented 7.52 algorithms (key-table
MD5 chain, temp key, per-direction tail bytes, the self-inverse 3-stage XOR
body transform, `AA len(u16BE) op [inc] body [tail]` framing, and the
documented cipher policy). No file, vector value, key-table prefix, or fixture
was copied from the KazeTK project: the committed synthetic fixtures are
generated in-repo by an independent Python implementation
(`tools/gen_fixtures.py`), so they cross-check this code instead of
echoing it.

## Evidence kinds

### `ntk_vector(ds_name, [suite: ...])` — Deterministic

Replays a known-answer vector file (declared as a content-addressed `dataset`)
and re-derives every answer from the documented algorithm:

- `keytables`: the 1024-byte MD5-chain table for the declared identity has the
  declared length/prefix, is ASCII hex, and is deterministic;
- `tempkeys`: `KeyTable(identity).TempKey(b8, w16)` equals the declared key;
- `ciphers`: the per-frame key comes from the declared identity (empty = the
  static key, non-empty = the name table via the decoded tail); the produced
  ciphertext matches the full value, or the declared `ciphertext_len` /
  `ciphertext_sha256` / `ciphertext_prefix`; the transform round-trips;
- `frames`: the wire bytes (`AA/len/opcode/inc/body/tail`; raw layouts carry
  no tail, and plain/raw frames carry the body verbatim) are reconstructed and
  compared byte-for-byte; the declared `raw`/`plaintext_body` flags must agree
  with the documented layout and policy;
- `streams`: the wire is split into frames, bodies decrypted, and the parsed
  list (opcode/increment/plaintext/tail/raw) plus the consumed byte count are
  compared;
- `errors`: the codec must reject the wire (any framing error class); for
  body-length vectors the encoder must reject the oversized frame.

`suite:` is one of `keytables`, `tempkeys`, `ciphers`, `frames`, `streams`,
`errors`, or `all` (the default). The first mismatch fails the evidence with
the suite name, the vector name, and the expected vs actual hex (bounded: large
bodies are never dumped whole). On success the facts are
`vector_suite_ok(ev, suite)`, `vector_count(ev, suite, n)`, and one of
`keytable_ok(ev, name)` / `tempkey_ok(ev, name)` /
`cipher_vector_ok(ev, name, dir, opcode)` /
`frame_vector_ok(ev, name, dir, opcode)` /
`stream_vector_ok(ev, name, dir)` / `error_vector_ok(ev, name)` per vector:
cipher and frame facts carry the vector's declared direction (`c2s`/`s2c`, `""`
when absent) and opcode, stream facts carry the direction, and the key-table,
temp-key, and error facts stay 2-ary.

### `ntk_frames(ds_name, [max_frames: n])` — Observational

Reads a `frames.jsonl` capture dataset (one JSON object per line) and emits
**structural facts only**: `frame(ev, dir, op, channel, body_len, ts)` where
`dir` is `in`/`out`, `op` is the integer opcode (0 when absent), `channel` is a
symbol (empty when absent), `body_len` is the declared body length
(`bodyDeclaredLen`, else the captured byte count `bodyHexCaptured`, else the
hex-char count of `bodyHex`; 0 when none is present — real captures truncate
`bodyHex` with a `…<N>` marker), and `ts` is the capture timestamp in
microseconds (0 when absent; the schema records epoch milliseconds). Rows
whose `event` field exists and is not `"frame"` (connect/close/logger
bookkeeping) are skipped, as are lines that are not JSON objects; both are
counted in a detail. `frame_count(ev, n)` is emitted, and `max_frames:` fails
the evidence when exceeded.

Bodies are **never** emitted into facts or details; the outcome records the
redaction note. The strength is Observational: the dataset is a
capture-derived observation, not something this evaluator re-derives from
verified bytes.

### `ntk_bundle(manifest_ds, bundle_id, [index_ds: name])` — Deterministic

Verifies the `kaze.bundle/v1` layout documented for the capture pipeline:

1. the manifest is JSON, and the SHA-256 of its canonical form (sorted keys,
   compact `,`/`:` separators, non-ASCII raw) with **both** the `seal` and
   `verify` keys removed equals the reference digest — otherwise
   "manifest verify digest mismatch";
2. when `index_ds` is declared, the index must contain a package entry for
   `bundle_id` whose `manifest_sha256` (the raw manifest bytes) and
   `seal_sha256` (the reference digest) match — without an index the hash
   chain is unpinned and a detail says so;
3. the manifest's `evidence` entry names a file next to the manifest whose
   SHA-256 matches;
4. the manifest's `files` entries (when present) each name a file next to
   the manifest whose SHA-256 matches;
5. every `blobs` entry resolves to `blobs/sha256/<aa>/<bb>/<sha256>`
   relative to the manifest directory (with `<aa>`/`<bb>` the digest's first
   bytes), the file exists, and its content hash equals the name.

Two schema generations are accepted. The **live** manifests carry
`seal: {algorithm, sha256}`, a `bundles` index array, and blob entries that
are objects with `sha256`/`kind`/`bytes`/`source_ref` and no `path` (the
canonical path is derived from the digest). The **documented** schema
describes `verify: {algorithm, sha256}`, a `packages` index array, and blob
entries that carry their `path` directly. Both are accepted — the verifier
errors only when neither `seal.sha256` nor `verify.sha256` exists, and the
reference digest always drops both keys. When a blob entry carries both
`path` and `sha256`, they must agree.

Paths resolve relative to the manifest dataset's file location
(`artifacts.items[manifest_ds].resolved_path.parent()`); blob paths and
`files` paths may not escape the bundle directory. Unknown/absent optional
fields are tolerated and noted. Facts: `bundle_verified(ev, bundle_id,
manifest_sha)`, `bundle_entries(ev, n)`, `bundle_blobs(ev, n)`,
`bundle_evidence_ok(ev, path)`, and `blob_ok(ev, index, sha)` per blob.

## Trust model and strength rules

The adapter follows `docs/extensions.md` exactly. The three evaluators are
compiled into the trusted `deg-nexustk` binary, are bound to verified
(content-addressed) datasets, and assign strength by the same invariant as the
core primitives:

- `ntk_vector` and `ntk_bundle` **re-derive** their facts from verified bytes
  (the codec replay and the hash chain), so they are Deterministic;
- `ntk_frames` admits capture-derived observations, so it is capped at
  Observational;
- nothing here reaches Exact.

The compiled-in code is the extension of the trusted kernel: review it like a
change to `evidence.rs`. A binary with extensions has a larger trusted surface
than the core binary, which is why `deg extensions` exists and why the core
binary registers nothing.

**Redaction:** packet bodies, key tables, temp keys, character names, and any
credential material are never emitted into facts or details. Facts carry
structure (opcodes, lengths, timestamps, counts, content hashes) only. Error
messages show bounded hex previews, never whole bodies.

## Usage

```console
$ cargo run -q -- extensions
ntk_bundle
ntk_frames
ntk_vector

$ cargo run -q -- check examples/synthetic/model.dg
$ cargo run -q -- explain examples/synthetic/model.dg P_vectors
```

The synthetic model declares the generated fixtures (`vectors-synthetic.json`,
`frames-synthetic.jsonl`, the `bundle/` layout, and a synthetic build image)
with real SHA-256 values, then proves the vector replay, a frame fact, and the
bundle verification. The first two claims seal at Deterministic; the frames
proof stays an Observational hypothesis by construction. Regenerate the
fixtures (and `model.dg`) with:

```console
$ python3 tools/gen_fixtures.py
```

The generator is deterministic and idempotent, so a regenerated tree must
match the committed one exactly.

## `generate` — from audit artifacts to a checked model

`deg-nexustk generate` converts the project's audit artifacts into a
deterministic `.dg` model plus content-addressed copies of the tabular inputs,
decision templates, and a provenance README. It is part of the adapter binary
itself, and everything else on the command line still falls through to the
core `deg` CLI unchanged.

```console
$ deg-nexustk generate --out <dir> \
    [--client <exe>] [--client-sha <hex>] \
    [--vectors <7.52.json>] \
    [--layouts <opcode-layouts.json>] \
    [--dispatch <DISPATCHER-AUDIT.json>] \
    [--artifacts <opcode-artifacts.json>] \
    [--anchors <anchors.json>] \
    [--target <n>] [--port-to <client2>]
```

The generator writes only inside `--out` (which must not exist yet or be an
empty directory). Inputs are read, never modified, and nothing from them is
copied into this repository.

What each input produces:

- `--client`: the `build ntk = binary(…, format: pe)` declaration. The digest
  is `--client-sha` when given (checked against the file) or computed; the
  `arch:` is decided by parsing the PE (`x86`/`x86_64`). Without a client the
  build declaration is a commented placeholder and all client-backed evidence
  and proofs are skipped.
- `--vectors`: a byte-exact copy `vectors.json`, `dataset ds_vec`, and
  `ev e_vec := ntk_vector(ds_vec, suite: "all")`. The rules
  `opcode_from_vector`/`opcode_from_cipher` turn the per-vector facts into
  ground `opcode(?op)` facts, and one proof `P_op_<hex>` is emitted per opcode
  the vectors exercise. These seal at Deterministic.
- `--dispatch`: a generated `table-cases.csv` (one `index` and one `case` row
  per table with the audit's VAs and file offsets) parsed as `table` evidence,
  plus one `bytes` evidence per row re-reading the declared table bytes from
  the client. `table_va` assignments are derived from the matching bytes
  evidence and feed the shared `table_bytes_ok` rule, so each
  `P_<table>_<kind>` proof is kernel-replayed and seals at Deterministic.
- `--layouts`: `opcodes.txt` with every numeric opcode id mentioned anywhere
  in the file (deduplicated, decimal), `dataset ds_ops`, an
  `obligation O_observe_<hex> : observe_opcode(<id>) priority: high;` per id
  without a vector proof, and a coverage claim
  `claim C_cov : coverage(ds_ops, target: <n>) in ntk from <vector proofs>;`
  (target defaults to the distinct id count). When no vector proofs exist an
  `O_coverage` obligation is emitted instead.
- `--artifacts`: `artifacts.csv` (id + role rows from the manifest), a capped
  rule per id (`rule art_<hex> cap observational: artifact(<id>) if
  row(e_art, <idx>, ?cells) and contains(?cells, "<role>");`), and a proof
  `P_art_<hex>` that stays an Observational **hypothesis** by construction —
  the CSV content is the project's analysis, not a kernel-replayed fact. Each
  id also gets a decision template `decisions/<hex>.txt` and a commented-out
  `decision`/`conflict` pair naming the real `P_op_<hex>`/`P_art_<hex>`
  claims. The template uses the claim-name form the decision declaration
  needs — `prefer: P_art_<hex>` / `over: P_op_<hex>` / `signer:
  OPERATOR-PENDING` / `reason: <role>` / `note: P_op_<hex> needs its own
  evidence first (see the commented block in model.dg)` — and a human fills
  the file, records its sha256, and uncomments the two lines.
- `--anchors`: a small JSON array of
  `{"name", "va", "bytes", "section"}` entries. Each becomes
  `fn <name> in ntk at <va>;`, a unique `scan` evidence, and a proof
  `P_<name> : anchored(<name>, <va>)` via the `anchored_at` rule — the
  standard DeG anchor pattern, sealing at Deterministic when the prologue is
  unique.
- `--port-to <client2>`: a commented `port from ntk to ntk2 { … }` template
  with one `rebase` line per anchor.

Strength discipline: only kernel-replayed facts (bytes, scans, dataset
parses, the vector replay) reach Deterministic; generator-authored
interpretation is capped Observational (the artifact rules) or left open as
obligations and commented-out decisions; nothing reaches Exact. The generated
`README.md` records the provenance and the exact check/seal commands.

## Crosscheck tooling (operator-local, never in CI)

`tools/crosscheck.sh` (wrapping `crosscheck.py`) runs the generate
lane against the **real** project artifacts — read-only from the checkout at
`/home/kin/nexustk-emulator`:

- `docs/analysis/opcodes/DISPATCHER-AUDIT.json`
- `ops/conductor/opcode-layouts.json`
- `docs/analysis/opcodes/artifacts.json`
- `server/internal/protocol/testdata/vectors/7.52.json`

plus the operator-local client binary, then runs `check --json` on the
generated model and prints a parity table (covered/target, the missing ids,
the nine artifact ids next to the ids the project files list, and the
sealed/hypothesis/obligation counts). The parity table is informational; the
exit code reflects only the DeG check itself. No project data is copied
anywhere: the files are read in place, and the generated model lands in a
fresh temporary directory by default (safe to rerun), or in `--out`
(`KZTK_OUT` in the wrapper) to keep it. An existing non-empty `--out` is
refused with a clear message — the script never deletes anything.

```console
$ tools/crosscheck.sh
```

This lane is operator-local by design: it never runs in CI, and it is
committed as tooling only, never with project data.

## Cross-checking against real vectors and packages (never in CI)

The adapter's unit suite is synthetic. Two `#[ignore]`d tests replay real
operator-local material when it is pointed at by environment variables.

Known-answer vectors (`NTK_VECTORS`):

```console
$ NTK_VECTORS=/path/to/7.52.json \
    cargo test --lib -- ntk_real_vectors --ignored
```

A sealed `kaze.bundle/v1` package (`NTK_BUNDLE` = the bundle directory,
`NTK_BUNDLE_INDEX` = its capture index):

```console
$ NTK_BUNDLE=/tmp/opencode/captures/sealed/bundles/bnd_board_empty_5 \
  NTK_BUNDLE_INDEX=/tmp/opencode/captures/sealed/index.json \
    cargo test --lib -- ntk_real_bundle --ignored
```

The test writes a throwaway model (absolute paths, hashes computed in the
test) and runs the full library pipeline (parse → index → artifact load →
check), asserting the evidence passes with the index pin. The reference files
are operator-local and are never committed, copied, or required by CI; this
lane verified the vector replay against the real 7.52 file (all 57 vectors:
3 key tables, 1 temp key, 11 ciphers, 37 frames, 3 streams, 2 errors) and the
bundle verifier against all seven operator-local sealed packages before
merging.

## Commands that must pass

```console
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo run -q -- check examples/synthetic/model.dg
```
