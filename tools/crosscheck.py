#!/usr/bin/env python3
"""Operator-local crosscheck between the KazeTK audit artifacts and DeG.

This tool is NEVER run in CI and never copies anything from the KazeTK
repository: it reads the project's analysis files read-only, runs the
`deg-nexustk generate` lane into a fresh output directory, checks the
generated model, and prints a parity table (coverage numbers, missing ids,
the artifact ids) next to the ids the layouts/artifacts files themselves
list. The parity output is informational; the exit code reflects only the
DeG check itself (0 when `check --json` reported ok=true).

Usage:
  crosscheck.py --repo /home/kin/nexustk-emulator \
      --client /path/to/NexusTK.exe \
      --deg-nexustk /path/to/deg-nexustk \
      [--out /tmp/opencode/ntk-crosscheck]

`--out` is optional: when omitted, the generated model lands in a fresh
temporary directory (tempfile.mkdtemp), so reruns never collide. When
`--out` is given it must be absent or empty; an existing non-empty directory
is refused with a clear message (the script never deletes anything).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def fail(msg: str) -> None:
    print(f"crosscheck: {msg}", file=sys.stderr)
    sys.exit(2)


def read_json(path: Path, what: str) -> dict | list:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        fail(f"cannot read {what} {path}: {e}")
    return {}


def collect_ids(node) -> set[int]:
    """Numeric values under object keys named `opcode` or `id` (mirrors the
    generator's own scan of the layouts file)."""
    ids: set[int] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("opcode", "id") and isinstance(value, int):
                ids.add(value)
            elif isinstance(value, (dict, list)):
                ids |= collect_ids(value)
    elif isinstance(node, list):
        for item in node:
            ids |= collect_ids(item)
    return ids


def artifact_ids(artifacts_path: Path) -> list[int]:
    doc = read_json(artifacts_path, "artifacts file")
    ids: list[int] = []
    if isinstance(doc, dict) and isinstance(doc.get("artifacts"), list):
        for entry in doc["artifacts"]:
            ident = entry.get("opcode", entry.get("id"))
            if isinstance(ident, int):
                ids.append(ident)
    if not ids and isinstance(doc, dict):
        scope = doc.get("scope")
        if isinstance(scope, dict) and isinstance(scope.get("ids"), list):
            ids = [i for i in scope["ids"] if isinstance(i, int)]
    return ids


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True, type=Path,
                    help="the read-only /home/kin/nexustk-emulator checkout")
    ap.add_argument("--client", required=True, type=Path,
                    help="operator-local NexusTK.exe")
    ap.add_argument("--deg-nexustk", required=True, type=Path,
                    help="path to the deg-nexustk binary")
    ap.add_argument("--out", type=Path,
                    help="output directory (optional; must be absent or "
                         "empty — defaults to a fresh temporary directory)")
    args = ap.parse_args()

    dispatch = args.repo / "docs/analysis/opcodes/DISPATCHER-AUDIT.json"
    layouts = args.repo / "ops/conductor/opcode-layouts.json"
    artifacts = args.repo / "docs/analysis/opcodes/artifacts.json"
    vectors = args.repo / "server/internal/protocol/testdata/vectors/7.52.json"
    for p in (dispatch, layouts, artifacts, vectors):
        if not p.is_file():
            fail(f"expected input missing in --repo: {p}")

    # The output directory: a fresh temporary directory by default (reruns
    # never collide); an explicit --out must be absent or empty. Nothing is
    # ever deleted here — an occupied --out is refused, not cleared.
    if args.out is not None:
        if args.out.exists():
            if not args.out.is_dir():
                fail(f"--out {args.out} exists and is not a directory")
            if any(args.out.iterdir()):
                fail(
                    f"--out {args.out} already exists and is not empty; "
                    "pass a fresh path or delete the directory first "
                    "(the script never deletes anything)"
                )
        args.out.mkdir(parents=True, exist_ok=True)
    else:
        args.out = Path(tempfile.mkdtemp(prefix="ntk-crosscheck-"))

    if not args.deg_nexustk.exists():
        # Allow a bare name resolved through PATH.
        pass
    bin_cmd = str(args.deg_nexustk)

    gen = subprocess.run(
        [
            bin_cmd, "generate",
            "--client", str(args.client),
            "--dispatch", str(dispatch),
            "--layouts", str(layouts),
            "--artifacts", str(artifacts),
            "--vectors", str(vectors),
            "--out", str(args.out),
        ],
        capture_output=True, text=True,
    )
    if gen.returncode != 0:
        print(gen.stdout, file=sys.stderr)
        print(gen.stderr, file=sys.stderr)
        fail("generate failed")

    check = subprocess.run(
        [bin_cmd, "check", str(args.out / "model.dg"), "--json"],
        capture_output=True, text=True,
    )
    if check.returncode != 0:
        print(check.stdout, file=sys.stderr)
        print(check.stderr, file=sys.stderr)
        fail("check failed (exit != 0)")
    report = json.loads(check.stdout)
    if not report.get("ok"):
        fail("check reported ok=false")

    # Parity table: DeG's reported numbers next to the project files' own ids.
    cov = next((c for c in report.get("claims", [])
                if c.get("name") == "C_cov"), None)
    layout_ids = collect_ids(read_json(layouts, "layouts file"))
    art_ids = artifact_ids(artifacts)

    print("crosscheck parity table (informational; the DeG check itself passed)")
    print("=" * 78)
    if cov is None:
        print("coverage claim: none generated (no client build?)")
    else:
        missing = sorted(int(m) for m in cov.get("missing", []))
        missing_str = ", ".join(hex(i) for i in missing) if missing else "none"
        print(f"coverage: {cov['covered']}/{cov['target']} covered")
        print(f"missing (from the layouts universe): {missing_str}")
        print(f"layouts file ids: {len(layout_ids)} distinct")
    print(f"artifact ids ({len(art_ids)}): "
          + ", ".join(f"0x{i:02x}" for i in art_ids))
    art_overlap = sorted(set(art_ids) & layout_ids)
    print(f"artifact ids present in the layouts universe: "
          + (", ".join(hex(i) for i in art_overlap) if art_overlap else "none"))
    sealed = [c["name"] for c in report.get("claims", [])
              if c.get("status") == "sealed"]
    hyp = [c["name"] for c in report.get("claims", [])
           if c.get("status") == "hypothesis"]
    obs = [o["name"] for o in report.get("obligations", [])]
    print(f"sealed claims: {len(sealed)}; hypotheses: {len(hyp)}; "
          f"obligations: {len(obs)}")
    print("=" * 78)

    # Clean up nothing: the generated tree is the operator's artifact to
    # review (a fresh temp directory when --out was omitted). The project
    # repo was only read.
    print(f"generated model kept at {args.out / 'model.dg'}")
    if args.out.name.startswith("ntk-crosscheck-"):
        print("(--out omitted: this is a fresh temporary directory; "
              "pass --out to keep it)")
    sys.exit(0)


if __name__ == "__main__":
    main()
