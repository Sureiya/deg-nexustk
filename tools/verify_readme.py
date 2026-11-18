#!/usr/bin/env python3
"""Verify that the synthetic "See it work" excerpts in README.md match the binary.

The README's "See it work — synthetic" section (and the matching section of
`docs/demo.md`) shows verbatim `deg-nexustk` output. This script re-runs each
pasted command against the built binary and diffs the excerpts byte-for-byte.
The committed seal lock is also re-derived and compared. The "See it work —
against the real artifacts" section depends on operator-local files this
repository never commits, so it sits after a `<!-- verify-skip -->` marker
and is never checked here.

Usage (from the repository root, after `cargo build`):

    python3 tools/verify_readme.py
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The README's seal excerpt writes to this exact path so the regenerated
# stdout line matches the pasted one.
SEAL_OUT = "/tmp/show.lock.json"


def binary():
    for candidate in (
        os.path.join(ROOT, "target", "debug", "deg-nexustk"),
        os.path.join(ROOT, "target", "release", "deg-nexustk"),
    ):
        if os.path.exists(candidate):
            return candidate
    sys.exit("error: no deg-nexustk binary under target/; run `cargo build` first")


def run(args, cwd=ROOT):
    return subprocess.run(
        [binary()] + args, cwd=cwd, capture_output=True, text=True, check=True
    ).stdout


def read_blocks(path, start_marker, end_marker):
    """Fenced code blocks between two headings of a doc, in order."""
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        text = fh.read()
    start = text.index(start_marker)
    end = text.index(end_marker)
    section = text[start:end]
    # When present, everything after this marker is operator-local and never
    # verified (README.md uses it; docs/demo.md already ends at a heading).
    marker = "<!-- verify-skip -->"
    if marker in section:
        section = section[: section.index(marker)]
    blocks = []
    for match in re.finditer(
        r"^(`{3,4})(\w+)?\n(.*?)^\1[ \t]*$", section, re.M | re.S
    ):
        blocks.append((match.group(2), match.group(3).rstrip("\n")))
    return blocks


def main():
    fails = []

    def check(name, got, want):
        if got.rstrip("\n") != want.rstrip("\n"):
            fails.append(name)
            import difflib

            print(f"--- FAIL: {name} ---")
            for line in difflib.unified_diff(
                want.splitlines(), got.splitlines(), "want", "got", lineterm=""
            ):
                print(line)
        else:
            print(f"ok: {name}")

    blocks = read_blocks(
        "README.md", "## See it work", "## Why this exists"
    )
    demo_blocks = read_blocks(
        "docs/demo.md", "## 2. Synthetic fixtures", "## 3. Real artifacts"
    )
    langs = [lang for lang, _ in blocks]
    assert langs == ["console", "console", "console", "console", "json"], langs
    demo_langs = [lang for lang, _ in demo_blocks]
    assert demo_langs == langs, demo_langs

    def block_body(block):
        # Drop the leading `$ <command>` prompt line, when present.
        lines = block.splitlines()
        if lines and lines[0].startswith("$ "):
            lines = lines[1:]
        return "\n".join(lines)

    commands = [
        ("check synthetic model", ["check", "examples/synthetic/model.dg"]),
        (
            "explain --mermaid",
            [
                "explain",
                "examples/synthetic/model.dg",
                "P_vectors",
                "--mermaid",
            ],
        ),
        ("extensions", ["extensions"]),
        (
            "seal stdout",
            ["seal", "examples/synthetic/model.dg", "--out", SEAL_OUT],
        ),
    ]
    for (name, argv), block, demo_block in zip(commands, blocks[:4], demo_blocks[:4]):
        want = run(argv)
        check(f"{name} (README.md)", block_body(block[1]), want)
        check(f"{name} (docs/demo.md)", block_body(demo_block[1]), want)

    # 5. lock excerpt: a fresh seal must first match the committed lock
    # byte-for-byte, then the excerpt's names/values must match the lock
    # (the README.md and docs/demo.md excerpts must agree with each other).
    committed_path = os.path.join(ROOT, "examples", "synthetic", "model.lock.json")
    with open(committed_path, encoding="utf-8") as fh:
        committed = fh.read()
    with open(SEAL_OUT, encoding="utf-8") as fh:
        regenerated = fh.read()
    if committed != regenerated:
        fails.append("committed model.lock.json")
        print("--- FAIL: committed model.lock.json differs from a fresh seal ---")
    else:
        print("ok: committed model.lock.json reproduces a fresh seal")

    lines = blocks[4][1].splitlines()
    demo_lines = demo_blocks[4][1].splitlines()
    if lines != demo_lines:
        fails.append("lock JSON excerpt (docs/demo.md)")
        print("--- FAIL: lock JSON excerpt differs between README.md and docs/demo.md ---")
    else:
        print("ok: lock JSON excerpt agrees between README.md and docs/demo.md")
    hyps_line = next(l for l in lines if '"hypotheses"' in l)
    sealed_line = next(l for l in lines if '"sealed"' in l)
    obls_line = next(l for l in lines if '"obligations"' in l)

    lock = json.loads(regenerated)

    def names(line):
        return re.findall(r'"([A-Za-z0-9_.]+)"', line.split(":", 1)[1])

    ok = True
    ok &= lock["artifact_count"] == 5
    ok &= lock["model"] == "examples/synthetic/model.dg"
    ok &= lock["deg_version"] == "0.1.0"
    ok &= lock["seal_threshold"] == "deterministic"
    ok &= names(sealed_line) == [s["name"] for s in lock["sealed"]]
    ok &= names(hyps_line) == [h["name"] for h in lock["hypotheses"]]
    ok &= names(obls_line) == [o["name"] for o in lock["obligations"]]
    ok &= any('"artifact_count": 5' in l for l in lines)
    ok &= any('"model": "examples/synthetic/model.dg"' in l for l in lines)
    ok &= any('"deg_version": "0.1.0"' in l for l in lines)
    ok &= any('"seal_threshold": "deterministic"' in l for l in lines)
    if not ok:
        fails.append("lock JSON excerpt")
        print("--- FAIL: lock JSON excerpt ---")
    else:
        print("ok: lock JSON excerpt")

    if fails:
        print(f"\n{len(fails)} check(s) failed")
        sys.exit(1)
    print("\nall synthetic excerpts match the binary")


if __name__ == "__main__":
    main()
