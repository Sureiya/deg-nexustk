#!/usr/bin/env python3
"""Generate the deterministic synthetic NexusTK adapter fixtures (deg-nexustk).

Everything here is synthetic and generated from the documented 7.52 algorithms
(md5 key-table chain, temp key, per-direction tails, the 3-stage XOR body
transform, and the AA/len/opcode/inc/body/tail framing) with the adapter's own
identities and keys. No value is copied from the KazeTK project: the point of
the generator is that an independent implementation derives the same bytes the
Rust codec must reproduce, so the committed fixtures cross-check the codec.

Outputs (all committed, all deterministic; the script is idempotent):

    examples/synthetic/
        client-synthetic.bin      synthetic build image for model anchoring
        vectors-synthetic.json    known-answer vectors for `ntk_vector`
        frames-synthetic.jsonl    frame samples for `ntk_frames`
        bundle/                   a valid `kaze.bundle/v1` layout + index
        model.dg                  the model (with real sha256 values inlined)
        client-syn.exe            a synthetic PE32 for the generate lane
        dispatch-synthetic.json   one dispatcher table (bytes inside the PE)
        layouts-synthetic.json    opcode-layouts shape (3 covered, 2 not)
        artifacts-synthetic.json  opcode-artifacts shape (one artifact id)
        anchors-synthetic.json    one unique prologue anchor
    tests/gen_data/mod.rs         hand-computed codec test constants

Run from the repository root:

    python3 tools/gen_fixtures.py
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SYN = ROOT / "examples" / "synthetic"
BUNDLE = SYN / "bundle"

STATIC_KEY_752 = bytes([0x55, 0x72, 0x6B, 0x23, 0x6E, 0x49, 0x37, 0x6E, 0x69])

# Adapter-owned identities and tail parameters (never the project's).
IDENTITY_A = "deg-vector-a"
B8_A = 0xAB
W16_A = 0xBEEF
B8_B = 0xDE
W16_B = 0xCAFE

BUNDLE_ID = "bnd_deg_synthetic_752"


# ---------------------------------------------------------------- algorithms


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def key_table(name: str) -> bytes:
    """The documented name table: md5_hex(name), md5_hex(h0), then
    repeatedly t += md5_hex(t) until 1024 ASCII-hex bytes."""
    h0 = md5_hex(name.encode("utf-8"))
    h1 = md5_hex(h0.encode("ascii"))
    t = bytearray(h1.encode("ascii"))
    while len(t) < 1024:
        t.extend(md5_hex(bytes(t)).encode("ascii"))
    return bytes(t[:1024])


def temp_key(table: bytes, b8: int, w16: int) -> bytes:
    """ecx = b8*b8; for i in 0..9: key[i] = table[(ecx*i + w16) & 0x3FF];
    ecx += 3."""
    ecx = b8 * b8
    key = bytearray()
    for i in range(9):
        key.append(table[(ecx * i + w16) & 0x3FF])
        ecx += 3
    return bytes(key)


def crypt(body: bytes, key: bytes, inc: int) -> bytes:
    """The self-inverse 3-stage XOR core with the 8-bit wrapped group
    counter."""
    out = bytearray(body)
    for i in range(len(out)):
        out[i] ^= key[i % 9]
        g = (i // 9) & 0xFF
        if g != inc:
            out[i] ^= g
        out[i] ^= inc
    return bytes(out)


def encode_tail_c2s(b8: int, w16: int) -> bytes:
    return bytes([(w16 & 0xFF) ^ 0x61, b8 ^ 0x25, (w16 >> 8) ^ 0x23])


def encode_tail_s2c(b8: int, w16: int) -> bytes:
    return bytes([(w16 & 0xFF) ^ 0x24, b8 ^ 0x21, (w16 >> 8) ^ 0x74])


PLAIN_C2S = {0x00, 0x10, 0x48}
PLAIN_S2C = {0x00, 0x03, 0x40, 0x7E}
STATIC_C2S = {
    0x02, 0x03, 0x04, 0x0B, 0x15, 0x26, 0x3A, 0x42, 0x43, 0x4B, 0x50, 0x57,
    0x62, 0x71, 0x73, 0x7B,
}
STATIC_S2C = {0x02, 0x0A, 0x44, 0x5E, 0x60, 0x62, 0x66, 0x6F}


def cipher_kind(channel: str, direction: str, opcode: int) -> str:
    if opcode == 0x00:
        return "plain"
    if opcode == 0x03 and direction == "s2c":
        return "plain"
    if opcode == 0x10:
        return "plain"
    if opcode == 0x7E:
        return "plain"
    if direction == "c2s" and opcode in PLAIN_C2S:
        return "plain"
    if direction == "s2c" and opcode in PLAIN_S2C:
        return "plain"
    if channel == "login":
        return "static"
    if direction == "c2s" and opcode in STATIC_C2S:
        return "static"
    if direction == "s2c" and opcode in STATIC_S2C:
        return "static"
    return "table"


def frame_shape(direction: str, opcode: int) -> tuple[bool, bool, bool]:
    """(has_increment, has_tail, raw) for one opcode/direction."""
    if opcode == 0x00:
        return (False, False, True)
    if opcode == 0x03 and direction == "s2c":
        return (False, False, True)
    if opcode == 0x10:
        return (True, False, True)
    if opcode == 0x7E:
        return (False, False, True)
    return (True, True, False)


def decrypt_tail(direction: str, tail: bytes) -> tuple[int, int]:
    if direction == "c2s":
        return (tail[1] ^ 0x25, ((tail[2] ^ 0x23) << 8) | (tail[0] ^ 0x61))
    return (tail[1] ^ 0x21, ((tail[2] ^ 0x74) << 8) | (tail[0] ^ 0x24))


def encrypt_body(channel: str, direction: str, opcode: int, inc: int,
                 plaintext: bytes, tail: bytes, identity: str) -> bytes:
    kind = cipher_kind(channel, direction, opcode)
    if kind == "plain":
        return plaintext
    if kind == "static":
        return crypt(plaintext, STATIC_KEY_752, inc)
    b8, w16 = decrypt_tail(direction, tail)
    key = temp_key(key_table(identity), b8, w16)
    return crypt(plaintext, key, inc)


def build_wire(channel: str, direction: str, opcode: int, inc: int,
               plaintext: bytes, tail: bytes, identity: str) -> bytes:
    """AA | len(u16 BE) | opcode | [inc] | body | [tail]; len counts
    opcode + inc + body + tail."""
    has_inc, has_tail, _raw = frame_shape(direction, opcode)
    body = encrypt_body(channel, direction, opcode, inc, plaintext, tail,
                        identity)
    n = 1 + (1 if has_inc else 0) + len(body) + (3 if has_tail else 0)
    wire = bytearray([0xAA])
    wire += struct.pack(">H", n)
    wire.append(opcode)
    if has_inc:
        wire.append(inc)
    wire += body
    if has_tail:
        wire += tail
    return bytes(wire)


def pattern_plaintext(n: int) -> bytes:
    """The vector-file convention for large bodies: plain[i] = (i*7+3)&0xff."""
    return bytes((i * 7 + 3) & 0xFF for i in range(n))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hexstr(data: bytes) -> str:
    return data.hex()


# ------------------------------------------------------------------ fixtures


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(value, fh, sort_keys=True, indent=1)
        fh.write("\n")


def make_vectors() -> dict:
    table_a = key_table(IDENTITY_A)
    prefix_a = table_a[:64].decode("ascii")
    temp_a = temp_key(table_a, B8_A, W16_A).decode("ascii")
    tail_s2c_a = encode_tail_s2c(B8_A, W16_A)
    tail_c2s_b = encode_tail_c2s(B8_B, W16_B)

    pt_static = b"deg-login-one"
    pt_policy = b"deg-exit"
    pt_table = b"deg-table"
    ct_static = crypt(pt_static, STATIC_KEY_752, 0)
    ct_policy = crypt(pt_policy, STATIC_KEY_752, 8)
    ct_table = crypt(pt_table, temp_key(table_a, B8_A, W16_A), 3)

    long_pt = pattern_plaintext(2305)
    long_ct = crypt(long_pt, temp_key(table_a, B8_A, W16_A), 1)

    raw_pt = b"deg-v1"
    arrival_pt = bytes([0x09]) + b"deg-vector-a" + b"\x00\x00\x00\x00"

    frame_static_wire = build_wire("login", "c2s", 0x62, 0, pt_static,
                                   tail_c2s_b, "")
    frame_table_wire = build_wire("game", "s2c", 0x0C, 3, pt_table, tail_s2c_a,
                                  IDENTITY_A)
    frame_raw_wire = build_wire("login", "c2s", 0x00, 0, raw_pt, b"", "")
    frame_arrival_wire = build_wire("game", "c2s", 0x10, 0, arrival_pt, b"",
                                    IDENTITY_A)

    welcome_pt = b"deg-welcome"
    stream_pt = b"\x00\x00\x00"
    stream_frames = [
        build_wire("login", "s2c", 0x00, 0, raw_pt, b"", ""),
        build_wire("login", "s2c", 0x7E, 0, welcome_pt, b"", ""),
        build_wire("login", "s2c", 0x02, 2, stream_pt, tail_s2c_a, ""),
    ]
    stream_wire = b"".join(stream_frames)

    return {
        "version": "7.52",
        "stub": False,
        "keytables": [
            {
                "name": "deg-keytable-a",
                "identity": IDENTITY_A,
                "prefix": prefix_a,
                "length": 1024,
            },
        ],
        "tempkeys": [
            {
                "name": "deg-tempkey-a",
                "identity": IDENTITY_A,
                "b8": B8_A,
                "w16": W16_A,
                "key": temp_a,
            },
        ],
        "ciphers": [
            {
                "name": "deg-cipher-static-login",
                "identity": "",
                "channel": "login",
                "direction": "c2s",
                "opcode": 0x62,
                "increment": 0,
                "plaintext": hexstr(pt_static),
                "plaintext_len": 0,
                "plaintext_prefix": "",
                "ciphertext": hexstr(ct_static),
                "ciphertext_sha256": "",
                "ciphertext_prefix": "",
                "ciphertext_len": 0,
                "tail": hexstr(tail_c2s_b),
            },
            {
                "name": "deg-cipher-static-policy",
                "identity": "",
                "channel": "game",
                "direction": "c2s",
                "opcode": 0x0B,
                "increment": 8,
                "plaintext": hexstr(pt_policy),
                "plaintext_len": 0,
                "plaintext_prefix": "",
                "ciphertext": hexstr(ct_policy),
                "ciphertext_sha256": "",
                "ciphertext_prefix": "",
                "ciphertext_len": 0,
                "tail": hexstr(tail_c2s_b),
            },
            {
                "name": "deg-cipher-table",
                "identity": IDENTITY_A,
                "channel": "game",
                "direction": "s2c",
                "opcode": 0x0C,
                "increment": 3,
                "plaintext": hexstr(pt_table),
                "plaintext_len": 0,
                "plaintext_prefix": "",
                "ciphertext": hexstr(ct_table),
                "ciphertext_sha256": "",
                "ciphertext_prefix": "",
                "ciphertext_len": 0,
                "tail": hexstr(tail_s2c_a),
            },
            {
                "name": "deg-cipher-table-long",
                "identity": IDENTITY_A,
                "channel": "game",
                "direction": "s2c",
                "opcode": 0x0C,
                "increment": 1,
                "plaintext": "",
                "plaintext_len": 2305,
                "plaintext_prefix": hexstr(long_pt[:8]),
                "ciphertext": "",
                "ciphertext_sha256": sha256_hex(long_ct),
                "ciphertext_prefix": hexstr(long_ct[:8]),
                "ciphertext_len": 2305,
                "tail": hexstr(tail_s2c_a),
            },
        ],
        "frames": [
            {
                "name": "deg-frame-static-login",
                "channel": "login",
                "direction": "c2s",
                "identity": "",
                "opcode": 0x62,
                "increment": 0,
                "plaintext": hexstr(pt_static),
                "wire": hexstr(frame_static_wire),
                "tail": hexstr(tail_c2s_b),
                "raw": False,
                "plaintext_body": False,
            },
            {
                "name": "deg-frame-table",
                "channel": "game",
                "direction": "s2c",
                "identity": IDENTITY_A,
                "opcode": 0x0C,
                "increment": 3,
                "plaintext": hexstr(pt_table),
                "wire": hexstr(frame_table_wire),
                "tail": hexstr(tail_s2c_a),
                "raw": False,
                "plaintext_body": False,
            },
            {
                "name": "deg-frame-raw-version",
                "channel": "login",
                "direction": "c2s",
                "identity": "",
                "opcode": 0x00,
                "increment": 0,
                "plaintext": hexstr(raw_pt),
                "wire": hexstr(frame_raw_wire),
                "tail": "",
                "raw": True,
                "plaintext_body": True,
            },
            {
                "name": "deg-frame-arrival",
                "channel": "game",
                "direction": "c2s",
                "identity": IDENTITY_A,
                "opcode": 0x10,
                "increment": 0,
                "plaintext": hexstr(arrival_pt),
                "wire": hexstr(frame_arrival_wire),
                "tail": "",
                "raw": True,
                "plaintext_body": True,
            },
        ],
        "streams": [
            {
                "name": "deg-stream-login-mixed",
                "channel": "login",
                "direction": "s2c",
                "identity": "",
                "wire": hexstr(stream_wire),
                "consumed": len(stream_wire),
                "frames": [
                    {
                        "opcode": 0x00,
                        "increment": 0,
                        "plaintext": hexstr(raw_pt),
                        "tail": "",
                        "raw": True,
                    },
                    {
                        "opcode": 0x7E,
                        "increment": 0,
                        "plaintext": hexstr(welcome_pt),
                        "tail": "",
                        "raw": True,
                    },
                    {
                        "opcode": 0x02,
                        "increment": 2,
                        "plaintext": hexstr(stream_pt),
                        "tail": hexstr(tail_s2c_a),
                        "raw": False,
                    },
                ],
            },
        ],
        "errors": [
            {
                "name": "deg-error-bad-magic",
                "channel": "game",
                "direction": "s2c",
                "identity": "",
                "opcode": 0x1E,
                "body_len": 0,
                "wire": "bb00051e00",
                "max_frame_bytes": 0,
                "error": "bad magic",
            },
            {
                "name": "deg-error-over-limit",
                "channel": "game",
                "direction": "s2c",
                "identity": "",
                "opcode": 0x1E,
                "body_len": 0,
                "wire": "aafffd1e",
                "max_frame_bytes": 1024,
                "error": "frame too large",
            },
            {
                "name": "deg-error-write-cap",
                "channel": "game",
                "direction": "s2c",
                "identity": IDENTITY_A,
                "opcode": 0x1E,
                "body_len": 40000,
                "wire": "",
                "max_frame_bytes": 0,
                "error": "frame too large",
            },
        ],
    }


def make_frames_jsonl() -> list[str]:
    """~30 lines of the frames.jsonl schema (structural fields only; bodies,
    when present, are synthetic bytes whose length is what the adapter emits).
    Includes a truncated-body row and a non-frame event row, like real
    captures."""
    lines = []
    ops = [0x00, 0x02, 0x0C, 0x10, 0x11, 0x15, 0x1E, 0x30, 0x62, 0x7E]
    base_ts = 1_794_422_049_000
    for i in range(28):
        obj = {
            "schema": 1,
            "seq": i + 1,
            "dir": "out" if i % 2 == 0 else "in",
            "stage": "wire.send" if i % 2 == 0 else "wire.recv",
            "channel": ["login", "game", "game", "unknown"][i % 4],
            "op": ops[i % len(ops)],
            "event": "frame",
        }
        if i % 3 == 0:
            body = bytes((i * 5 + j) & 0xFF for j in range(4 + i % 5))
            obj["bodyHex"] = hexstr(body)
        if i % 4 != 1:
            obj["ts"] = base_ts + i * 1000
        lines.append(json.dumps(obj, sort_keys=True))
    # A truncated-body frame row: the declared captured length wins over the
    # `…<N>`-suffixed bodyHex.
    lines.append(
        json.dumps(
            {
                "schema": 1,
                "seq": 99,
                "dir": "in",
                "stage": "wire.recv",
                "channel": "game",
                "op": 0x0C,
                "event": "frame",
                "bodyHex": "aabbccdd…<8>",
                "bodyHexTruncated": True,
                "bodyHexCaptured": 8,
                "bodyDeclaredLen": 8,
                "ts": base_ts + 99 * 1000,
            },
            sort_keys=True,
        )
    )
    # A non-frame event row (connection bookkeeping), skipped by the adapter.
    lines.append(
        json.dumps(
            {
                "schema": 1,
                "seq": 100,
                "dir": "event",
                "stage": "connect",
                "channel": "unknown",
                "op": None,
                "event": "connect",
                "ts": base_ts + 100 * 1000,
            },
            sort_keys=True,
        )
    )
    # Two deliberately non-object lines exercise the skip path.
    lines.insert(7, '{"not": "a complete object"')
    lines.insert(21, "this line is not json at all")
    return lines


def make_bundle() -> dict:
    blob1 = {
        "kind": "opcode-layout",
        "opcode": 0x0C,
        "direction": "s2c",
        "channel": "game",
        "fields": "len(u8) name",
        "note": "synthetic deg-nexustk fixture",
    }
    blob2 = {
        "kind": "opcode-layout",
        "opcode": 0x62,
        "direction": "c2s",
        "channel": "login",
        "fields": "profile(u8) sha1(20)",
        "note": "synthetic deg-nexustk fixture",
    }
    blob_bytes = [
        json.dumps(blob1, sort_keys=True).encode("utf-8") + b"\n",
        json.dumps(blob2, sort_keys=True).encode("utf-8") + b"\n",
    ]
    # Live-style blob entries: objects with sha256/kind/bytes/source_ref and
    # no `path` (the canonical content-addressed path is derived from the
    # digest).
    blob_entries = []
    blob_paths = []
    for raw, kind in zip(blob_bytes, ["opcode-layout", "opcode-layout"]):
        digest = sha256_hex(raw)
        blob_entries.append(
            {
                "kind": kind,
                "sha256": digest,
                "bytes": len(raw),
                "source_ref": "local:deg-synthetic-fixture",
            }
        )
        blob_paths.append(f"blobs/sha256/{digest[:2]}/{digest[2:4]}/{digest}")
    evidence = {
        "schema": "kaze.capture-evidence/v1",
        "bundle_id": BUNDLE_ID,
        "packets": [
            {
                "opcode": 0x0C,
                "direction": "s2c",
                "channel": "game",
                "stage": "wire.recv",
                "length": 8,
                "artifact_sha256": sha256_hex(blob_bytes[0]),
            },
            {
                "opcode": 0x62,
                "direction": "c2s",
                "channel": "login",
                "stage": "wire.send",
                "length": 25,
                "artifact_sha256": sha256_hex(blob_bytes[1]),
            },
            {
                "opcode": 0x11,
                "direction": "c2s",
                "channel": "game",
                "stage": "wire.send",
                "length": 2,
            },
            {
                "opcode": 0x1E,
                "direction": "s2c",
                "channel": "game",
                "stage": "wire.recv",
                "length": 4,
            },
            {
                "opcode": 0x00,
                "direction": "c2s",
                "channel": "login",
                "stage": "wire.send",
                "length": 7,
            },
        ],
        "maps": [
            {"id": 4711, "width": 128, "height": 96, "revision": 1},
            {"id": 4712, "width": 96, "height": 96, "revision": 1},
        ],
    }
    evidence_bytes = (
        json.dumps(evidence, sort_keys=True, indent=1).encode("utf-8") + b"\n"
    )
    manifest = {
        "schema": "kaze.bundle/v1",
        "bundle_id": BUNDLE_ID,
        "sealed_at": "2026-11-17T00:00:00Z",
        "operator_alias": "deg-synthetic",
        "target": {"server": "synthetic", "protocol": "7.52"},
        "client": {
            "profile": "synthetic-deg-fixture",
            "exe_sha256": "0" * 64,
        },
        "evidence": {"path": "evidence.json", "sha256": sha256_hex(evidence_bytes)},
        "files": [
            {
                "path": "evidence.json",
                "sha256": sha256_hex(evidence_bytes),
                "bytes": len(evidence_bytes),
            }
        ],
        "blobs": blob_entries,
        "counts": {
            "evidence_entries": 7,
            "blobs": len(blob_entries),
            "bytes": sum(len(b) for b in blob_bytes),
        },
    }
    # The live manifests seal the canonical form with BOTH `seal` and `verify`
    # removed (the generator writes only `seal`; the documented `verify` form
    # is covered by a hand-written Rust test).
    payload = {k: v for k, v in manifest.items() if k not in ("seal", "verify")}
    digest = sha256_hex(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    )
    manifest["seal"] = {"algorithm": "sha256", "sha256": digest}
    index = {
        "schema": "kaze.capture-seal-index/v1",
        "bundles": [
            {
                "bundle_id": BUNDLE_ID,
                "manifest": "bundle/manifest.json",
                "manifest_sha256": sha256_hex(
                    json.dumps(manifest, sort_keys=True, indent=1).encode("utf-8")
                    + b"\n"
                ),
                "seal_sha256": digest,
                "sealed_at": "2026-11-17T00:00:00Z",
                "counts": manifest["counts"],
            }
        ],
    }
    return manifest, evidence, blob_bytes, blob_paths, index


def make_client_bin() -> bytes:
    head = b"DeG-NTK-SYNTHETIC-CLIENT\x00"
    body = bytes((i * 13 + 7) & 0xFF for i in range(4096))
    return head + body


# ------------------------------------------------- generate-lane fixtures

# The synthetic PE layout for the generate lane. All values are adapter-owned;
# the dispatch table bytes live at the declared VAs inside the PE's .text.
PE_IMAGE_BASE = 0x400000
PE_TEXT_RVA = 0x1000          # .text VA 0x401000
PE_RAW_BASE = 0x200          # .text raw data at file offset 0x200
PE_TEXT_SIZE = 0x400

DISPATCHER_VA = 0x401200      # file offset 0x400
CASE_VA = 0x401280            # file offset 0x480
INDEX_VA = 0x401290           # file offset 0x490

ANCHOR_BYTES = "55 8b ec 6a ff 68 01 30 40 00"
CASE_BYTES = "00 13 40 00 10 13 40 00 20 13 40 00 30 13 40 00"
INDEX_BYTES = "00 01 02 03 04 05"


def make_client_pe() -> bytes:
    """A minimal PE32 (image base 0x400000, one .text section) carrying the
    dispatch table bytes and the unique anchor prologue at their declared
    VAs. It parses with `deg::pe`; the generator re-reads the table bytes
    from it at check time."""
    anchor = bytes.fromhex(ANCHOR_BYTES)
    case_bytes = struct.pack("<4I", 0x401300, 0x401310, 0x401320, 0x401330)
    index_bytes = bytes.fromhex(INDEX_BYTES)

    text = bytearray([0xCC]) * PE_TEXT_SIZE
    aoff = DISPATCHER_VA - (PE_IMAGE_BASE + PE_TEXT_RVA)
    coff = CASE_VA - (PE_IMAGE_BASE + PE_TEXT_RVA)
    ioff = INDEX_VA - (PE_IMAGE_BASE + PE_TEXT_RVA)
    text[aoff:aoff + len(anchor)] = anchor
    text[coff:coff + len(case_bytes)] = case_bytes
    text[ioff:ioff + len(index_bytes)] = index_bytes

    file_len = PE_RAW_BASE + PE_TEXT_SIZE
    image = bytearray(file_len)
    image[0] = 0x4D
    image[1] = 0x5A
    image[0x3C:0x40] = struct.pack("<I", 0x80)          # e_lfanew
    image[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    image[coff:coff + 2] = struct.pack("<H", 0x14C)     # Machine: i386
    image[coff + 2:coff + 4] = struct.pack("<H", 1)     # NumberOfSections
    image[coff + 16:coff + 18] = struct.pack("<H", 0xE0)  # SizeOfOptionalHeader
    image[coff + 18:coff + 20] = struct.pack("<H", 0x0102)  # Characteristics
    opt = coff + 20
    image[opt:opt + 2] = struct.pack("<H", 0x10B)       # Magic: PE32
    image[opt + 28:opt + 32] = struct.pack("<I", PE_IMAGE_BASE)  # ImageBase
    image[opt + 32:opt + 36] = struct.pack("<I", 0x1000)  # SectionAlignment
    image[opt + 36:opt + 40] = struct.pack("<I", 0x200)   # FileAlignment
    image[opt + 56:opt + 60] = struct.pack("<I", 0x2000)  # SizeOfImage
    image[opt + 60:opt + 64] = struct.pack("<I", 0x200)   # SizeOfHeaders
    table = opt + 0xE0
    image[table:table + 8] = b".text\x00\x00\x00"
    image[table + 8:table + 12] = struct.pack("<I", PE_TEXT_SIZE)   # VirtualSize
    image[table + 12:table + 16] = struct.pack("<I", PE_TEXT_RVA)   # VirtualAddress
    image[table + 16:table + 20] = struct.pack("<I", PE_TEXT_SIZE)  # SizeOfRawData
    image[table + 20:table + 24] = struct.pack("<I", PE_RAW_BASE)   # PointerToRawData
    image[table + 36:table + 40] = struct.pack(
        "<I", 0x60000020)  # CNT_CODE | MEM_EXECUTE | MEM_READ
    image[PE_RAW_BASE:PE_RAW_BASE + PE_TEXT_SIZE] = text
    return bytes(image)


def make_dispatch_synthetic(client_sha: str) -> dict:
    """One dispatch table in the DISPATCHER-AUDIT.json shape; its declared
    bytes live verbatim inside client-syn.exe."""
    return {
        "schema": "kazetk.opcode-dispatcher-audit/v1",
        "generated": "synthetic-deg-fixture",
        "client": {
            "path": "client-syn.exe",
            "sha256": client_sha,
            "note": "synthetic deg-nexustk fixture",
        },
        "tables": {
            "mappane_syn": {
                "dispatcher_va": f"0x{DISPATCHER_VA:x}",
                "case_table_va": f"0x{CASE_VA:x}",
                "case_table_file_offset": f"0x{CASE_VA - (PE_IMAGE_BASE + PE_TEXT_RVA) + PE_RAW_BASE:x}",
                "case_table_bytes": CASE_BYTES,
                "case_count": 4,
                "index_table_va": f"0x{INDEX_VA:x}",
                "index_table_file_offset": f"0x{INDEX_VA - (PE_IMAGE_BASE + PE_TEXT_RVA) + PE_RAW_BASE:x}",
                "index_table_bytes": INDEX_BYTES,
                "index_count": 6,
            },
        },
    }


def make_layouts_synthetic() -> dict:
    """The opcode-layouts shape: three layout entries whose opcodes the
    synthetic vectors exercise (0x0C, 0x10, 0x62) and two unknowns (0x33,
    0x44) they do not."""
    return {
        "schema": "kaze.opcode-layouts/v1",
        "version": "synthetic-deg-fixture",
        "universe": {"path": "synthetic", "expected_count": 5},
        "layouts": [
            {
                "opcode": 0x0C,
                "direction": "s2c",
                "channel": "game",
                "name": "SyntheticBoardItemUpdate",
                "confidence": "confirmed",
                "status": "documented",
                "body_layout": "len(u8) name",
            },
            {
                "opcode": 0x10,
                "direction": "c2s",
                "channel": "game",
                "name": "SyntheticArrival",
                "confidence": "confirmed",
                "status": "documented",
                "body_layout": "u8 len(u8) name",
            },
            {
                "opcode": 0x62,
                "direction": "c2s",
                "channel": "login",
                "name": "SyntheticSignature",
                "confidence": "confirmed",
                "status": "documented",
                "body_layout": "profile(u8) sha1(20)",
            },
        ],
        "unknowns": [
            {
                "opcode": 0x33,
                "reason": "synthetic uncovered opcode",
                "status": "unsupported",
            },
            {
                "opcode": 0x44,
                "reason": "synthetic uncovered opcode",
                "status": "unsupported",
            },
        ],
    }


def make_artifacts_synthetic() -> dict:
    """The opcode-artifacts shape with a single artifact id (0x5A = 90)."""
    return {
        "schema": "kaze.opcode-artifacts/v1",
        "version": "synthetic-deg-fixture",
        "universe": {"path": "synthetic", "expected_count": 1},
        "dossier": "synthetic",
        "artifacts": [
            {
                "opcode": 0x5A,
                "hex": "0x5a",
                "status": "parser-artifact",
                "classification": "synthetic-artifact-role",
                "summary": "synthetic deg-nexustk fixture",
                "evidence": [],
            },
        ],
    }


def make_anchors_synthetic() -> list[dict]:
    """One unique prologue anchor at the dispatcher VA of client-syn.exe."""
    return [
        {
            "name": "syn_prologue",
            "va": f"0x{DISPATCHER_VA:x}",
            "bytes": ANCHOR_BYTES,
            "section": ".text",
        },
    ]


def make_model(vector_sha: str, frames_sha: str, manifest_sha: str,
               index_sha: str, client_sha: str) -> str:
    return f"""// Generated by tools/gen_fixtures.py — do not edit by hand.
// Synthetic end-to-end model for the deg-nexustk adapter: vector replay,
// a frame fact, and a verified kaze.bundle/v1 package.
//
// Run from the repository root:
//   cargo run -q -- check examples/synthetic/model.dg

build ntk_syn = binary("client-synthetic.bin",
  sha256: "{client_sha}",
  arch: x86, load: 0x400000);

dataset ds_vec = dataset("vectors-synthetic.json",
  sha256: "{vector_sha}", build: ntk_syn);
dataset ds_frames = dataset("frames-synthetic.jsonl",
  sha256: "{frames_sha}", build: ntk_syn);
dataset ds_manifest = dataset("bundle/manifest.json",
  sha256: "{manifest_sha}", build: ntk_syn);
dataset ds_index = dataset("bundle/index.json",
  sha256: "{index_sha}", build: ntk_syn);

ev ev_vec := ntk_vector(ds_vec, suite: "all");
ev ev_frames := ntk_frames(ds_frames);
ev ev_bundle := ntk_bundle(ds_manifest, "{BUNDLE_ID}", index_ds: ds_index);

rule r_vec: vector_replay(?ev, ?suite) if vector_suite_ok(?ev, ?suite);
rule r_frame: frame_seen(?ev) if frame(?ev, ?dir, ?op, ?channel, ?len, ?ts);
rule r_bundle: bundle_seen(?ev, ?id) if bundle_verified(?ev, ?id, ?sha);

proof P_vectors : vector_replay(ev_vec, all) in ntk_syn {{
  evidence ev_vec;
  rules r_vec;
}}
proof P_frames : frame_seen(ev_frames) in ntk_syn {{
  evidence ev_frames;
  rules r_frame;
}}
proof P_bundle : bundle_seen(ev_bundle, {BUNDLE_ID}) in ntk_syn {{
  evidence ev_bundle;
  rules r_bundle;
}}

// The sealed adapter claims: everything Deterministic except the capture
// frames proof, which stays an Observational hypothesis.
claim C_adapter : adapter_sealed(ntk_syn) in ntk_syn
  from P_vectors, P_bundle;
"""


def make_gen_data(vectors: dict) -> str:
    c_static = vectors["ciphers"][0]
    c_table = vectors["ciphers"][2]
    c_long = vectors["ciphers"][3]
    f_static = vectors["frames"][0]
    f_raw = vectors["frames"][2]
    stream = vectors["streams"][0]
    e_bad_magic = vectors["errors"][0]
    e_over_limit = vectors["errors"][1]
    tail_s2c_a = bytes.fromhex(c_table["tail"])
    tail_c2s_b = bytes.fromhex(c_static["tail"])

    def arr3(t: bytes) -> str:
        return f"[{t[0]}, {t[1]}, {t[2]}]"

    return f"""// Generated by tools/gen_fixtures.py — do not edit by hand.
// Hand-computed 7.52 codec vectors from the independent Python implementation.

pub const KEYTABLE_DEG_VECTOR_A_PREFIX: &str = "{vectors['keytables'][0]['prefix']}";
pub const TEMPKEY_B8: u8 = {vectors['tempkeys'][0]['b8']};
pub const TEMPKEY_W16: u16 = {vectors['tempkeys'][0]['w16']};
pub const TEMPKEY_KEY: &str = "{vectors['tempkeys'][0]['key']}";

pub const TAIL_C2S_DE_CAFE: &str = "{hexstr(tail_c2s_b)}";
pub const TAIL_S2C_AB_BEEF: &str = "{hexstr(tail_s2c_a)}";

pub const CIPHER_STATIC_PT: &str = "{c_static['plaintext']}";
pub const CIPHER_STATIC_CT: &str = "{c_static['ciphertext']}";
pub const CIPHER_STATIC_INC: u8 = {c_static['increment']};
pub const CIPHER_TABLE_PT: &str = "{c_table['plaintext']}";
pub const CIPHER_TABLE_CT: &str = "{c_table['ciphertext']}";
pub const CIPHER_TABLE_INC: u8 = {c_table['increment']};
pub const CIPHER_TABLE_TAIL: [u8; 3] = {arr3(tail_s2c_a)};
pub const LONG_INC: u8 = {c_long['increment']};
pub const LONG_TAIL: [u8; 3] = {arr3(tail_s2c_a)};
pub const LONG_CT_SHA256: &str = "{c_long['ciphertext_sha256']}";

pub const FRAME_STATIC_TAIL: [u8; 3] = {arr3(tail_c2s_b)};
pub const FRAME_STATIC_WIRE: &str = "{f_static['wire']}";
pub const FRAME_RAW_PLAINTEXT: &str = "{f_raw['plaintext']}";
pub const FRAME_RAW_WIRE: &str = "{f_raw['wire']}";

pub const STREAM_WIRE: &str = "{stream['wire']}";
pub const STREAM_FRAME_COUNT: usize = {len(stream['frames'])};
pub const STREAM_FRAME2_PLAINTEXT: &str = "{stream['frames'][2]['plaintext']}";

pub const ERROR_BAD_MAGIC_WIRE: &str = "{e_bad_magic['wire']}";
pub const ERROR_BAD_MAGIC_BYTE: u8 = 0xBB;
pub const ERROR_OVER_LIMIT_WIRE: &str = "{e_over_limit['wire']}";
pub const ERROR_OVER_LIMIT_MAX: usize = {e_over_limit['max_frame_bytes']};
"""


def main() -> None:
    SYN.mkdir(parents=True, exist_ok=True)
    (BUNDLE / "blobs" / "sha256").mkdir(parents=True, exist_ok=True)

    vectors = make_vectors()
    write_json(SYN / "vectors-synthetic.json", vectors)

    frames_lines = make_frames_jsonl()
    frames_text = "\n".join(frames_lines) + "\n"
    (SYN / "frames-synthetic.jsonl").write_text(frames_text, encoding="utf-8")

    manifest, evidence, blob_bytes, blob_paths, index = make_bundle()
    write_json(BUNDLE / "manifest.json", manifest)
    write_json(BUNDLE / "evidence.json", evidence)
    write_json(BUNDLE / "index.json", index)
    for raw, rel in zip(blob_bytes, blob_paths):
        blob_file = BUNDLE / rel
        blob_file.parent.mkdir(parents=True, exist_ok=True)
        blob_file.write_bytes(raw)

    client_bin = make_client_bin()
    (SYN / "client-synthetic.bin").write_bytes(client_bin)

    # The generate-lane fixtures: a synthetic PE32 plus the audit-file shapes
    # whose declared bytes live inside it.
    client_pe = make_client_pe()
    (SYN / "client-syn.exe").write_bytes(client_pe)
    write_json(SYN / "dispatch-synthetic.json",
               make_dispatch_synthetic(sha256_hex(client_pe)))
    write_json(SYN / "layouts-synthetic.json", make_layouts_synthetic())
    write_json(SYN / "artifacts-synthetic.json", make_artifacts_synthetic())
    write_json(SYN / "anchors-synthetic.json", make_anchors_synthetic())

    model = make_model(
        vector_sha=sha256_hex((SYN / "vectors-synthetic.json").read_bytes()),
        frames_sha=sha256_hex((SYN / "frames-synthetic.jsonl").read_bytes()),
        manifest_sha=sha256_hex((BUNDLE / "manifest.json").read_bytes()),
        index_sha=sha256_hex((BUNDLE / "index.json").read_bytes()),
        client_sha=sha256_hex(client_bin),
    )
    (SYN / "model.dg").write_text(model, encoding="utf-8")

    gen_data = make_gen_data(vectors)
    (ROOT / "tests" / "gen_data").mkdir(parents=True, exist_ok=True)
    (ROOT / "tests" / "gen_data" / "mod.rs").write_text(gen_data, encoding="utf-8")

    print(f"wrote {SYN.relative_to(ROOT)} fixtures and "
          f"tests/gen_data/mod.rs")


if __name__ == "__main__":
    main()
