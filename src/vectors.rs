//! Known-answer vector replay for the documented 7.52 wire codec, exposed as
//! the `ntk_vector` evidence kind.
//!
//! The vector file schema mirrors the documented known-answer schema: top
//! level `version`/`stub`, then `keytables`, `tempkeys`, `ciphers`, `frames`,
//! `streams`, and `errors` sections. Every check re-derives the expected
//! bytes from the documented algorithm; the fixture only pins the answers.

use crate::codec::{
    build_wire, cipher_kind, crypt, decode_stream, decode_tail, encrypt_body, frame_shape,
    parse_frame, Channel, CipherKind, Direction, KeyTable, ABSOLUTE_MAX_FRAME_BYTES,
    STATIC_KEY_752,
};
use deg::artifact::ArtifactSet;
use deg::ast::EvidenceDecl;
use deg::evidence::EvidenceOutcome;
use deg::json::Json;
use deg::semantic::ModelIndex;
use deg::sha256::sha256_hex;
use deg::strength::Strength;
use deg::value::Value;

pub const KIND: &str = "ntk_vector";

/// The suite names the `suite:` argument accepts.
pub const SUITES: &[&str] = &[
    "keytables",
    "tempkeys",
    "ciphers",
    "frames",
    "streams",
    "errors",
];

/// What a successful replay produced: the per-suite counts and the per-vector
/// facts to emit. Never contains bodies, keys, or digests of secret material.
#[derive(Debug)]
pub struct ReplayReport {
    pub suite_counts: Vec<(String, usize)>,
    /// One entry per vector that passed. `rel` selects the fact relation and
    /// its arity; `dir`/`opcode` are filled in where the vector declares them
    /// (cipher/frame vectors carry both, stream vectors carry the direction;
    /// key-table/temp-key/error facts carry neither).
    pub vector_facts: Vec<VectorFact>,
}

/// The fact a single passing vector contributes, with the direction/opcode it
/// declared where its suite has them.
#[derive(Debug)]
pub struct VectorFact {
    pub rel: &'static str,
    pub name: String,
    pub dir: String,
    pub opcode: u8,
}

fn hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex digit {:?}", b as char)),
    }
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A bounded hex preview for error messages: never dumps whole bodies.
fn hex_short(bytes: &[u8], limit: usize) -> String {
    let shown = &bytes[..bytes.len().min(limit)];
    let mut s = hex_of(shown);
    if bytes.len() > limit {
        s.push_str(&format!("…({} bytes total)", bytes.len()));
    }
    s
}

fn obj_string<'a>(obj: &'a Json, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(Json::as_str)
}

fn obj_u64(obj: &Json, key: &str) -> Option<u64> {
    obj.get(key).and_then(Json::as_u64)
}

fn obj_bool(obj: &Json, key: &str) -> Option<bool> {
    obj.get(key).and_then(Json::as_bool)
}

fn parse_tail(s: &str) -> Result<[u8; 3], String> {
    if s.is_empty() {
        return Ok([0, 0, 0]);
    }
    let bytes = hex_bytes(s)?;
    if bytes.len() != 3 {
        return Err(format!("tail is {} bytes, want 3", bytes.len()));
    }
    Ok([bytes[0], bytes[1], bytes[2]])
}

fn channel_of(s: &str) -> Result<Channel, String> {
    Channel::parse(s).ok_or_else(|| format!("unknown channel {s:?}"))
}

fn direction_of(s: &str) -> Result<Direction, String> {
    Direction::parse(s).ok_or_else(|| format!("unknown direction {s:?}"))
}

fn fail(suite: &str, name: &str, msg: impl std::fmt::Display) -> String {
    format!("vectors suite `{suite}` vector `{name}`: {msg}")
}

/// Replay the selected suites of a vector file. The first mismatch fails the
/// whole replay with a message naming the suite and the vector.
pub fn replay(text: &str, suite: &str) -> Result<ReplayReport, String> {
    let root = deg::json::parse(text).map_err(|e| format!("vector file is not valid JSON: {e}"))?;
    if root.as_obj().is_none() {
        return Err("vector file is not a JSON object".to_string());
    }
    let version = obj_string(&root, "version").unwrap_or("");
    if version != "7.52" {
        return Err(format!(
            "vector file version is {version:?}; only \"7.52\" is supported"
        ));
    }

    let requested: Vec<&str> = if suite == "all" {
        SUITES.to_vec()
    } else if SUITES.contains(&suite) {
        vec![suite]
    } else {
        return Err(format!(
            "unknown vector suite {suite:?}; expected one of {:?} or \"all\"",
            SUITES
        ));
    };

    let mut report = ReplayReport {
        suite_counts: Vec::new(),
        vector_facts: Vec::new(),
    };

    for name in &requested {
        let count = match *name {
            "keytables" => replay_keytables(&root, &mut report)?,
            "tempkeys" => replay_tempkeys(&root, &mut report)?,
            "ciphers" => replay_ciphers(&root, &mut report)?,
            "frames" => replay_frames(&root, &mut report)?,
            "streams" => replay_streams(&root, &mut report)?,
            "errors" => replay_errors(&root, &mut report)?,
            other => return Err(format!("unknown vector suite {other:?}")),
        };
        report.suite_counts.push(((*name).to_string(), count));
    }
    Ok(report)
}

fn replay_keytables(root: &Json, report: &mut ReplayReport) -> Result<usize, String> {
    let Some(list) = root.get("keytables").and_then(Json::as_arr) else {
        return Ok(0);
    };
    for entry in list {
        let name = obj_string(entry, "name").unwrap_or("").to_string();
        let identity = obj_string(entry, "identity").unwrap_or("");
        let prefix = obj_string(entry, "prefix").unwrap_or("");
        let length = obj_u64(entry, "length").unwrap_or(0) as usize;

        let table = KeyTable::new(identity);
        if length != 0 && table.as_bytes().len() != length {
            return Err(fail(
                "keytables",
                &name,
                format!("table length {}, want {length}", table.as_bytes().len()),
            ));
        }
        if prefix.len() > table.as_bytes().len() {
            return Err(fail(
                "keytables",
                &name,
                format!("prefix is {} bytes but the table is 1024", prefix.len()),
            ));
        }
        if table.as_bytes()[..prefix.len()] != *prefix.as_bytes() {
            return Err(fail(
                "keytables",
                &name,
                format!(
                    "table prefix mismatch: expected {}, got {}",
                    prefix,
                    hex_short(&table.as_bytes()[..prefix.len().min(128)], 128)
                ),
            ));
        }
        if table.as_bytes().iter().any(|b| !b.is_ascii_hexdigit()) {
            return Err(fail("keytables", &name, "table contains non-hex bytes"));
        }
        if KeyTable::new(identity) != table {
            return Err(fail("keytables", &name, "key table is not deterministic"));
        }
        report.vector_facts.push(VectorFact {
            rel: "keytable_ok",
            name: name.clone(),
            dir: String::new(),
            opcode: 0,
        });
    }
    Ok(list.len())
}

fn replay_tempkeys(root: &Json, report: &mut ReplayReport) -> Result<usize, String> {
    let Some(list) = root.get("tempkeys").and_then(Json::as_arr) else {
        return Ok(0);
    };
    for entry in list {
        let name = obj_string(entry, "name").unwrap_or("").to_string();
        let identity = obj_string(entry, "identity").unwrap_or("");
        let b8 = obj_u64(entry, "b8").unwrap_or(0) as u8;
        let w16 = obj_u64(entry, "w16").unwrap_or(0) as u16;
        let want = obj_string(entry, "key").unwrap_or("");

        let table = KeyTable::new(identity);
        let key = table.temp_key(b8, w16);
        let got = String::from_utf8_lossy(&key);
        if got != want {
            return Err(fail(
                "tempkeys",
                &name,
                format!("temp key mismatch: expected {want:?}, got {got:?}"),
            ));
        }
        report.vector_facts.push(VectorFact {
            rel: "tempkey_ok",
            name: name.clone(),
            dir: String::new(),
            opcode: 0,
        });
    }
    Ok(list.len())
}

/// The per-frame key for a cipher vector: the declared identity selects the
/// key source (empty = static key, non-empty = the name table via the decoded
/// tail), exactly as the cipher-vector replay specifies.
fn cipher_transform(
    identity: &str,
    dir: Direction,
    body: &[u8],
    increment: u8,
    tail: [u8; 3],
) -> Vec<u8> {
    if identity.is_empty() {
        crypt(body, &STATIC_KEY_752, increment)
    } else {
        let table = KeyTable::new(identity);
        let params = decode_tail(dir, tail);
        crypt(body, &table.temp_key(params.b8, params.w16), increment)
    }
}

fn replay_ciphers(root: &Json, report: &mut ReplayReport) -> Result<usize, String> {
    let Some(list) = root.get("ciphers").and_then(Json::as_arr) else {
        return Ok(0);
    };
    for entry in list {
        let name = obj_string(entry, "name").unwrap_or("").to_string();
        let identity = obj_string(entry, "identity").unwrap_or("");
        let dir = direction_of(obj_string(entry, "direction").unwrap_or(""))
            .map_err(|e| fail("ciphers", &name, e))?;
        let opcode = obj_u64(entry, "opcode").unwrap_or(0) as u8;
        let increment = obj_u64(entry, "increment").unwrap_or(0) as u8;

        let plaintext = obj_string(entry, "plaintext").unwrap_or("");
        let plaintext_len = obj_u64(entry, "plaintext_len").unwrap_or(0) as usize;
        let plaintext_prefix = obj_string(entry, "plaintext_prefix").unwrap_or("");
        let plain = if !plaintext.is_empty() || plaintext_len == 0 {
            hex_bytes(plaintext).map_err(|e| fail("ciphers", &name, e))?
        } else {
            // The vector convention for large bodies: plain[i] = (i*7+3)&0xff.
            (0..plaintext_len)
                .map(|i| ((i * 7 + 3) & 0xff) as u8)
                .collect()
        };
        if !plaintext_prefix.is_empty() && plain.len() >= plaintext_prefix.len() / 2 {
            let prefix_len = plaintext_prefix.len() / 2;
            if hex_of(&plain[..prefix_len]) != plaintext_prefix {
                return Err(fail(
                    "ciphers",
                    &name,
                    format!(
                        "plaintext prefix mismatch: expected {plaintext_prefix}, got {}",
                        hex_of(&plain[..prefix_len])
                    ),
                ));
            }
        }

        let tail = parse_tail(obj_string(entry, "tail").unwrap_or(""))
            .map_err(|e| fail("ciphers", &name, e))?;
        let produced = cipher_transform(identity, dir, &plain, increment, tail);

        let ciphertext = obj_string(entry, "ciphertext").unwrap_or("");
        let ciphertext_sha = obj_string(entry, "ciphertext_sha256").unwrap_or("");
        let ciphertext_prefix = obj_string(entry, "ciphertext_prefix").unwrap_or("");
        let ciphertext_len = obj_u64(entry, "ciphertext_len").unwrap_or(0) as usize;

        if !ciphertext.is_empty() {
            let want = hex_bytes(ciphertext).map_err(|e| fail("ciphers", &name, e))?;
            if produced != want {
                return Err(fail(
                    "ciphers",
                    &name,
                    format!(
                        "ciphertext mismatch: expected {}, got {}",
                        hex_short(&want, 64),
                        hex_short(&produced, 64)
                    ),
                ));
            }
        } else if !ciphertext_sha.is_empty() {
            if ciphertext_len != 0 && produced.len() != ciphertext_len {
                return Err(fail(
                    "ciphers",
                    &name,
                    format!(
                        "ciphertext length {}, want {ciphertext_len}",
                        produced.len()
                    ),
                ));
            }
            let digest = sha256_hex(&produced);
            if digest != ciphertext_sha {
                return Err(fail(
                    "ciphers",
                    &name,
                    format!("ciphertext sha256 mismatch: expected {ciphertext_sha}, got {digest}"),
                ));
            }
            if !ciphertext_prefix.is_empty() {
                let prefix_len = ciphertext_prefix.len() / 2;
                if produced.len() < prefix_len {
                    return Err(fail(
                        "ciphers",
                        &name,
                        "ciphertext is shorter than its prefix",
                    ));
                }
                if hex_of(&produced[..prefix_len]) != ciphertext_prefix {
                    return Err(fail(
                        "ciphers",
                        &name,
                        format!(
                            "ciphertext prefix mismatch: expected {ciphertext_prefix}, got {}",
                            hex_of(&produced[..prefix_len])
                        ),
                    ));
                }
            }
        } else {
            return Err(fail("ciphers", &name, "vector has no ciphertext or digest"));
        }

        // Round-trip: the transform is self-inverse.
        let recovered = cipher_transform(identity, dir, &produced, increment, tail);
        if recovered != plain {
            return Err(fail(
                "ciphers",
                &name,
                format!(
                    "round-trip mismatch: expected {}, got {}",
                    hex_short(&plain, 64),
                    hex_short(&recovered, 64)
                ),
            ));
        }
        report.vector_facts.push(VectorFact {
            rel: "cipher_vector_ok",
            name: name.clone(),
            dir: dir.as_str().to_string(),
            opcode,
        });
    }
    Ok(list.len())
}

fn replay_frames(root: &Json, report: &mut ReplayReport) -> Result<usize, String> {
    let Some(list) = root.get("frames").and_then(Json::as_arr) else {
        return Ok(0);
    };
    for entry in list {
        let name = obj_string(entry, "name").unwrap_or("").to_string();
        let channel = channel_of(obj_string(entry, "channel").unwrap_or(""))
            .map_err(|e| fail("frames", &name, e))?;
        let dir = direction_of(obj_string(entry, "direction").unwrap_or(""))
            .map_err(|e| fail("frames", &name, e))?;
        let identity = obj_string(entry, "identity").unwrap_or("");
        let opcode = obj_u64(entry, "opcode").unwrap_or(0) as u8;
        let increment = obj_u64(entry, "increment").unwrap_or(0) as u8;
        let raw = obj_bool(entry, "raw").unwrap_or(false);
        let plaintext_body = obj_bool(entry, "plaintext_body").unwrap_or(false);
        let plaintext = hex_bytes(obj_string(entry, "plaintext").unwrap_or(""))
            .map_err(|e| fail("frames", &name, e))?;
        let tail = parse_tail(obj_string(entry, "tail").unwrap_or(""))
            .map_err(|e| fail("frames", &name, e))?;
        let declared_wire = hex_bytes(obj_string(entry, "wire").unwrap_or(""))
            .map_err(|e| fail("frames", &name, e))?;
        if declared_wire.is_empty() {
            return Err(fail("frames", &name, "vector has no wire bytes"));
        }

        let shape = frame_shape(dir, opcode);
        if raw != shape.raw {
            return Err(fail(
                "frames",
                &name,
                format!(
                    "raw flag is {raw}, the documented layout says {}",
                    shape.raw
                ),
            ));
        }
        let plain_expected = shape.raw || cipher_kind(channel, dir, opcode) == CipherKind::Plain;
        if plaintext_body != plain_expected {
            return Err(fail(
                "frames",
                &name,
                format!("plaintext_body flag is {plaintext_body}, expected {plain_expected}"),
            ));
        }

        // Raw/plain frames carry the body verbatim; otherwise the body is
        // encrypted with the documented policy key before framing.
        let body_wire = if plain_expected {
            plaintext.clone()
        } else {
            encrypt_body(channel, dir, opcode, increment, &plaintext, tail, identity)
                .map_err(|e| fail("frames", &name, e))?
        };
        let wire = build_wire(dir, opcode, increment, &body_wire, tail)
            .map_err(|e| fail("frames", &name, e))?;
        if wire != declared_wire {
            return Err(fail(
                "frames",
                &name,
                format!(
                    "wire mismatch: expected {}, got {}",
                    hex_short(&declared_wire, 128),
                    hex_short(&wire, 128)
                ),
            ));
        }
        report.vector_facts.push(VectorFact {
            rel: "frame_vector_ok",
            name: name.clone(),
            dir: dir.as_str().to_string(),
            opcode,
        });
    }
    Ok(list.len())
}

fn replay_streams(root: &Json, report: &mut ReplayReport) -> Result<usize, String> {
    let Some(list) = root.get("streams").and_then(Json::as_arr) else {
        return Ok(0);
    };
    for entry in list {
        let name = obj_string(entry, "name").unwrap_or("").to_string();
        let channel = channel_of(obj_string(entry, "channel").unwrap_or(""))
            .map_err(|e| fail("streams", &name, e))?;
        let dir = direction_of(obj_string(entry, "direction").unwrap_or(""))
            .map_err(|e| fail("streams", &name, e))?;
        let identity = obj_string(entry, "identity").unwrap_or("");
        let wire = hex_bytes(obj_string(entry, "wire").unwrap_or(""))
            .map_err(|e| fail("streams", &name, e))?;
        let declared_consumed = obj_u64(entry, "consumed").unwrap_or(0) as usize;
        let want_frames = entry
            .get("frames")
            .and_then(Json::as_arr)
            .ok_or_else(|| fail("streams", &name, "vector has no frames array"))?;

        let (frames, consumed) = decode_stream(channel, dir, &wire, identity, 0)
            .map_err(|e| fail("streams", &name, e))?;
        let want_consumed = if declared_consumed == 0 {
            wire.len()
        } else {
            declared_consumed
        };
        if consumed != want_consumed {
            return Err(fail(
                "streams",
                &name,
                format!(
                    "consumed {consumed} of {} bytes, want {want_consumed}",
                    wire.len()
                ),
            ));
        }
        if frames.len() != want_frames.len() {
            return Err(fail(
                "streams",
                &name,
                format!(
                    "decoded {} frames, want {}",
                    frames.len(),
                    want_frames.len()
                ),
            ));
        }
        for (i, want) in want_frames.iter().enumerate() {
            let got = &frames[i];
            let want_opcode = obj_u64(want, "opcode").unwrap_or(0) as u8;
            let want_increment = obj_u64(want, "increment").unwrap_or(0) as u8;
            let want_plaintext = hex_bytes(obj_string(want, "plaintext").unwrap_or(""))
                .map_err(|e| fail("streams", &name, format!("frame {i}: {e}")))?;
            let want_tail = parse_tail(obj_string(want, "tail").unwrap_or(""))
                .map_err(|e| fail("streams", &name, e))?;
            let want_raw = obj_bool(want, "raw").unwrap_or(false);

            if got.opcode != want_opcode || got.increment != want_increment {
                return Err(fail(
                    "streams",
                    &name,
                    format!(
                        "frame {i} header is 0x{:02X}/{}, want 0x{want_opcode:02X}/{want_increment}",
                        got.opcode, got.increment
                    ),
                ));
            }
            if got.body != want_plaintext {
                return Err(fail(
                    "streams",
                    &name,
                    format!(
                        "frame {i} plaintext mismatch: expected {}, got {}",
                        hex_short(&want_plaintext, 64),
                        hex_short(&got.body, 64)
                    ),
                ));
            }
            if got.tail != want_tail {
                return Err(fail(
                    "streams",
                    &name,
                    format!(
                        "frame {i} tail mismatch: expected {}, got {}",
                        hex_of(&want_tail),
                        hex_of(&got.tail)
                    ),
                ));
            }
            if got.raw != want_raw {
                return Err(fail(
                    "streams",
                    &name,
                    format!("frame {i} raw flag is {}, want {want_raw}", got.raw),
                ));
            }
        }
        report.vector_facts.push(VectorFact {
            rel: "stream_vector_ok",
            name: name.clone(),
            dir: dir.as_str().to_string(),
            opcode: 0,
        });
    }
    Ok(list.len())
}

fn replay_errors(root: &Json, report: &mut ReplayReport) -> Result<usize, String> {
    let Some(list) = root.get("errors").and_then(Json::as_arr) else {
        return Ok(0);
    };
    for entry in list {
        let name = obj_string(entry, "name").unwrap_or("").to_string();
        let channel = channel_of(obj_string(entry, "channel").unwrap_or(""))
            .map_err(|e| fail("errors", &name, e))?;
        let dir = direction_of(obj_string(entry, "direction").unwrap_or(""))
            .map_err(|e| fail("errors", &name, e))?;
        let opcode = obj_u64(entry, "opcode").unwrap_or(0) as u8;
        let body_len = obj_u64(entry, "body_len").unwrap_or(0) as usize;
        let wire = obj_string(entry, "wire").unwrap_or("");
        let max_frame_bytes = obj_u64(entry, "max_frame_bytes").unwrap_or(0) as usize;

        if !wire.is_empty() {
            let wire = hex_bytes(wire).map_err(|e| fail("errors", &name, e))?;
            let max = if max_frame_bytes > 0 {
                max_frame_bytes
            } else {
                ABSOLUTE_MAX_FRAME_BYTES
            };
            match parse_frame(channel, dir, &wire, max) {
                Ok((_frame, _)) => {
                    return Err(fail(
                        "errors",
                        &name,
                        "the codec accepted the wire; a framing error was expected",
                    ));
                }
                Err(e) if !e.is_framing_error() => {
                    return Err(fail(
                        "errors",
                        &name,
                        "the codec only reported a truncated frame; a framing error was expected",
                    ));
                }
                Err(_) => {}
            }
        } else if body_len > 0 {
            // An oversized body must be rejected at encode time (the
            // documented 7.52 send cap is 39,990 wire bytes).
            let body = vec![0u8; body_len];
            let attempt = build_wire(dir, opcode, 0, &body, [0, 0, 0]);
            if let Ok(wire) = attempt {
                return Err(fail(
                    "errors",
                    &name,
                    format!(
                        "the codec accepted an oversized frame ({} wire bytes)",
                        wire.len()
                    ),
                ));
            }
        } else {
            return Err(fail("errors", &name, "vector has no wire and no body_len"));
        }
        report.vector_facts.push(VectorFact {
            rel: "error_vector_ok",
            name: name.clone(),
            dir: String::new(),
            opcode: 0,
        });
    }
    Ok(list.len())
}

/// Evaluate `ntk_vector(ds_name, [suite: ...])`.
pub fn eval(
    _index: &ModelIndex,
    artifacts: &ArtifactSet,
    decl: &EvidenceDecl,
) -> Result<EvidenceOutcome, String> {
    let (ds_name, suite) = match &decl.kind {
        deg::ast::EvidenceKind::Extension { args, .. } => (
            args.positional_string(0)
                .ok_or_else(|| "ntk_vector needs a dataset name".to_string())?,
            args.string("suite").unwrap_or_else(|| "all".to_string()),
        ),
        _ => return Err("ntk_vector evaluator called on a non-extension".into()),
    };
    let text = artifacts.dataset_text(&ds_name)?;
    let report = replay(&text, &suite)?;

    let total: usize = report.suite_counts.iter().map(|(_, n)| n).sum();
    let mut out = EvidenceOutcome::new(
        &decl.name,
        KIND,
        Strength::Deterministic,
        format!(
            "vector replay ok: {} vector(s) across {} suite(s)",
            total,
            report.suite_counts.len()
        ),
    );
    out.fact(
        "vector_suite_ok",
        vec![Value::sym(&decl.name), Value::sym(suite.clone())],
    );
    out.fact(
        "vector_count",
        vec![
            Value::sym(&decl.name),
            Value::sym(suite.clone()),
            Value::Int(total as i128),
        ],
    );
    for vf in &report.vector_facts {
        match vf.rel {
            "cipher_vector_ok" | "frame_vector_ok" => {
                out.fact(
                    vf.rel,
                    vec![
                        Value::sym(&decl.name),
                        Value::sym(vf.name.clone()),
                        Value::sym(vf.dir.clone()),
                        Value::Int(vf.opcode as i128),
                    ],
                );
            }
            "stream_vector_ok" => {
                out.fact(
                    vf.rel,
                    vec![
                        Value::sym(&decl.name),
                        Value::sym(vf.name.clone()),
                        Value::sym(vf.dir.clone()),
                    ],
                );
            }
            "keytable_ok" | "tempkey_ok" | "error_vector_ok" => {
                out.fact(
                    vf.rel,
                    vec![Value::sym(&decl.name), Value::sym(vf.name.clone())],
                );
            }
            other => {
                return Err(format!(
                    "vector replay produced an unknown fact relation {other:?}"
                ))
            }
        }
    }
    for (suite_name, count) in &report.suite_counts {
        out.detail(suite_name, count.to_string());
    }
    out.detail("dataset", ds_name.clone());
    out.detail("suite", suite.clone());
    Ok(out)
}

/// The build this evidence is bound to: the dataset's declared build, exactly
/// like the core `table` evidence.
pub fn build_hook(index: &ModelIndex, decl: &EvidenceDecl) -> Option<String> {
    let ds_name = match &decl.kind {
        deg::ast::EvidenceKind::Extension { args, .. } => args.positional_string(0)?,
        _ => return None,
    };
    index.datasets.get(&ds_name).and_then(|d| d.build.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed synthetic vector file must replay completely; it is the
    /// cross-check of this implementation against the independent Python
    /// generator.
    #[test]
    fn synthetic_vectors_replay() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples/synthetic/vectors-synthetic.json");
        let text = std::fs::read_to_string(path).unwrap();
        for suite in SUITES.iter().chain(std::iter::once(&"all")) {
            let report = replay(&text, suite).unwrap();
            let total: usize = report.suite_counts.iter().map(|(_, n)| n).sum();
            assert!(total > 0, "suite {suite} replayed no vectors");
        }
    }

    /// A tampered ciphertext fails with the suite and vector name in the
    /// message, and the expected vs actual hex.
    #[test]
    fn tampered_ciphertext_is_named() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples/synthetic/vectors-synthetic.json");
        let text = std::fs::read_to_string(path).unwrap();
        let tampered = text.replace(
            "\"ciphertext\": \"055e551d1506045c03\"",
            "\"ciphertext\": \"055e551d1506045c00\"",
        );
        assert_ne!(tampered, text, "the fixture changed under the test");
        let err = replay(&tampered, "ciphers").unwrap_err();
        assert!(err.contains("ciphers"), "{err}");
        assert!(err.contains("deg-cipher-table"), "{err}");
        assert!(err.contains("expected"), "{err}");
        assert!(err.contains("got"), "{err}");
    }

    /// The per-vector facts carry the direction/opcode the vector declares:
    /// cipher and frame facts are 4-ary (ev, name, dir, opcode), stream facts
    /// are 3-ary (ev, name, dir), and key-table/temp-key/error facts stay
    /// 2-ary with no direction or opcode.
    #[test]
    fn per_vector_facts_carry_direction_and_opcode() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples/synthetic/vectors-synthetic.json");
        let text = std::fs::read_to_string(path).unwrap();
        let report = replay(&text, "all").unwrap();
        let find = |rel: &str, name: &str| -> &VectorFact {
            report
                .vector_facts
                .iter()
                .find(|f| f.rel == rel && f.name == name)
                .unwrap_or_else(|| panic!("no {rel} fact for {name}"))
        };

        let cipher = find("cipher_vector_ok", "deg-cipher-table");
        assert_eq!(cipher.dir, "s2c");
        assert_eq!(cipher.opcode, 0x0C);
        let cipher_login = find("cipher_vector_ok", "deg-cipher-static-login");
        assert_eq!(cipher_login.dir, "c2s");
        assert_eq!(cipher_login.opcode, 0x62);

        let frame = find("frame_vector_ok", "deg-frame-arrival");
        assert_eq!(frame.dir, "c2s");
        assert_eq!(frame.opcode, 0x10);
        let frame_s2c = find("frame_vector_ok", "deg-frame-table");
        assert_eq!(frame_s2c.dir, "s2c");
        assert_eq!(frame_s2c.opcode, 0x0C);

        let stream = find("stream_vector_ok", "deg-stream-login-mixed");
        assert_eq!(stream.dir, "s2c");
        assert_eq!(stream.opcode, 0);

        let key = find("keytable_ok", "deg-keytable-a");
        assert!(key.dir.is_empty());
        assert_eq!(key.opcode, 0);
        let temp = find("tempkey_ok", "deg-tempkey-a");
        assert!(temp.dir.is_empty());
        let err = find("error_vector_ok", "deg-error-bad-magic");
        assert!(err.dir.is_empty());
        assert_eq!(err.opcode, 0);
    }

    /// The real 7.52 vector file cross-check. Never run in CI; the file is
    /// operator-local. See README.md.
    #[test]
    #[ignore]
    fn ntk_real_vectors() {
        let path = std::env::var("NTK_VECTORS")
            .expect("set NTK_VECTORS to a real 7.52 vector file to cross-check");
        let text = std::fs::read_to_string(path).expect("NTK_VECTORS file is unreadable");
        let report = replay(&text, "all").expect("real vector replay failed");
        for (suite, count) in &report.suite_counts {
            assert!(*count > 0, "suite {suite} replayed no vectors");
        }
        eprintln!(
            "ntk_real_vectors: {} suites, {} vectors ok",
            report.suite_counts.len(),
            report.vector_facts.len()
        );
    }
}
