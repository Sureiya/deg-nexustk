//! The `deg-nexustk generate` lane.
//!
//! Converts the project's audit artifacts (DISPATCHER-AUDIT.json,
//! opcode-layouts.json, opcode-artifacts.json, and the known-answer 7.52
//! vectors) into a deterministic `.dg` model plus content-addressed copies of
//! the tabular inputs, decision templates, and a provenance README.
//!
//! Strength discipline: only kernel-replayed facts (bytes re-read from the
//! client, unique scans, content-addressed dataset parses, and the compiled-in
//! vector replay) reach Deterministic. Generator-authored interpretation is
//! either capped (the artifact rules, at Observational) or left open as
//! obligations and commented-out human decisions. Nothing here reaches Exact.
//!
//! The generator is deterministic: the same inputs always produce byte-
//! identical outputs (no timestamps, no host state, sorted id order).

use deg::json::Json;
use deg::sha256::sha256_hex;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub const USAGE: &str = r#"deg-nexustk generate — emit a .dg model from the project's audit artifacts

Usage:
  deg-nexustk generate --out <dir>
      [--client <exe>] [--client-sha <hex>]
      [--vectors <7.52.json>]
      [--layouts <opcode-layouts.json>]
      [--dispatch <DISPATCHER-AUDIT.json>]
      [--artifacts <opcode-artifacts.json>]
      [--anchors <anchors.json>]
      [--target <n>]
      [--port-to <client2>]

The generator writes only inside `--out` (which must not exist yet or be an
empty directory): model.dg, README.md, copies of the tabular inputs, and
decision templates under decisions/. Inputs are read, never modified.

Exit codes: 0 ok, 2 usage or input error.
"#;

/// Entry point: returns `None` when `argv[1]` is not `generate` (so the host
/// binary can fall through to the core CLI unchanged).
pub fn run(args: &[String]) -> Option<ExitCode> {
    if args.first().map(String::as_str) != Some("generate") {
        return None;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return Some(ExitCode::SUCCESS);
    }
    Some(match run_generate(&args[1..]) {
        Ok(summary) => {
            print!("{summary}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("deg-nexustk generate: {e}\n\n{USAGE}");
            ExitCode::from(2)
        }
    })
}

// ------------------------------------------------------------------ options

#[derive(Default)]
struct Options {
    out: Option<PathBuf>,
    client: Option<PathBuf>,
    client_sha: Option<String>,
    vectors: Option<PathBuf>,
    layouts: Option<PathBuf>,
    dispatch: Option<PathBuf>,
    artifacts: Option<PathBuf>,
    anchors: Option<PathBuf>,
    target: Option<u64>,
    port_to: Option<String>,
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut o = Options::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let take = |i: &mut usize, name: &str| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match a {
            "--out" => o.out = Some(PathBuf::from(take(&mut i, "--out")?)),
            "--client" => o.client = Some(PathBuf::from(take(&mut i, "--client")?)),
            "--client-sha" => o.client_sha = Some(take(&mut i, "--client-sha")?),
            "--vectors" => o.vectors = Some(PathBuf::from(take(&mut i, "--vectors")?)),
            "--layouts" => o.layouts = Some(PathBuf::from(take(&mut i, "--layouts")?)),
            "--dispatch" => o.dispatch = Some(PathBuf::from(take(&mut i, "--dispatch")?)),
            "--artifacts" => o.artifacts = Some(PathBuf::from(take(&mut i, "--artifacts")?)),
            "--anchors" => o.anchors = Some(PathBuf::from(take(&mut i, "--anchors")?)),
            "--target" => {
                let v = take(&mut i, "--target")?;
                o.target = Some(
                    v.parse()
                        .map_err(|_| format!("--target is not a number: {v:?}"))?,
                );
            }
            "--port-to" => o.port_to = Some(take(&mut i, "--port-to")?),
            other => return Err(format!("unknown option `{other}`")),
        }
        i += 1;
    }
    let out = o
        .out
        .clone()
        .ok_or_else(|| "missing required --out <dir>".to_string())?;
    if o.client_sha.is_some() && o.client.is_none() {
        return Err("--client-sha requires --client".to_string());
    }
    if o.target.is_some() && o.layouts.is_none() {
        return Err("--target requires --layouts".to_string());
    }
    if out == Path::new("") {
        return Err("--out must not be empty".to_string());
    }
    Ok(o)
}

/// A verified input file: its path (as given), its bytes, and its digest.
struct Input {
    path: PathBuf,
    sha256: String,
    text: String,
}
fn read_input(path: &Path, what: &str) -> Result<Input, String> {
    let bytes =
        fs::read(path).map_err(|e| format!("cannot read {what} {}: {e}", path.display()))?;
    let text = String::from_utf8(bytes.clone())
        .map_err(|e| format!("{what} {} is not valid UTF-8: {e}", path.display()))?;
    Ok(Input {
        path: path.to_path_buf(),
        sha256: sha256_hex(&bytes),
        text,
    })
}

// --------------------------------------------------------------- name helpers

/// A registry that hands out unique identifiers from sanitized bases.
struct Names {
    used: BTreeMap<String, usize>,
}

impl Names {
    fn new() -> Names {
        Names {
            used: BTreeMap::new(),
        }
    }

    /// Sanitize `base` into a DeG identifier (`[a-zA-Z_][a-zA-Z0-9_]*`) and
    /// disambiguate collisions by appending `_2`, `_3`, … Case is preserved
    /// (callers lowercase raw file names themselves); invalid characters
    /// become `_`.
    fn claim(&mut self, base: &str) -> String {
        let mut ident = String::new();
        let mut last_underscore = false;
        for c in base.chars() {
            if c.is_ascii_alphanumeric() || c == '_' {
                ident.push(c);
                last_underscore = c == '_';
            } else if !last_underscore && !ident.is_empty() {
                ident.push('_');
                last_underscore = true;
            }
        }
        while ident.ends_with('_') {
            ident.pop();
        }
        if ident.is_empty() {
            ident = "x".to_string();
        } else if ident.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            ident.insert(0, 'x');
        }
        let n = self.used.entry(ident.clone()).or_insert(0);
        *n += 1;
        if *n == 1 {
            ident
        } else {
            format!("{ident}_{n}")
        }
    }
}

fn sanitize_ident(base: &str) -> String {
    let mut out = String::new();
    let mut last_underscore = false;
    for c in base.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_underscore = false;
        } else if !last_underscore && !out.is_empty() {
            out.push('_');
            last_underscore = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    // Identifiers must start with an alphabetic character or `_`.
    if out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out.insert(0, 'x');
    }
    out
}

/// DeG string literal quoting (the model lexer's escape set).
fn dg_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Normalize a hex byte string (with spaces, commas, underscores) into
/// compact lowercase hex, validating even length and hex digits.
fn compact_hex(raw: &str, what: &str) -> Result<String, String> {
    let compact: String = raw
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ',' && *c != '_')
        .collect::<String>()
        .to_ascii_lowercase();
    if compact.is_empty() {
        return Err(format!("{what} has no bytes"));
    }
    if compact.len() % 2 != 0 {
        return Err(format!("{what} hex string has odd length"));
    }
    if !compact.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{what} contains non-hex characters"));
    }
    Ok(compact)
}

/// Normalize a byte string into space-separated lowercase hex pairs (the form
/// `scan` patterns use).
fn spaced_hex(raw: &str, what: &str) -> Result<String, String> {
    let compact = compact_hex(raw, what)?;
    let mut out = String::new();
    for (i, b) in compact.as_bytes().iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push(' ');
        }
        out.push(*b as char);
    }
    Ok(out)
}

fn hex_id(id: u64) -> String {
    format!("{id:02x}")
}

fn parse_va(v: &Json, what: &str) -> Result<u64, String> {
    v.as_u64()
        .ok_or_else(|| format!("{what} is not a number or hex string: {v}"))
}

// ------------------------------------------------------------ input parsing

/// One dispatch/case table row from the dispatch audit: the `index` table and
/// the `case` table of one dispatcher.
struct TableRow {
    /// Sanitized base name (`mappane`, `send_shape_a`, …).
    name: String,
    dispatcher_va: Option<u64>,
    index: Option<TableHalf>,
    case: Option<TableHalf>,
}

struct TableHalf {
    va: u64,
    file_offset: Option<u64>,
    bytes: String,
}

fn parse_dispatch(input: &Input) -> Result<Vec<TableRow>, String> {
    let root = deg::json::parse(&input.text)
        .map_err(|e| format!("{} is not valid JSON: {e}", input.path.display()))?;
    let root_obj = root
        .as_obj()
        .ok_or_else(|| format!("{} is not a JSON object", input.path.display()))?;

    // The audit file stores dispatch tables either as a name -> entry object
    // (`tables`) or as a list of entries (`dispatch_tables`); accept both.
    let mut entries: Vec<(String, &Json)> = Vec::new();
    if let Some(tables) = root_obj.get("tables").and_then(Json::as_obj) {
        for (name, entry) in tables {
            entries.push((name.clone(), entry));
        }
    } else if let Some(list) = root_obj.get("dispatch_tables").and_then(Json::as_arr) {
        for (i, entry) in list.iter().enumerate() {
            let name = entry
                .get("name")
                .and_then(Json::as_str)
                .unwrap_or("dispatch")
                .to_string();
            entries.push((format!("{name}_{i}"), entry));
        }
    }
    if entries.is_empty() {
        return Err(format!(
            "{} has no `tables` object and no `dispatch_tables` array",
            input.path.display()
        ));
    }

    let dispatchers = root_obj
        .get("dispatchers_checked")
        .and_then(Json::as_arr)
        .map(|list| list.to_vec())
        .unwrap_or_default();

    let half = |entry: &Json,
                va_key: &str,
                off_key: &str,
                bytes_key: &str|
     -> Result<Option<TableHalf>, String> {
        let Some(va) = entry.get(va_key) else {
            return Ok(None);
        };
        let Some(bytes) = entry.get(bytes_key).and_then(Json::as_str) else {
            return Ok(None);
        };
        let va = parse_va(va, va_key)?;
        let bytes = compact_hex(bytes, bytes_key)?;
        let file_offset = entry.get(off_key).and_then(|v| v.as_u64());
        Ok(Some(TableHalf {
            va,
            file_offset,
            bytes,
        }))
    };

    let mut rows = Vec::new();
    for (raw_name, entry) in entries {
        let dispatcher_va = entry
            .get("dispatcher_va")
            .and_then(|v| v.as_u64())
            .or_else(|| entry.get("va").and_then(|v| v.as_u64()))
            .or_else(|| {
                // Some audits keep the dispatcher VA in a parallel
                // `dispatchers_checked` list keyed by the table VA.
                let table_va = entry.get("case_table_va").and_then(|v| v.as_u64());
                dispatchers.iter().find_map(|d| {
                    let matches = d.get("table_va").and_then(|v| v.as_u64()) == table_va;
                    matches
                        .then(|| d.get("va").and_then(|v| v.as_u64()))
                        .flatten()
                })
            });
        let index = half(
            entry,
            "index_table_va",
            "index_table_file_offset",
            "index_table_bytes",
        )?;
        let case = half(
            entry,
            "case_table_va",
            "case_table_file_offset",
            "case_table_bytes",
        )?;
        if index.is_none() && case.is_none() {
            return Err(format!(
                "{}: dispatch entry `{raw_name}` has neither an index nor a case table",
                input.path.display()
            ));
        }
        rows.push(TableRow {
            name: raw_name,
            dispatcher_va,
            index,
            case,
        });
    }
    Ok(rows)
}

/// The union of opcodes exercised by the vectors file's `frames` and
/// `ciphers` sections, sorted.
fn vector_opcodes(input: &Input) -> Result<Vec<u8>, String> {
    let root = deg::json::parse(&input.text)
        .map_err(|e| format!("{} is not valid JSON: {e}", input.path.display()))?;
    let mut ops = BTreeSet::new();
    for section in ["frames", "ciphers"] {
        if let Some(list) = root.get(section).and_then(Json::as_arr) {
            for entry in list {
                if let Some(op) = entry.get("opcode").and_then(Json::as_u64) {
                    if op <= 0xff {
                        ops.insert(op as u8);
                    }
                }
            }
        }
    }
    Ok(ops.into_iter().collect())
}

/// Every numeric opcode id the layouts manifest mentions: any JSON object key
/// named `opcode` or `id` with a numeric (or numeric-hex-string) value.
fn layouts_ids(input: &Input) -> Result<Vec<u64>, String> {
    let root = deg::json::parse(&input.text)
        .map_err(|e| format!("{} is not valid JSON: {e}", input.path.display()))?;
    let mut ids = BTreeSet::new();
    collect_ids(&root, &mut ids);
    if ids.is_empty() {
        return Err(format!(
            "{} contains no numeric opcode/id values",
            input.path.display()
        ));
    }
    Ok(ids.into_iter().collect())
}

fn collect_ids(v: &Json, ids: &mut BTreeSet<u64>) {
    match v {
        Json::Obj(map) => {
            for (key, val) in map {
                if (key == "opcode" || key == "id") && !matches!(val, Json::Obj(_) | Json::Arr(_)) {
                    if let Some(n) = val.as_u64() {
                        ids.insert(n);
                    }
                } else {
                    collect_ids(val, ids);
                }
            }
        }
        Json::Arr(items) => {
            for item in items {
                collect_ids(item, ids);
            }
        }
        _ => {}
    }
}

/// One artifact entry: its numeric id, its hex form, and a human role.
struct Artifact {
    id: u64,
    hex: String,
    role: String,
}

fn parse_artifacts(input: &Input) -> Result<Vec<Artifact>, String> {
    let root = deg::json::parse(&input.text)
        .map_err(|e| format!("{} is not valid JSON: {e}", input.path.display()))?;
    let mut out = Vec::new();

    if let Some(list) = root.get("artifacts").and_then(Json::as_arr) {
        for entry in list {
            let id = entry
                .get("opcode")
                .and_then(Json::as_u64)
                .or_else(|| entry.get("id").and_then(Json::as_u64))
                .ok_or_else(|| {
                    format!(
                        "{}: artifact entry has no `opcode`/`id`",
                        input.path.display()
                    )
                })?;
            let hex = entry
                .get("hex")
                .and_then(Json::as_str)
                .map(normalize_hex)
                .filter(|s| {
                    !s.is_empty() && s.len() <= 2 && s.bytes().all(|b| b.is_ascii_hexdigit())
                })
                .unwrap_or_else(|| hex_id(id));
            let role = entry
                .get("classification")
                .and_then(Json::as_str)
                .or_else(|| entry.get("non_opcode_role").and_then(Json::as_str))
                .unwrap_or("opcode_artifact")
                .to_string();
            out.push(Artifact {
                id,
                hex,
                role: sanitize_role(&role),
            });
        }
    } else if let Some(scope) = root.get("scope") {
        // The verification-style manifest lists the nine ids/hex forms under
        // `scope` without per-id classifications.
        let ids = scope
            .get("ids")
            .and_then(Json::as_arr)
            .map(|a| a.iter().filter_map(Json::as_u64).collect::<Vec<_>>())
            .unwrap_or_default();
        let hexes = scope
            .get("hex")
            .and_then(Json::as_arr)
            .map(|a| {
                a.iter()
                    .filter_map(Json::as_str)
                    .map(normalize_hex)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for (i, id) in ids.iter().enumerate() {
            let hex = hexes
                .get(i)
                .cloned()
                .filter(|s| {
                    !s.is_empty() && s.len() <= 2 && s.bytes().all(|b| b.is_ascii_hexdigit())
                })
                .unwrap_or_else(|| hex_id(*id));
            out.push(Artifact {
                id: *id,
                hex,
                role: "opcode_artifact".to_string(),
            });
        }
    }
    if out.is_empty() {
        return Err(format!(
            "{} has no `artifacts` list and no `scope.ids` list",
            input.path.display()
        ));
    }
    Ok(out)
}

fn normalize_hex(s: &str) -> String {
    s.trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_lowercase()
}

fn sanitize_role(role: &str) -> String {
    let mut s = String::new();
    for c in role.chars() {
        if c == ',' || c.is_control() {
            s.push(';');
        } else {
            s.push(c);
        }
    }
    let s = s.trim().to_string();
    if s.is_empty() {
        "opcode_artifact".to_string()
    } else {
        s
    }
}

/// One client anchor: a unique prologue scan at a declared function address.
struct Anchor {
    name: String,
    va: u64,
    bytes: String,
    section: String,
}

fn parse_anchors(input: &Input) -> Result<Vec<Anchor>, String> {
    let root = deg::json::parse(&input.text)
        .map_err(|e| format!("{} is not valid JSON: {e}", input.path.display()))?;
    let list = root
        .as_arr()
        .ok_or_else(|| format!("{} is not a JSON array of anchors", input.path.display()))?;
    let mut out = Vec::new();
    for (i, entry) in list.iter().enumerate() {
        let name = entry
            .get("name")
            .and_then(Json::as_str)
            .ok_or_else(|| format!("{}: anchor {i} has no `name`", input.path.display()))?
            .to_string();
        let va = parse_va(
            entry
                .get("va")
                .ok_or_else(|| format!("{}: anchor {i} has no `va`", input.path.display()))?,
            &format!("anchor {i} va"),
        )?;
        let bytes = spaced_hex(
            entry
                .get("bytes")
                .and_then(Json::as_str)
                .ok_or_else(|| format!("{}: anchor {i} has no `bytes`", input.path.display()))?,
            &format!("anchor {i} bytes"),
        )?;
        let section = entry
            .get("section")
            .and_then(Json::as_str)
            .unwrap_or(".text")
            .to_string();
        out.push(Anchor {
            name,
            va,
            bytes,
            section,
        });
    }
    Ok(out)
}

// ------------------------------------------------------------------- output

fn run_generate(args: &[String]) -> Result<String, String> {
    let o = parse_options(args)?;
    let out = o.out.as_ref().expect("--out checked above");

    // The output directory must be fresh or empty: the generator owns
    // everything inside it, and refusing a non-empty directory prevents
    // accidental overwrites of operator work.
    if out.exists() {
        if !out.is_dir() {
            return Err(format!(
                "--out {} exists and is not a directory",
                out.display()
            ));
        }
        let entries =
            fs::read_dir(out).map_err(|e| format!("cannot list --out {}: {e}", out.display()))?;
        if entries.count() > 0 {
            return Err(format!(
                "--out {} is not empty; the generator refuses to write into it",
                out.display()
            ));
        }
    } else {
        fs::create_dir_all(out)
            .map_err(|e| format!("cannot create --out {}: {e}", out.display()))?;
    }

    // Read every input up front; the generator never modifies them.
    let vectors = o
        .vectors
        .as_ref()
        .map(|p| read_input(p, "vectors file"))
        .transpose()?;
    let layouts = o
        .layouts
        .as_ref()
        .map(|p| read_input(p, "layouts file"))
        .transpose()?;
    let dispatch = o
        .dispatch
        .as_ref()
        .map(|p| read_input(p, "dispatch file"))
        .transpose()?;
    let artifacts = o
        .artifacts
        .as_ref()
        .map(|p| read_input(p, "artifacts file"))
        .transpose()?;
    let anchors = o
        .anchors
        .as_ref()
        .map(|p| read_input(p, "anchors file"))
        .transpose()?;

    // The client build (optional): hash and PE-parse to pick the arch.
    let mut client = None;
    if let Some(path) = &o.client {
        let bytes =
            fs::read(path).map_err(|e| format!("cannot read client {}: {e}", path.display()))?;
        let computed = sha256_hex(&bytes);
        let declared = match &o.client_sha {
            Some(s) => {
                let s = s.trim().to_ascii_lowercase();
                if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(format!("--client-sha is not a sha256 hex digest: {s:?}"));
                }
                if s != computed {
                    return Err(format!(
                        "--client-sha {s} does not match the file {} (sha256 {computed})",
                        path.display()
                    ));
                }
                s
            }
            None => computed,
        };
        let image = deg::pe::parse(&bytes)
            .map_err(|e| format!("client {} is not a parseable PE image: {e}", path.display()))?;
        client = Some(ClientInfo {
            path: path.clone(),
            sha256: declared,
            arch: if image.is_pe32 { "x86" } else { "x86_64" },
        });
    }
    let have_build = client.is_some();
    let sources = Sources {
        client,
        vectors,
        layouts,
        dispatch,
        artifacts,
        anchors,
    };

    // Pre-parse the structured inputs into the emission model.
    let dispatch_rows = sources
        .dispatch
        .as_ref()
        .map(parse_dispatch)
        .transpose()?
        .unwrap_or_default();
    let vec_ops = sources
        .vectors
        .as_ref()
        .map(vector_opcodes)
        .transpose()?
        .unwrap_or_default();
    let layout_ids = sources
        .layouts
        .as_ref()
        .map(layouts_ids)
        .transpose()?
        .unwrap_or_default();
    let artifacts_list = sources
        .artifacts
        .as_ref()
        .map(parse_artifacts)
        .transpose()?
        .unwrap_or_default();
    let anchors_list = sources
        .anchors
        .as_ref()
        .map(parse_anchors)
        .transpose()?
        .unwrap_or_default();

    // Opcode ids covered by a generated vector proof: vector opcodes that are
    // also in the layouts universe (the coverage claim's premises must name
    // ids the dataset contains, and vector proofs exist only with a build).
    let covered_ops: Vec<u8> = if have_build {
        vec_ops
            .iter()
            .copied()
            .filter(|op| layout_ids.contains(&(*op as u64)))
            .collect()
    } else {
        Vec::new()
    };
    let covered_set: BTreeSet<u8> = covered_ops.iter().copied().collect();

    // The generator writes the model's supporting files first (their digests
    // go into the model), then model.dg, then README.md.
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    let mut model = Model {
        names: Names::new(),
        client: sources.client.as_ref(),
        vec_ops: vec_ops.iter().copied().collect(),
        lines: Vec::new(),
    };
    model.header(&o, &sources);

    // 1. The client build (or a placeholder comment).
    model.build_decl();

    // 2. Vectors: copy + dataset + evidence + opcode rules + proofs.
    if let Some(input) = &sources.vectors {
        files.insert(
            "vectors.json".to_string(),
            fs::read(&input.path)
                .map_err(|e| format!("cannot re-read {}: {e}", input.path.display()))?,
        );
        model.vectors_section(input, &vec_ops, have_build);
    }

    // 3. Dispatch tables: CSV + dataset + evidence + bytes evidence + proofs.
    if let Some(input) = &sources.dispatch {
        let csv = dispatch_csv(&dispatch_rows);
        let csv_sha = sha256_hex(csv.as_bytes());
        files.insert("table-cases.csv".to_string(), csv.into_bytes());
        model.dispatch_section(input, &csv_sha, &dispatch_rows, have_build);
    }

    // 4. Anchors: fn decls + unique scans + proofs.
    if let Some(input) = &sources.anchors {
        model.anchors_section(input, &anchors_list, have_build);
    }

    // 5. Layouts: opcodes.txt + dataset + obligations + coverage claim.
    if let Some(input) = &sources.layouts {
        let ops_txt = opcodes_txt(&layout_ids);
        let ops_sha = sha256_hex(ops_txt.as_bytes());
        files.insert("opcodes.txt".to_string(), ops_txt.into_bytes());
        model.layouts_section(
            input,
            &ops_sha,
            &layout_ids,
            &covered_ops,
            o.target,
            have_build,
        );
    }

    // 6. Artifacts: CSV + dataset + capped rules + proofs + decision templates.
    if let Some(input) = &sources.artifacts {
        let csv = artifacts_csv(&artifacts_list);
        let csv_sha = sha256_hex(csv.as_bytes());
        files.insert("artifacts.csv".to_string(), csv.into_bytes());
        model.artifacts_section(input, &csv_sha, &artifacts_list, have_build);
        for a in &artifacts_list {
            files.insert(
                format!("decisions/{}.txt", a.hex),
                decision_template(a).into_bytes(),
            );
        }
    }

    // 7. The porting template.
    model.port_section(&o, &anchors_list);

    model.finish();

    files.insert("model.dg".to_string(), model.render().into_bytes());

    let mut written = Vec::new();
    for (rel, bytes) in &files {
        let path = out.join(rel);
        if let Some(parent) = path.parent() {
            if parent != out {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
        }
        fs::write(&path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        written.push(rel.clone());
    }
    written.sort();

    let readme = readme(
        &written,
        &sources,
        &covered_set,
        &layout_ids,
        &artifacts_list,
        have_build,
    );
    fs::write(out.join("README.md"), readme).map_err(|e| format!("cannot write README.md: {e}"))?;
    written.push("README.md".to_string());

    let mut summary = String::new();
    summary.push_str(&format!(
        "generated {} into {}\n",
        written.len(),
        out.display()
    ));
    summary.push_str(&format!("  files: {}\n", written.join(", ")));
    summary.push_str(&format!(
        "  client build: {}\n",
        sources
            .client
            .as_ref()
            .map(|c| format!(
                "{} (sha256 {}, arch {})",
                c.path.display(),
                c.sha256,
                c.arch
            ))
            .unwrap_or_else(|| "none (client-backed evidence skipped)".to_string())
    ));
    summary.push_str(&format!(
        "  vector opcodes with proofs: {}\n",
        if have_build {
            vec_ops.len().to_string()
        } else {
            "0 (no client build)".to_string()
        }
    ));
    summary.push_str(&format!(
        "  coverage premises: {covered_set:?} of {} layout id(s)\n",
        layout_ids.len()
    ));
    summary.push_str(&format!(
        "  observe obligations: {}\n",
        layout_ids.len() - covered_set.len()
    ));
    summary.push_str(&format!("  artifact templates: {}\n", artifacts_list.len()));
    Ok(summary)
}

struct ClientInfo {
    path: PathBuf,
    sha256: String,
    arch: &'static str,
}

/// The optional sources bundled together so the emitters' signatures stay
/// short: the client build plus every input file the operator provided.
struct Sources {
    client: Option<ClientInfo>,
    vectors: Option<Input>,
    layouts: Option<Input>,
    dispatch: Option<Input>,
    artifacts: Option<Input>,
    anchors: Option<Input>,
}

// ------------------------------------------------------------------- model

/// Accumulates the generated model text section by section.
struct Model<'a> {
    names: Names,
    client: Option<&'a ClientInfo>,
    /// The opcodes exercised by the vectors file (for conflict comments).
    vec_ops: BTreeSet<u8>,
    lines: Vec<String>,
}

impl Model<'_> {
    fn push(&mut self, line: &str) {
        self.lines.push(line.to_string());
    }

    fn blank(&mut self) {
        self.lines.push(String::new());
    }

    fn render(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    fn build_name(&self) -> &'static str {
        "ntk"
    }

    fn build_field(&self) -> String {
        if self.client.is_some() {
            format!(", build: {}", self.build_name())
        } else {
            String::new()
        }
    }

    fn header(&mut self, o: &Options, sources: &Sources) {
        self.push("// Generated by `deg-nexustk generate` (deg-nexustk version");
        self.push(&format!(
            "// {}). Do not edit by hand; regenerate with the command in",
            env!("CARGO_PKG_VERSION")
        ));
        self.push("// README.md next to this file. The generator is deterministic: the same");
        self.push("// inputs always produce byte-identical outputs.");
        self.push("//");
        self.push("// Provenance (input paths as given, digests computed at generation time):");
        match &sources.client {
            Some(c) => self.push(&format!(
                "//   client:     {} sha256: {} (format: pe, arch: {})",
                c.path.display(),
                c.sha256,
                c.arch
            )),
            None => self.push("//   client:     (not provided)"),
        }
        let mut note = |label: &str, input: Option<&Input>| match input {
            Some(i) => self.push(&format!(
                "//   {label:<11} {} sha256: {}",
                i.path.display(),
                i.sha256
            )),
            None => self.push(&format!("//   {label:<11} (not provided)")),
        };
        note("vectors:", sources.vectors.as_ref());
        note("layouts:", sources.layouts.as_ref());
        note("dispatch:", sources.dispatch.as_ref());
        note("artifacts:", sources.artifacts.as_ref());
        note("anchors:", sources.anchors.as_ref());
        if let Some(target) = o.target {
            self.push(&format!("//   target:     {target}"));
        }
        self.push("//");
        self.push("// Strength discipline:");
        self.push("//   - Deterministic: kernel-replayed facts only (bytes re-read from the");
        self.push("//     client, unique scans, content-addressed dataset parses, and the");
        self.push("//     compiled-in 7.52 vector replay).");
        self.push("//   - Observational (capped): generator-authored interpretation, e.g. the");
        self.push("//     artifact rules derived from artifacts.csv.");
        self.push("//   - Obligations/decisions: everything else stays open until evidence or");
        self.push("//     a human decision exists. Nothing here reaches Exact.");
        self.blank();
    }

    fn build_decl(&mut self) {
        match self.client {
            Some(c) => {
                self.push(&format!(
                    "build ntk = binary({},",
                    dg_string(&c.path.display().to_string())
                ));
                self.push(&format!("  sha256: {},", dg_string(&c.sha256)));
                self.push(&format!("  arch: {}, format: pe);", c.arch));
                self.blank();
            }
            None => {
                self.push("// No client given: the build declaration is omitted and all");
                self.push("// client-backed evidence (dispatch-table bytes, anchor scans) and the");
                self.push("// proofs that need a build are skipped. To enable them, rerun with:");
                self.push("//");
                self.push("//   deg-nexustk generate --client <path-to-client.exe> \\");
                self.push("//       [--client-sha <hex>] --out <dir> …");
                self.push("//");
                self.push("// build ntk = binary(\"<client>\", sha256: \"<sha256>\",");
                self.push("//   arch: x86, format: pe);");
                self.blank();
            }
        }
    }

    fn vectors_section(&mut self, input: &Input, vec_ops: &[u8], have_build: bool) {
        self.push("// ── known-answer vector replay ─────────────────────────────────────────────");
        self.push(&format!(
            "// vectors.json is the byte-exact copy of {}.",
            input.path.display()
        ));
        self.push(&format!(
            "dataset ds_vec = dataset(\"vectors.json\", sha256: {}{});",
            dg_string(&input.sha256),
            self.build_field()
        ));
        self.push("ev e_vec := ntk_vector(ds_vec, suite: \"all\");");
        self.blank();

        // The per-opcode derivation rules: a replayed frame or cipher vector
        // for an opcode yields a ground `opcode` fact.
        self.push("// Every opcode a replayed frame/cipher vector exercises becomes a ground");
        self.push("// opcode claim; the kernel re-derives the vector facts, so these proofs");
        self.push("// seal at Deterministic.");
        self.push("rule opcode_from_vector: opcode(?op) if frame_vector_ok(?e, ?n, ?d, ?op);");
        self.push("rule opcode_from_cipher: opcode(?op) if cipher_vector_ok(?e, ?n, ?d, ?op);");
        self.blank();

        if have_build {
            for op in vec_ops {
                let hex = hex_id(*op as u64);
                let pname = self.names.claim(&format!("P_op_{hex}"));
                self.push(&format!("proof {pname} : opcode({op}) in ntk {{"));
                self.push("  evidence e_vec;");
                self.push("  rules opcode_from_vector, opcode_from_cipher;");
                self.push("}");
            }
        } else {
            self.push("// No client build is declared, so the per-opcode proofs are skipped");
            self.push("// (`in ntk` needs the build). Add --client to generate them.");
        }
        self.blank();
    }

    fn dispatch_section(
        &mut self,
        input: &Input,
        csv_sha: &str,
        rows: &[TableRow],
        have_build: bool,
    ) {
        self.push("// ── dispatcher audit tables (bytes re-read from the client) ───────────────");
        self.push(&format!(
            "// table-cases.csv is derived from {} (table names, kinds, VAs, and",
            input.path.display()
        ));
        self.push("// file offsets). The bytes evidence below re-reads each declared VA from");
        self.push("// the client image, so the table-byte proofs are kernel-replayed.");
        self.push(&format!(
            "dataset ds_cases = dataset(\"table-cases.csv\", sha256: {}{});",
            dg_string(csv_sha),
            self.build_field()
        ));
        self.push("ev e_cases := table(ds_cases, has_header: true);");
        self.blank();

        let mut halves: Vec<(String, String, &TableHalf)> = Vec::new();
        for row in rows {
            if let Some(disp) = row.dispatcher_va {
                self.push(&format!("// {} dispatcher: 0x{:x}", row.name, disp));
            }
            // The model identifiers use a sanitized, collision-free table
            // name; the CSV keeps the audit's original name verbatim.
            let base = self.names.claim(&sanitize_ident(&row.name));
            if let Some(h) = &row.index {
                halves.push((base.clone(), "index".to_string(), h));
            }
            if let Some(h) = &row.case {
                halves.push((base, "case".to_string(), h));
            }
        }
        if !halves.is_empty() {
            self.blank();
        }

        if !have_build {
            self.push("// No client build is declared, so the per-table bytes evidence and the");
            self.push("// table-byte proofs are skipped. Add --client to generate them.");
            self.blank();
            return;
        }

        let mut claimed: Vec<(String, String)> = Vec::new();
        for (row_base, kind, h) in &halves {
            let sym = format!("{row_base}_{kind}");
            let ev_name = self.names.claim(&format!("e_{sym}"));
            self.push(&format!(
                "ev {ev_name} := bytes(ntk, at: 0x{:x}, expect: {});",
                h.va,
                dg_string(&h.bytes)
            ));
            claimed.push((sym, ev_name));
        }
        if !halves.is_empty() {
            self.blank();
        }

        let mut tva_rules = Vec::new();
        for (i, (_row_base, _kind, h)) in halves.iter().enumerate() {
            let (sym, ev_name) = &claimed[i];
            let rule_name = self.names.claim(&format!("tva_{sym}"));
            self.push(&format!(
                "rule {rule_name}: table_va({sym}, 0x{:x}) if bytes_ok({ev_name}, 0x{:x});",
                h.va, h.va
            ));
            tva_rules.push((rule_name, sym.clone(), ev_name.clone()));
        }
        if !halves.is_empty() {
            self.push(
                "rule table_bytes_ok: table_bytes_ok(?t) if table_va(?t, ?a) and bytes_ok(?e, ?a);",
            );
            self.blank();
        }

        for (rule_name, sym, ev_name) in &tva_rules {
            let pname = self.names.claim(&format!("P_{sym}"));
            self.push(&format!("proof {pname} : table_bytes_ok({sym}) in ntk {{"));
            self.push(&format!("  evidence {ev_name};"));
            self.push(&format!("  rules {rule_name}, table_bytes_ok;"));
            self.push("}");
        }
        self.blank();
    }

    fn anchors_section(&mut self, input: &Input, anchors: &[Anchor], have_build: bool) {
        if !have_build {
            self.push(
                "// ── client anchors ──────────────────────────────────────────────────────────",
            );
            self.push(&format!(
                "// {} declares {} anchor(s); the fn decls, scans, and proofs are skipped",
                input.path.display(),
                anchors.len()
            ));
            self.push("// without a client build. Add --client to generate them.");
            self.blank();
            return;
        }
        self.push("// ── client anchors (unique prologue scans) ─────────────────────────────────");
        self.push(&format!(
            "// One fn + unique scan per anchor declared in {}.",
            input.path.display()
        ));
        let mut fn_names = Vec::new();
        for a in anchors {
            let fname = self.names.claim(&sanitize_ident(&a.name));
            self.push(&format!("fn {fname} in ntk at 0x{:x};", a.va));
            fn_names.push((fname, a));
        }
        if !anchors.is_empty() {
            self.blank();
        }
        for (fname, a) in fn_names.iter() {
            let ev_name = self.names.claim(&format!("e_{fname}"));
            self.push(&format!(
                "ev {ev_name} := scan(ntk, {}, {}) |> unique;",
                dg_string(&a.section),
                dg_string(&a.bytes)
            ));
        }
        if !anchors.is_empty() {
            self.blank();
            self.push("rule anchored_at: anchored(?f, ?a) if fn_addr(?f, ?a) and scan_hit(?e, ?a) and scan_unique(?e);");
            self.blank();
        }
        for (fname, a) in fn_names.iter() {
            let ev_name = format!("e_{fname}");
            let pname = self.names.claim(&format!("P_{fname}"));
            self.push(&format!(
                "proof {pname} : anchored({fname}, 0x{:x}) in ntk {{",
                a.va
            ));
            self.push(&format!("  evidence {ev_name};"));
            self.push("  rules anchored_at;");
            self.push("}");
        }
        self.blank();
    }

    fn layouts_section(
        &mut self,
        input: &Input,
        ops_sha: &str,
        layout_ids: &[u64],
        covered_ops: &[u8],
        target: Option<u64>,
        have_build: bool,
    ) {
        self.push("// ── opcode universe and coverage ───────────────────────────────────────────");
        self.push(&format!(
            "// opcodes.txt lists every numeric opcode id mentioned anywhere in {}",
            input.path.display()
        ));
        self.push("// (layouts, unknowns, excluded). The dataset fixes the coverage universe;");
        self.push("// the vector opcode proofs above are the premises. DeG reports coverage,");
        self.push("// it never invents counts.");
        self.push(&format!(
            "dataset ds_ops = dataset(\"opcodes.txt\", sha256: {}{});",
            dg_string(ops_sha),
            self.build_field()
        ));
        self.blank();

        // Observe obligations for every layout id the generated vector proofs
        // do not cover.
        for id in layout_ids {
            if *id <= 0xff && covered_ops.contains(&(*id as u8)) {
                continue;
            }
            let hex = hex_id(*id);
            let oname = self.names.claim(&format!("O_observe_{hex}"));
            self.push(&format!(
                "obligation {oname} : observe_opcode({id}) priority: high;"
            ));
        }
        if !layout_ids.is_empty() {
            self.blank();
        }

        let covered_count = covered_ops.len();
        if have_build && covered_count > 0 {
            let target = target.unwrap_or(layout_ids.len() as u64);
            let premises = covered_ops
                .iter()
                .map(|op| format!("P_op_{}", hex_id(*op as u64)))
                .collect::<Vec<_>>()
                .join(", ");
            self.push(&format!(
                "claim C_cov : coverage(ds_ops, target: {target}) in ntk from {premises};"
            ));
        } else {
            let oname = self.names.claim("O_coverage");
            self.push(&format!(
                "obligation {oname} : opcode_coverage(ds_ops) priority: high;"
            ));
        }
        self.blank();
    }

    fn artifacts_section(
        &mut self,
        input: &Input,
        csv_sha: &str,
        artifacts: &[Artifact],
        have_build: bool,
    ) {
        self.push("// ── the artifact dossier ───────────────────────────────────────────────────");
        self.push(&format!(
            "// artifacts.csv is generator-authored from {} (id + role per artifact).",
            input.path.display()
        ));
        self.push("// The per-id rules are capped at Observational, so P_art_* stays a");
        self.push("// hypothesis by construction: the CSV content is the project's analysis,");
        self.push("// not a kernel-replayed fact.");
        self.push(&format!(
            "dataset ds_artifacts = dataset(\"artifacts.csv\", sha256: {}{});",
            dg_string(csv_sha),
            self.build_field()
        ));
        self.push("ev e_art := table(ds_artifacts, has_header: true);");
        self.blank();

        let mut rule_names = Vec::new();
        for (row_idx, a) in artifacts.iter().enumerate() {
            let rname = self.names.claim(&format!("art_{}", a.hex));
            self.push(&format!("rule {rname} cap observational:"));
            self.push(&format!(
                "  artifact({}) if row(e_art, {row_idx}, ?cells) and contains(?cells, {});",
                a.id,
                dg_string(&a.role)
            ));
            rule_names.push(rname);
        }
        if !artifacts.is_empty() {
            self.blank();
        }

        for (rname, a) in rule_names.iter().zip(artifacts) {
            if !have_build {
                break;
            }
            let pname = self.names.claim(&format!("P_art_{}", a.hex));
            self.push(&format!("proof {pname} : artifact({}) in ntk {{", a.id));
            self.push("  evidence e_art;");
            self.push(&format!("  rules {rname};"));
            self.push("}");
        }
        if !artifacts.is_empty() {
            self.blank();
        }

        // The commented-out decision + conflict per artifact. They name the
        // real claims (P_op_*/P_art_*); a human fills the decision file,
        // records its sha256, and uncomments both lines.
        for a in artifacts {
            self.push(&format!(
                "// To resolve the 0x{} artifact conflict: fill in",
                a.hex
            ));
            self.push(&format!(
                "// decisions/{}.txt, compute its sha256, and uncomment both lines.",
                a.hex
            ));
            if !have_build {
                self.push(&format!(
                    "// (P_art_{} and the conflict also need a client build; add --client)",
                    a.hex
                ));
            }
            if !self.vec_ops.contains(&(a.id as u8)) {
                self.push(&format!(
                    "// (P_op_{} is not generated yet: 0x{:02x} is not exercised by the",
                    a.hex, a.id
                ));
                self.push("//  vector file; add an opcode claim with its own evidence first)");
                self.push("// To create it from a frames.jsonl capture (ntk_frames facts are");
                self.push("// frame(ev, dir, op, channel, body_len, ts_us)), declare");
                self.push("// `ev e_frames := ntk_frames(<frames dataset>);` and add:");
                self.push(
                    "//   rule opcode_from_frames: opcode(?op) if frame(?e, ?d, ?op, ?c, ?l, ?t);",
                );
                self.push(&format!(
                    "//   proof P_op_{} : opcode({}) in ntk {{ evidence e_frames; rules opcode_from_frames; }}",
                    a.hex, a.id
                ));
            }
            self.push(&format!(
                "// decision D_{} := decision(\"decisions/{}.txt\", sha256: \"<REPLACE-WITH-ACTUAL-SHA256>\", prefer: P_art_{}, over: P_op_{}, signer: \"OPERATOR\");",
                a.hex, a.hex, a.hex, a.hex
            ));
            self.push(&format!(
                "// conflict C_{} : P_op_{} vs P_art_{} decision D_{} reason {};",
                a.hex,
                a.hex,
                a.hex,
                a.hex,
                dg_string(&a.role)
            ));
        }
        if !artifacts.is_empty() {
            self.blank();
        }
    }

    fn port_section(&mut self, o: &Options, anchors: &[Anchor]) {
        let Some(port_to) = &o.port_to else {
            return;
        };
        self.push("// ── porting template ───────────────────────────────────────────────────────");
        self.push("// Porting to a second client profile is a template, not a claim: add the");
        self.push("// second build declaration, then run `deg-nexustk port model.dg --to ntk2`.");
        self.push("//");
        self.push("// build ntk2 = binary(<path-to-the-second-client>, sha256: \"<sha256>\",");
        self.push("//   arch: x86, format: pe);");
        self.push("//");
        self.push("// port from ntk to ntk2 {");
        if anchors.is_empty() {
            self.push("//   // add one `rebase` line per anchored fn once --anchors is given:");
            self.push("//   // rebase <fn> by structural_similarity(64) min 0.55;");
        } else {
            for a in anchors {
                let fname = sanitize_ident(&a.name);
                self.push(&format!(
                    "//   rebase {fname} by structural_similarity(64) min 0.55;"
                ));
            }
        }
        self.push("// }");
        self.push(&format!(
            "//   (template references the operator-local client {port_to};"
        ));
        self.push("//   fill in the real path/sha256 before use)");
        self.blank();
    }

    fn finish(&mut self) {
        self.push("// ── end of generated model ─────────────────────────────────────────────────");
    }
}

// --------------------------------------------------------------- file makers

fn dispatch_csv(rows: &[TableRow]) -> String {
    let mut out = String::from("table,kind,va,file_offset\n");
    for row in rows {
        for (kind, half) in [("index", &row.index), ("case", &row.case)] {
            let Some(h) = half else { continue };
            let off = h
                .file_offset
                .map(|o| format!("0x{o:x}"))
                .unwrap_or_default();
            out.push_str(&format!("{},{},0x{:x},{off}\n", row.name, kind, h.va));
        }
    }
    out
}

fn opcodes_txt(ids: &[u64]) -> String {
    let mut out = String::new();
    for id in ids {
        out.push_str(&format!("{id}\n"));
    }
    out
}

fn artifacts_csv(artifacts: &[Artifact]) -> String {
    let mut out = String::from("id,role\n");
    for a in artifacts {
        out.push_str(&format!("{},{}\n", a.id, a.role));
    }
    out
}

fn decision_template(a: &Artifact) -> String {
    format!(
        concat!(
            "prefer: P_art_{hex}\n",
            "over: P_op_{hex}\n",
            "signer: OPERATOR-PENDING\n",
            "reason: {role}\n",
            "note: P_op_{hex} needs its own evidence first (see the commented block in model.dg)\n",
        ),
        hex = a.hex,
        role = a.role,
    )
}

fn readme(
    written: &[String],
    sources: &Sources,
    covered: &BTreeSet<u8>,
    layout_ids: &[u64],
    artifacts_list: &[Artifact],
    have_build: bool,
) -> String {
    let mut s = String::new();
    s.push_str("# Generated DeG model — provenance and trust boundaries\n\n");
    s.push_str(&format!(
        "Generated by `deg-nexustk generate` (deg-nexustk {}). Deterministic: the\n",
        env!("CARGO_PKG_VERSION")
    ));
    s.push_str("same inputs always produce byte-identical outputs.\n\n");
    s.push_str("## Inputs (read-only)\n\n");
    s.push_str("| role | path | sha256 |\n|---|---|---|\n");
    if let Some(c) = &sources.client {
        s.push_str(&format!(
            "| client | {} | {} |\n",
            c.path.display(),
            c.sha256
        ));
    }
    for (role, input) in [
        ("vectors", sources.vectors.as_ref()),
        ("layouts", sources.layouts.as_ref()),
        ("dispatch", sources.dispatch.as_ref()),
        ("artifacts", sources.artifacts.as_ref()),
        ("anchors", sources.anchors.as_ref()),
    ] {
        match input {
            Some(i) => s.push_str(&format!(
                "| {role} | {} | {} |\n",
                i.path.display(),
                i.sha256
            )),
            None => s.push_str(&format!("| {role} | (not provided) | — |\n")),
        }
    }
    s.push('\n');
    s.push_str("## Files written here\n\n");
    for f in written {
        s.push_str(&format!("- `{f}`\n"));
    }
    s.push('\n');
    s.push_str("## What is machine-checked (Deterministic)\n\n");
    s.push_str("- the client image: hash-pinned, PE-section-mapped (`format: pe`);\n");
    if have_build {
        s.push_str("- dispatch audit table bytes re-read from the client at the declared VAs\n");
        s.push_str("  (`P_<table>_<kind>` proofs);\n");
        s.push_str("- unique anchor scans at the declared function addresses (`P_<anchor>`\n");
        s.push_str("  proofs);\n");
        s.push_str("- the 7.52 vector replay and every `opcode(<id>)` proof derived from it\n");
        s.push_str("  (`P_op_<hex>` proofs);\n");
    } else {
        s.push_str("- (no client given: bytes/scan proofs are skipped; add `--client`)\n");
    }
    s.push_str("- the content-addressed parses of `vectors.json`, `table-cases.csv`,\n");
    s.push_str("  `opcodes.txt`, and `artifacts.csv`.\n\n");
    s.push_str("## Generator-authored assumptions (capped Observational)\n\n");
    s.push_str("- the artifact rules (`art_<hex>`) read `artifacts.csv`, which is the\n");
    s.push_str("  project's analysis, not a kernel-replayed fact: each rule is capped at\n");
    s.push_str("  Observational, so `P_art_<hex>` stays a hypothesis.\n");
    s.push_str("- the VA assignments (`table_va`) are copied from the dispatch audit\n");
    s.push_str("  verbatim; the proofs re-read those bytes from the client, they do not\n");
    s.push_str("  re-derive the audit's decoding of them.\n\n");
    s.push_str("## Open obligations and human decisions\n\n");
    s.push_str("- `O_observe_<hex>`: one per layout id without a vector opcode proof\n");
    s.push_str(&format!(
        "  ({} of {} ids covered: {:?}).\n",
        covered.len(),
        layout_ids.len(),
        covered
    ));
    s.push_str("- `O_coverage` (when no coverage claim was generated).\n");
    if !artifacts_list.is_empty() {
        s.push_str("- the artifact conflicts stay commented out until a human writes\n");
        s.push_str("  `decisions/<hex>.txt`, computes its sha256, and uncomments the\n");
        s.push_str("  `decision`/`conflict` lines in `model.dg`.\n");
    }
    s.push('\n');
    s.push_str("## Commands\n\n```console\n");
    s.push_str("$ deg-nexustk check model.dg\n");
    s.push_str("$ deg-nexustk check model.dg --json\n");
    s.push_str("$ deg-nexustk seal model.dg --out model.lock.json\n");
    s.push_str("```\n");
    s
}

// -------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_ident_produces_de_identifiers() {
        assert_eq!(sanitize_ident("MapPane::OnPacket"), "mappane_onpacket");
        assert_eq!(sanitize_ident("send_shape_a"), "send_shape_a");
        assert_eq!(sanitize_ident("0x79"), "x0x79");
        assert_eq!(sanitize_ident(""), "");
        assert_eq!(sanitize_ident("__a__"), "a");
    }

    #[test]
    fn names_claim_disambiguates_collisions() {
        let mut n = Names::new();
        assert_eq!(n.claim("mappane"), "mappane");
        assert_eq!(n.claim("mappane"), "mappane_2");
        assert_eq!(n.claim("mappane"), "mappane_3");
    }

    #[test]
    fn compact_hex_validates_and_normalizes() {
        assert_eq!(compact_hex("8C 7C 50 00", "t").unwrap(), "8c7c5000");
        assert_eq!(compact_hex("8c,7c_50 00", "t").unwrap(), "8c7c5000");
        assert!(compact_hex("8c7", "t").is_err());
        assert!(compact_hex("zz", "t").is_err());
        assert!(compact_hex("", "t").is_err());
        assert_eq!(spaced_hex("8C7C5000", "t").unwrap(), "8c 7c 50 00");
    }

    #[test]
    fn collect_ids_accepts_hex_strings_and_skips_words() {
        let j = deg::json::parse(
            r#"{"layouts":[{"opcode":12},{"opcode":"0x0c"}],
                "sources":[{"id":"protocol-752"}],
                "unknowns":[{"opcode":121}],
                "universe":{"expected_count":82}}"#,
        )
        .unwrap();
        let mut ids = BTreeSet::new();
        collect_ids(&j, &mut ids);
        assert_eq!(ids.into_iter().collect::<Vec<_>>(), vec![12, 121]);
    }

    #[test]
    fn decision_template_and_artifacts_csv_are_stable() {
        let a = Artifact {
            id: 121,
            hex: "79".to_string(),
            role: "body-field".to_string(),
        };
        assert_eq!(
            decision_template(&a),
            concat!(
                "prefer: P_art_79\n",
                "over: P_op_79\n",
                "signer: OPERATOR-PENDING\n",
                "reason: body-field\n",
                "note: P_op_79 needs its own evidence first (see the commented block in model.dg)\n",
            )
        );
        assert_eq!(artifacts_csv(&[a]), "id,role\n121,body-field\n");
    }
}
