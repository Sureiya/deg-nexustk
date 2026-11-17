//! The `ntk_bundle` evidence kind: the `kaze.bundle/v1` verification subset.
//!
//! The evaluator re-derives every claim from the verified manifest dataset's
//! bytes and from files next to it on disk, so its facts are Deterministic:
//!
//! * the manifest is JSON, and the SHA-256 of its canonical form (sorted
//!   keys, compact `,`/`:` separators, non-ASCII raw) with **both** the
//!   `seal` and `verify` keys removed equals the reference digest;
//! * when an index dataset is declared, its package entry pins the bundle id,
//!   the raw manifest SHA-256, and the reference digest;
//! * the manifest's `evidence` entry names a file next to the manifest whose
//!   SHA-256 matches;
//! * the manifest's `files` entries (when present) each name a file next to
//!   the manifest whose SHA-256 matches;
//! * every `blobs` entry references `blobs/sha256/<aa>/<bb>/<sha256>`
//!   relative to the manifest directory, the file exists, and its content
//!   hash equals the name.
//!
//! Two schema generations are accepted. The live manifests carry
//! `seal: {algorithm, sha256}`, a `bundles` index array, and blob entries
//! that are objects with `sha256`/`kind`/`bytes`/`source_ref` and no `path`
//! (the canonical path is derived from the digest). The documented schema
//! describes `verify: {algorithm, sha256}`, a `packages` index array, and
//! blob entries that carry their `path` directly. Both are accepted; the
//! reference digest always drops both `seal` and `verify`.
//!
//! Unknown or absent optional fields are tolerated (and noted in details);
//! a `seal.sha256` or `verify.sha256` reference digest is required.

use deg::artifact::ArtifactSet;
use deg::ast::EvidenceDecl;
use deg::evidence::EvidenceOutcome;
use deg::json::Json;
use deg::semantic::ModelIndex;
use deg::sha256::sha256_hex;
use deg::strength::Strength;
use deg::value::Value;
use std::fs;
use std::path::{Path, PathBuf};

pub const KIND: &str = "ntk_bundle";

/// Canonical JSON serialization compatible with the documented reference
/// digest convention: sorted keys, `:`/`,` separators, no whitespace, and
/// non-ASCII emitted raw (`ensure_ascii=false`). The packager computes the
/// reference digests with Python's
/// `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`;
/// this writer produces the same bytes for the same object. Manifests should
/// therefore keep numbers integral: a float like `5.0` round-trips as `5`.
pub fn canonical_json(value: &Json) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Num(n) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                out.push_str(&format!("{}", *n as i64));
            } else {
                out.push_str(&format!("{n}"));
            }
        }
        Json::Str(s) => write_escaped(s, out),
        Json::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Json::Obj(map) => {
            out.push('{');
            for (i, (key, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_escaped(key, out);
                out.push(':');
                write_canonical(val, out);
            }
            out.push('}');
        }
    }
}

fn write_escaped(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn obj_string<'a>(obj: &'a Json, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(Json::as_str)
}

fn is_lowercase_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Verify one `blobs/sha256/<aa>/<bb>/<sha256>` reference: the canonical
/// content-addressing layout, where `<aa>`/`<bb>` are the first two bytes of
/// the digest.
fn blob_path_parts(path: &str) -> Option<(String, String, String)> {
    let mut parts = path.split('/');
    let b0 = parts.next()?;
    let b1 = parts.next()?;
    let aa = parts.next()?;
    let bb = parts.next()?;
    let digest = parts.next()?;
    if parts.next().is_some() || b0 != "blobs" || b1 != "sha256" {
        return None;
    }
    if !is_lowercase_hex64(digest) {
        return None;
    }
    if aa.len() != 2 || bb.len() != 2 {
        return None;
    }
    if !digest.starts_with(aa) || !digest[2..].starts_with(bb) {
        return None;
    }
    Some((aa.to_string(), bb.to_string(), digest.to_string()))
}

/// The canonical blob path derived from a digest:
/// `blobs/sha256/<aa>/<bb>/<sha256>`.
fn canonical_blob_path(digest: &str) -> Result<String, String> {
    if !is_lowercase_hex64(digest) {
        return Err(format!("digest {digest:?} is not a canonical sha256"));
    }
    Ok(format!(
        "blobs/sha256/{}/{}/{digest}",
        &digest[..2],
        &digest[2..4]
    ))
}

/// The reference digest of a manifest: the canonical form without the `seal`
/// and `verify` keys, and the declared digest(s) those keys carry.
fn manifest_digest(obj: &std::collections::BTreeMap<String, Json>) -> Result<String, String> {
    let mut declared: Vec<(&str, String)> = Vec::new();
    for key in ["seal", "verify"] {
        let Some(sig) = obj.get(key) else {
            continue;
        };
        if let Some(algo) = obj_string(sig, "algorithm") {
            if algo != "sha256" {
                return Err(format!(
                    "manifest `{key}.algorithm` is {algo:?}, want \"sha256\""
                ));
            }
        }
        if let Some(sha) = obj_string(sig, "sha256") {
            declared.push((key, sha.to_string()));
        }
    }
    if declared.is_empty() {
        return Err(
            "manifest has no `seal.sha256` or `verify.sha256` reference digest".to_string(),
        );
    }
    let mut payload = obj.clone();
    payload.remove("seal");
    payload.remove("verify");
    let digest = sha256_hex(canonical_json(&Json::Obj(payload)).as_bytes());
    for (key, sha) in &declared {
        if sha != &digest {
            return Err(format!(
                "manifest verify digest mismatch: {key}.sha256 is {sha}, computed {digest}"
            ));
        }
    }
    Ok(digest)
}

/// Evaluate `ntk_bundle(manifest_ds, bundle_id, [index_ds: name])`.
pub fn eval(
    _index: &ModelIndex,
    artifacts: &ArtifactSet,
    decl: &EvidenceDecl,
) -> Result<EvidenceOutcome, String> {
    let (manifest_ds, bundle_id, index_ds) = match &decl.kind {
        deg::ast::EvidenceKind::Extension { args, .. } => (
            args.positional_string(0)
                .ok_or_else(|| "ntk_bundle needs a manifest dataset".to_string())?,
            args.positional_string(1)
                .ok_or_else(|| "ntk_bundle needs a bundle id".to_string())?,
            args.string("index_ds"),
        ),
        _ => return Err("ntk_bundle evaluator called on a non-extension".into()),
    };

    let manifest_art = artifacts
        .items
        .get(&manifest_ds)
        .ok_or_else(|| format!("unknown dataset `{manifest_ds}`"))?;
    let manifest_dir: PathBuf = manifest_art
        .resolved_path
        .parent()
        .ok_or_else(|| "manifest dataset has no parent directory".to_string())?
        .to_path_buf();
    let manifest_text = artifacts.dataset_text(&manifest_ds)?;
    let manifest_sha = sha256_hex(manifest_text.as_bytes());

    let root =
        deg::json::parse(&manifest_text).map_err(|e| format!("manifest is not valid JSON: {e}"))?;
    let obj = root
        .as_obj()
        .ok_or_else(|| "manifest is not a JSON object".to_string())?;

    // The reference digest: seal (live manifests) or verify (the documented
    // schema); both keys are dropped from the canonical payload.
    let digest = manifest_digest(obj)?;

    // The bundle id argument must agree with the manifest's own id, when the
    // manifest declares one.
    for key in ["bundle_id", "package_id"] {
        if let Some(manifest_id) = obj_string(&root, key) {
            if manifest_id != bundle_id {
                return Err(format!(
                    "manifest bundle id mismatch: argument {bundle_id:?}, manifest {manifest_id:?}"
                ));
            }
        }
    }

    // Index pin (optional but recommended): the index must contain a package
    // entry for this bundle whose manifest/seal hashes match the computed
    // values. Live indexes use a `bundles` array; the documented schema calls
    // it `packages`.
    let index_status = match &index_ds {
        Some(name) => {
            let index_text = artifacts.dataset_text(name)?;
            let index_root = deg::json::parse(&index_text)
                .map_err(|e| format!("index dataset `{name}` is not valid JSON: {e}"))?;
            let packages = index_root
                .get("packages")
                .or_else(|| index_root.get("bundles"))
                .and_then(Json::as_arr)
                .ok_or_else(|| "index has no packages/bundles array".to_string())?;
            let entry = packages.iter().find(|p| {
                obj_string(p, "bundle_id")
                    .or_else(|| obj_string(p, "package_id"))
                    .map(|id| id == bundle_id)
                    .unwrap_or(false)
            });
            let Some(entry) = entry else {
                return Err(format!(
                    "index has no package entry for bundle id {bundle_id:?}"
                ));
            };
            let entry_manifest = obj_string(entry, "manifest_sha256").unwrap_or("");
            if entry_manifest != manifest_sha {
                return Err(format!(
                    "index manifest_sha256 mismatch: expected {entry_manifest}, got {manifest_sha}"
                ));
            }
            let entry_seal = obj_string(entry, "seal_sha256").unwrap_or("");
            if entry_seal != digest {
                return Err(format!(
                    "index seal_sha256 mismatch: expected {entry_seal}, got {digest}"
                ));
            }
            format!("pinned by index dataset `{name}`")
        }
        None => "index not provided; hash chain not pinned".to_string(),
    };

    // The evidence document: a file next to the manifest with a matching
    // SHA-256.
    let evidence = obj
        .get("evidence")
        .ok_or_else(|| "manifest has no `evidence` object".to_string())?;
    let evidence_path = obj_string(evidence, "path")
        .ok_or_else(|| "manifest `evidence.path` is required".to_string())?;
    let evidence_sha = obj_string(evidence, "sha256")
        .ok_or_else(|| "manifest `evidence.sha256` is required".to_string())?;
    let evidence_file = manifest_dir.join(evidence_path);
    let evidence_bytes = fs::read(&evidence_file)
        .map_err(|e| format!("evidence file `{evidence_path}` is missing: {e}"))?;
    let evidence_actual = sha256_hex(&evidence_bytes);
    if evidence_actual != evidence_sha {
        return Err(format!(
            "evidence hash mismatch for `{evidence_path}`: expected {evidence_sha}, got {evidence_actual}"
        ));
    }
    let evidence_entries = count_evidence_entries(&evidence_bytes);

    // The `files` array (live manifests list every loose package file here):
    // each entry `{path, sha256, bytes?}` must exist next to the manifest and
    // hash to its declared SHA-256.
    let file_count = obj
        .get("files")
        .and_then(Json::as_arr)
        .map_or(0, |f| f.len());
    if let Some(files) = obj.get("files").and_then(Json::as_arr) {
        for (i, entry) in files.iter().enumerate() {
            let path =
                obj_string(entry, "path").ok_or_else(|| format!("files entry {i} has no path"))?;
            if Path::new(path).is_absolute() {
                return Err(format!("files entry {i} path `{path}` is absolute"));
            }
            let sha = obj_string(entry, "sha256")
                .ok_or_else(|| format!("files entry {i} has no sha256"))?;
            let file = manifest_dir.join(path);
            let bytes =
                fs::read(&file).map_err(|e| format!("files entry {i} `{path}` is missing: {e}"))?;
            let actual = sha256_hex(&bytes);
            if actual != sha {
                return Err(format!(
                    "files entry {i} hash mismatch for `{path}`: expected {sha}, got {actual}"
                ));
            }
        }
    }

    // Every blob must exist at its canonical content-addressed path and hash
    // to its name. Live entries declare `sha256` and no path; documented
    // entries carry a `path` (both forms may carry the other field, and they
    // must agree).
    let blobs = obj.get("blobs").and_then(Json::as_arr);
    let blob_count = blobs.map(|b| b.len()).unwrap_or(0);
    let mut blob_facts = Vec::new();
    if let Some(blobs) = blobs {
        for (i, entry) in blobs.iter().enumerate() {
            let path = match entry {
                Json::Str(s) => Some(s.as_str()),
                obj => obj.get("path").and_then(Json::as_str),
            };
            let path = match path {
                Some(p) => p.to_string(),
                None => {
                    let sha = obj_string(entry, "sha256")
                        .ok_or_else(|| format!("blob {i} has no path or sha256"))?;
                    canonical_blob_path(sha).map_err(|e| format!("blob {i} {e}"))?
                }
            };
            let (_aa, _bb, digest) = blob_path_parts(&path).ok_or_else(|| {
                format!("blob {i} path `{path}` is not a canonical blob reference")
            })?;
            if let Some(sha) = obj_string(entry, "sha256") {
                if sha != digest {
                    return Err(format!("blob {i} sha256 does not match its path digest"));
                }
            }
            let blob_file = manifest_dir.join(&path);
            let bytes =
                fs::read(&blob_file).map_err(|e| format!("blob {i} `{path}` is missing: {e}"))?;
            let actual = sha256_hex(&bytes);
            if actual != digest {
                return Err(format!(
                    "blob {i} hash mismatch for `{path}`: expected {digest}, got {actual}"
                ));
            }
            blob_facts.push((i, digest));
        }
    }

    let mut out = EvidenceOutcome::new(
        &decl.name,
        KIND,
        Strength::Deterministic,
        format!("bundle {bundle_id} verified ({blob_count} blobs)"),
    );
    out.fact(
        "bundle_verified",
        vec![
            Value::sym(&decl.name),
            Value::sym(bundle_id.clone()),
            Value::sym(manifest_sha.clone()),
        ],
    );
    out.fact(
        "bundle_entries",
        vec![Value::sym(&decl.name), Value::Int(evidence_entries as i128)],
    );
    out.fact(
        "bundle_blobs",
        vec![Value::sym(&decl.name), Value::Int(blob_count as i128)],
    );
    out.fact(
        "bundle_evidence_ok",
        vec![Value::sym(&decl.name), Value::sym(evidence_path)],
    );
    for (i, digest) in blob_facts {
        out.fact(
            "blob_ok",
            vec![
                Value::sym(&decl.name),
                Value::Int(i as i128),
                Value::sym(digest),
            ],
        );
    }
    out.detail("manifest", manifest_art.resolved_path.display().to_string());
    out.detail("index", index_status);
    out.detail("evidence_entries", evidence_entries.to_string());
    out.detail("blobs", blob_count.to_string());
    out.detail("files", file_count.to_string());
    Ok(out)
}

/// The number of evidence entries in an evidence document: the total length
/// of every top-level list value (the documented `count_evidence` convention).
/// Best-effort: an unparseable evidence document still passes its hash check
/// and contributes zero here.
fn count_evidence_entries(bytes: &[u8]) -> usize {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return 0;
    };
    let Ok(root) = deg::json::parse(text) else {
        return 0;
    };
    root.as_obj()
        .map(|obj| {
            obj.values()
                .filter_map(Json::as_arr)
                .map(|list| list.len())
                .sum()
        })
        .unwrap_or(0)
}

/// The build this evidence is bound to: the manifest dataset's declared build.
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

    #[test]
    fn canonical_json_matches_the_python_convention() {
        let j = deg::json::parse(r#"{"z":1,"a":[true,null,"x\ny"],"n":{},"s":"héllo"}"#).unwrap();
        assert_eq!(
            canonical_json(&j),
            r#"{"a":[true,null,"x\ny"],"n":{},"s":"héllo","z":1}"#
        );
    }

    #[test]
    fn canonical_json_writes_integral_numbers_compactly() {
        let j = deg::json::parse(r#"{"n":3}"#).unwrap();
        assert_eq!(canonical_json(&j), r#"{"n":3}"#);
    }

    #[test]
    fn manifest_digest_drops_both_seal_and_verify() {
        // A manifest declaring both keys: the digest covers neither, and both
        // declared values must match it.
        let placeholder = "0".repeat(64);
        let mut text = format!(
            r#"{{"schema":"kaze.bundle/v1","bundle_id":"bnd_x","a":1,"seal":{{"algorithm":"sha256","sha256":"{placeholder}"}},"verify":{{"algorithm":"sha256","sha256":"{placeholder}"}}}}"#
        );
        let probe = deg::json::parse(&text).unwrap();
        let mut obj = probe.as_obj().unwrap().clone();
        obj.remove("seal");
        obj.remove("verify");
        let digest = sha256_hex(canonical_json(&Json::Obj(obj)).as_bytes());
        text = text.replace(&placeholder, &digest);
        let root = deg::json::parse(&text).unwrap();
        assert_eq!(manifest_digest(root.as_obj().unwrap()).unwrap(), digest);

        // A tampered seal fails the digest check.
        let bad = text.replace(
            &format!("\"sha256\":\"{digest}\""),
            &format!("\"sha256\":\"{}\"", "1".repeat(64)),
        );
        let root = deg::json::parse(&bad).unwrap();
        let err = manifest_digest(root.as_obj().unwrap()).unwrap_err();
        assert!(err.contains("manifest verify digest mismatch"), "{err}");

        // No seal/verify at all is an error.
        let root = deg::json::parse(r#"{"schema":"kaze.bundle/v1"}"#).unwrap();
        let err = manifest_digest(root.as_obj().unwrap()).unwrap_err();
        assert!(err.contains("no `seal.sha256` or `verify.sha256`"), "{err}");
    }

    #[test]
    fn blob_references_are_strict() {
        assert_eq!(
            blob_path_parts(
                "blobs/sha256/79/72/797245401e527de9ebfe7638c6570d42e81592791ac469d886eac89568855eba"
            )
            .unwrap()
            .2,
            "797245401e527de9ebfe7638c6570d42e81592791ac469d886eac89568855eba"
        );
        assert!(blob_path_parts("blobs/sha256/79/72/short").is_none());
        assert!(blob_path_parts("../blobs/sha256/79/72/797245401e527de9ebfe7638c6570d42e81592791ac469d886eac89568855eba").is_none());
        assert!(blob_path_parts(
            "blobs/sha256/ab/cd/797245401e527de9ebfe7638c6570d42e81592791ac469d886eac89568855eba"
        )
        .is_none());
        assert!(blob_path_parts("blobs/sha256/79/72/797245401e527de9ebfe7638c6570d42e81592791ac469d886eac89568855eba/extra").is_none());
        assert!(blob_path_parts(
            "blobs/sha256/79/72/797245401E527DE9EBFE7638C6570D42E81592791AC469D886EAC89568855EBA"
        )
        .is_none());
    }

    #[test]
    fn canonical_blob_path_derives_from_the_digest() {
        let digest = "797245401e527de9ebfe7638c6570d42e81592791ac469d886eac89568855eba";
        assert_eq!(
            canonical_blob_path(digest).unwrap(),
            "blobs/sha256/79/72/797245401e527de9ebfe7638c6570d42e81592791ac469d886eac89568855eba"
        );
        assert!(canonical_blob_path("short").is_err());
        assert!(canonical_blob_path(&digest.to_uppercase()).is_err());
    }

    /// The real operator-local package cross-check. Never run in CI; the
    /// package and index are operator-local. See README.md.
    #[test]
    #[ignore]
    fn ntk_real_bundle() {
        let bundle_dir = std::env::var("NTK_BUNDLE")
            .expect("set NTK_BUNDLE to a real kaze.bundle/v1 directory to cross-check");
        let index_path = std::env::var("NTK_BUNDLE_INDEX")
            .expect("set NTK_BUNDLE_INDEX to the capture index.json to cross-check");
        crate::register_once();

        let manifest_path = Path::new(&bundle_dir).join("manifest.json");
        let manifest_text =
            std::fs::read_to_string(&manifest_path).expect("manifest.json is readable");
        let root = deg::json::parse(&manifest_text).expect("manifest parses");
        let bundle_id = obj_string(&root, "bundle_id")
            .or_else(|| obj_string(&root, "package_id"))
            .expect("manifest declares a bundle id")
            .to_string();

        let src = format!(
            "dataset ds_manifest = dataset({:?}, sha256: {:?});\n\
             dataset ds_index = dataset({:?}, sha256: {:?});\n\
             ev e := ntk_bundle(ds_manifest, {:?}, index_ds: ds_index);\n",
            manifest_path.display().to_string(),
            sha256_hex(manifest_text.as_bytes()),
            index_path,
            sha256_hex(&std::fs::read(&index_path).expect("index is readable")),
            bundle_id
        );
        let model =
            deg::parser::parse_model("/tmp/ntk-real-bundle.dg", &src).expect("model parses");
        let index = ModelIndex::new(&model).expect("model indexes");
        let artifacts = ArtifactSet::load(&model, None);
        assert!(
            artifacts.errors.is_empty(),
            "artifact errors: {:?}",
            artifacts.errors
        );
        let report = deg::kernel::check(&index, &artifacts);
        let outcome = report.evidence.get("e").expect("evidence e evaluated");
        assert!(outcome.ok, "real bundle failed: {:?}", outcome.error);
        assert_eq!(outcome.strength, Strength::Deterministic);
        assert!(outcome
            .details
            .iter()
            .any(|(k, v)| k == "index" && v.starts_with("pinned by index dataset")));
        eprintln!(
            "ntk_real_bundle: {} verified ({} blobs, {} files)",
            bundle_id,
            outcome
                .details
                .iter()
                .find(|(k, _)| k == "blobs")
                .map(|(_, v)| v.as_str())
                .unwrap_or("?"),
            outcome
                .details
                .iter()
                .find(|(k, _)| k == "files")
                .map(|(_, v)| v.as_str())
                .unwrap_or("?")
        );
    }
}
