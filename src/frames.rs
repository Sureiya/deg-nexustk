//! The `ntk_frames` evidence kind: structural facts over a `frames.jsonl`
//! capture dataset.
//!
//! Only structure is ever emitted — direction, opcode, channel, body length,
//! and timestamp. Packet bodies, keys, and credential material are never
//! emitted into facts or details, and the emitted strength is Observational:
//! the dataset is a capture-derived observation, not something this evaluator
//! re-derives from verified bytes.

use deg::artifact::ArtifactSet;
use deg::ast::EvidenceDecl;
use deg::evidence::EvidenceOutcome;
use deg::json::Json;
use deg::semantic::ModelIndex;
use deg::strength::Strength;
use deg::value::Value;

pub const KIND: &str = "ntk_frames";

/// Evaluate `ntk_frames(ds_name, [max_frames: n])`.
pub fn eval(
    _index: &ModelIndex,
    artifacts: &ArtifactSet,
    decl: &EvidenceDecl,
) -> Result<EvidenceOutcome, String> {
    let (ds_name, max_frames) = match &decl.kind {
        deg::ast::EvidenceKind::Extension { args, .. } => (
            args.positional_string(0)
                .ok_or_else(|| "ntk_frames needs a dataset name".to_string())?,
            args.u64("max_frames"),
        ),
        _ => return Err("ntk_frames evaluator called on a non-extension".into()),
    };
    let text = artifacts.dataset_text(&ds_name)?;

    let mut out = EvidenceOutcome::new(&decl.name, KIND, Strength::Observational, String::new());
    let mut count = 0usize;
    let mut skipped = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Json::Obj(obj) = deg::json::parse(line).unwrap_or(Json::Null) else {
            skipped += 1;
            continue;
        };
        // Real captures interleave connect/close/logger events; only rows
        // whose `event` is absent or `"frame"` are frame facts.
        if let Some(event) = obj.get("event").and_then(Json::as_str) {
            if event != "frame" {
                skipped += 1;
                continue;
            }
        }
        let dir = obj.get("dir").and_then(Json::as_str).unwrap_or("");
        let op = obj.get("op").and_then(Json::as_u64).unwrap_or(0);
        let channel = obj.get("channel").and_then(Json::as_str).unwrap_or("");
        // Real captures truncate `bodyHex` with a `…<N>` marker; the declared
        // body length (`bodyDeclaredLen`, or the captured byte count) wins
        // over counting hex chars.
        let body_len = if let Some(n) = obj.get("bodyDeclaredLen").and_then(Json::as_u64) {
            n as usize
        } else if let Some(n) = obj.get("bodyHexCaptured").and_then(Json::as_u64) {
            n as usize
        } else {
            obj.get("bodyHex")
                .and_then(Json::as_str)
                .map(|s| s.len() / 2)
                .unwrap_or(0)
        };
        // The frames schema records `ts` in epoch milliseconds; the fact is
        // emitted in microseconds (the DeG duration convention).
        let ts_us = obj
            .get("ts")
            .and_then(Json::as_u64)
            .map(|t| t.saturating_mul(1000))
            .unwrap_or(0);
        out.fact(
            "frame",
            vec![
                Value::sym(&decl.name),
                Value::sym(dir),
                Value::Int(op as i128),
                Value::sym(channel),
                Value::Int(body_len as i128),
                Value::Duration(ts_us),
            ],
        );
        count += 1;
    }

    if let Some(max) = max_frames {
        if count > max as usize {
            return Err(format!("frame count exceeds max_frames: {count} > {max}"));
        }
    }

    out.summary = format!("{count} frames from {ds_name}");
    out.fact(
        "frame_count",
        vec![Value::sym(&decl.name), Value::Int(count as i128)],
    );
    out.detail("count", count.to_string());
    out.detail("redaction", "bodies are never emitted");
    out.detail("skipped_lines", skipped.to_string());
    out.detail("dataset", ds_name.clone());
    Ok(out)
}

/// The build this evidence is bound to: the dataset's declared build.
pub fn build_hook(index: &ModelIndex, decl: &EvidenceDecl) -> Option<String> {
    let ds_name = match &decl.kind {
        deg::ast::EvidenceKind::Extension { args, .. } => args.positional_string(0)?,
        _ => return None,
    };
    index.datasets.get(&ds_name).and_then(|d| d.build.clone())
}
