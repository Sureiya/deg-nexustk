//! `deg-nexustk`: the NexusTK 7.52 protocol adapter for the DeG proof
//! checker.
//!
//! This crate compiles three reviewed evidence extensions into the extended
//! checker binary (`deg-nexustk`), all registered at startup:
//!
//! * [`ntk_vector`](crate::vectors) — replays known-answer 7.52
//!   framing/cipher/tail/key-table vectors and re-derives the answers from
//!   the documented algorithms (Deterministic);
//! * [`ntk_frames`](crate::frames) — structural facts over a `frames.jsonl`
//!   capture dataset, never body bytes (Observational);
//! * [`ntk_bundle`](crate::bundle) — verifies the `kaze.bundle/v1` layout
//!   (manifest digest, index pin, evidence file, blobs) (Deterministic);
//! * [`generate`](crate::generate) — the `deg-nexustk generate` lane that
//!   turns the project's audit artifacts (dispatch audit, opcode layouts,
//!   artifact dossier, known-answer vectors) into a deterministic `.dg`
//!   model, decision templates, and a provenance README.
//!
//! The core `deg` binary registers none of these; a model that names them
//! fails loudly under it. See `README.md` for the trust model and
//! the strength rules.

pub mod bundle;
pub mod codec;
pub mod frames;
pub mod generate;
pub mod md5;
pub mod vectors;

/// Register the three NexusTK evidence kinds. Idempotent callers must run
/// this exactly once before `deg::cli::run()`; duplicate registration is a
/// startup error by design.
pub fn register() {
    deg::ext::register(
        "ntk_vector",
        deg::ext::Extension {
            eval: vectors::eval,
            build: Some(vectors::build_hook),
            describe: "replays known-answer 7.52 framing/cipher/tail/key-table vectors",
        },
    )
    .expect("ntk_vector is already registered");

    deg::ext::register(
        "ntk_frames",
        deg::ext::Extension {
            eval: frames::eval,
            build: Some(frames::build_hook),
            describe: "structural frame facts from a frames.jsonl capture dataset",
        },
    )
    .expect("ntk_frames is already registered");

    deg::ext::register(
        "ntk_bundle",
        deg::ext::Extension {
            eval: bundle::eval,
            build: Some(bundle::build_hook),
            describe: "verifies a kaze.bundle/v1 capture package (manifest, index, blobs)",
        },
    )
    .expect("ntk_bundle is already registered");
}

#[cfg(test)]
pub(crate) fn register_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(register);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_exposes_exactly_the_three_kinds() {
        register_once();
        let kinds = deg::ext::registered();
        assert!(kinds.contains(&"ntk_vector"));
        assert!(kinds.contains(&"ntk_frames"));
        assert!(kinds.contains(&"ntk_bundle"));
        // The core deg binary registers no extensions at all; this crate's
        // surface is exactly these three plus whatever else a host binary
        // registered before us.
        let ours = kinds
            .iter()
            .filter(|k| k.starts_with("ntk_"))
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(ours.len(), 3, "{ours:?}");
    }
}
