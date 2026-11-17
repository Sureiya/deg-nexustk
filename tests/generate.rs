//! End-to-end test for the `deg-nexustk generate` lane over the committed
//! synthetic fixtures.
//!
//! The test runs the compiled binary against the synthetic audit shapes and
//! the synthetic PE, then runs `check --json` on the generated model and
//! asserts the strength split: dispatch-table and vector-opcode proofs seal
//! Deterministic, the anchor proof seals, the coverage claim is an honest
//! Hypothesis with the right covered/missing ids, the artifact proof stays an
//! Observational hypothesis, and the uncovered ids are open obligations.
//!
//! The generator must also be idempotent: two runs into different directories
//! produce byte-identical trees.

use deg::json::Json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_deg-nexustk"))
}

fn synth_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/synthetic")
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("generate")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("deg-nexustk runs")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn generate(out: &Path, with_client: bool) {
    let mut argv: Vec<String> = vec!["generate".to_string()];
    let mut push = |flag: &str, value: &Path| {
        argv.push(flag.to_string());
        argv.push(value.display().to_string());
    };
    if with_client {
        push("--client", &synth_dir().join("client-syn.exe"));
    }
    push("--vectors", &synth_dir().join("vectors-synthetic.json"));
    push("--layouts", &synth_dir().join("layouts-synthetic.json"));
    push("--dispatch", &synth_dir().join("dispatch-synthetic.json"));
    push("--artifacts", &synth_dir().join("artifacts-synthetic.json"));
    push("--anchors", &synth_dir().join("anchors-synthetic.json"));
    argv.push("--out".to_string());
    argv.push(out.display().to_string());
    let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let output = run(&argv_refs);
    assert!(
        output.status.success(),
        "generate failed:\nstdout: {}\nstderr: {}",
        stdout(&output),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn check_json(out: &Path) -> BTreeMap<String, Json> {
    let model = out.join("model.dg");
    let output = run(&["check", model.to_str().unwrap(), "--json"]);
    assert!(
        output.status.success(),
        "check failed:\nstdout: {}\nstderr: {}",
        stdout(&output),
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed = deg::json::parse(&stdout(&output)).expect("check --json output parses");
    match parsed {
        Json::Obj(map) => map,
        other => panic!("check --json output is not an object: {other}"),
    }
}

fn find_by_name<'a>(list: &'a Json, name: &str) -> &'a Json {
    list.as_arr()
        .unwrap_or_else(|| panic!("expected an array"))
        .iter()
        .find(|c| c.get("name").and_then(Json::as_str) == Some(name))
        .unwrap_or_else(|| panic!("no entry named {name:?}"))
}

fn claim<'a>(report: &'a BTreeMap<String, Json>, name: &str) -> &'a Json {
    find_by_name(report.get("claims").unwrap(), name)
}

fn obligation<'a>(report: &'a BTreeMap<String, Json>, name: &str) -> &'a Json {
    find_by_name(report.get("obligations").unwrap(), name)
}

/// All files under `dir`, as (relative path, bytes), for tree comparison.
fn tree(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.insert(
                    path.strip_prefix(dir).unwrap().to_path_buf(),
                    fs::read(&path).unwrap(),
                );
            }
        }
    }
    out
}

#[test]
fn generated_model_checks_with_the_documented_strength_split() {
    let out = tmp_dir("gen-out");

    generate(&out, true);

    // The supporting files the generator emits.
    let ops = fs::read_to_string(out.join("opcodes.txt")).unwrap();
    assert_eq!(ops, "12\n16\n51\n68\n98\n", "opcodes.txt");
    let art_csv = fs::read_to_string(out.join("artifacts.csv")).unwrap();
    assert_eq!(art_csv, "id,role\n90,synthetic-artifact-role\n");
    let cases = fs::read_to_string(out.join("table-cases.csv")).unwrap();
    assert_eq!(
        cases,
        concat!(
            "table,kind,va,file_offset\n",
            "mappane_syn,index,0x401290,0x490\n",
            "mappane_syn,case,0x401280,0x480\n",
        )
    );

    // Exactly one decision template, with the documented content.
    let decisions: Vec<String> = fs::read_dir(out.join("decisions"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(decisions, vec!["5a.txt"]);
    assert_eq!(
        fs::read_to_string(out.join("decisions/5a.txt")).unwrap(),
        concat!(
            "prefer: P_art_5a\n",
            "over: P_op_5a\n",
            "signer: OPERATOR-PENDING\n",
            "reason: synthetic-artifact-role\n",
            "note: P_op_5a needs its own evidence first (see the commented block in model.dg)\n",
        )
    );

    // The model itself checks OK.
    let report = check_json(&out);
    assert_eq!(report.get("ok").and_then(Json::as_bool), Some(true));
    assert_eq!(
        report.get("seal_threshold").and_then(Json::as_str),
        Some("deterministic")
    );

    // All five artifacts verify (the synthetic PE among them).
    let artifacts = report.get("artifacts").unwrap();
    assert_eq!(artifacts.as_arr().unwrap().len(), 5);
    for a in artifacts.as_arr().unwrap() {
        assert_eq!(a.get("verified").and_then(Json::as_bool), Some(true));
    }

    // The dispatch-table proofs seal at Deterministic: the kernel re-read the
    // declared bytes from the synthetic PE.
    for name in ["P_mappane_syn_index", "P_mappane_syn_case"] {
        let c = claim(&report, name);
        assert_eq!(
            c.get("status").and_then(Json::as_str),
            Some("sealed"),
            "{name}"
        );
        assert_eq!(
            c.get("strength").and_then(Json::as_str),
            Some("deterministic"),
            "{name}"
        );
    }

    // The vector-backed opcode proofs seal at Deterministic (0x0C, 0x10 and
    // 0x62 are the synthetic vector opcodes the layouts universe contains).
    for name in ["P_op_0c", "P_op_10", "P_op_62"] {
        let c = claim(&report, name);
        assert_eq!(
            c.get("status").and_then(Json::as_str),
            Some("sealed"),
            "{name}"
        );
        assert_eq!(
            c.get("strength").and_then(Json::as_str),
            Some("deterministic"),
            "{name}"
        );
    }

    // The unique-scan anchor proof seals too.
    let anchor = claim(&report, "P_syn_prologue");
    assert_eq!(anchor.get("status").and_then(Json::as_str), Some("sealed"));
    assert_eq!(
        anchor.get("strength").and_then(Json::as_str),
        Some("deterministic")
    );

    // The coverage claim is an honest hypothesis: 3 of 5 layout ids covered,
    // and the two uncovered ids named.
    let cov = claim(&report, "C_cov");
    assert_eq!(cov.get("status").and_then(Json::as_str), Some("hypothesis"));
    assert_eq!(cov.get("covered").and_then(Json::as_f64), Some(3.0));
    assert_eq!(cov.get("target").and_then(Json::as_f64), Some(5.0));
    let missing = cov
        .get("missing")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(missing, vec!["51", "68"]);

    // The artifact proof is capped Observational and stays a hypothesis.
    let art = claim(&report, "P_art_5a");
    assert_eq!(art.get("status").and_then(Json::as_str), Some("hypothesis"));
    assert_eq!(
        art.get("strength").and_then(Json::as_str),
        Some("observational")
    );

    // The uncovered ids are open observe obligations.
    for name in ["O_observe_33", "O_observe_44"] {
        let o = obligation(&report, name);
        assert_eq!(
            o.get("status").and_then(Json::as_str),
            Some("open"),
            "{name}"
        );
        assert_eq!(o.get("priority").and_then(Json::as_str), Some("high"));
    }

    // The vector evidence itself replayed deterministically.
    let evidence = report.get("evidence").unwrap();
    let e_vec = find_by_name(evidence, "e_vec");
    assert_eq!(e_vec.get("ok").and_then(Json::as_bool), Some(true));
    assert_eq!(
        e_vec.get("strength").and_then(Json::as_str),
        Some("deterministic")
    );
}

#[test]
fn generate_is_idempotent_across_directories() {
    let a = tmp_dir("gen-a");
    let b = tmp_dir("gen-b");
    generate(&a, true);
    generate(&b, true);
    assert_eq!(tree(&a), tree(&b), "two runs must produce identical trees");
}

#[test]
fn generate_without_a_client_skips_client_backed_claims() {
    let out = tmp_dir("gen-no-client");

    // Vectors, layouts, artifacts — but no client, so no build exists.
    generate(&out, false);

    let report = check_json(&out);
    assert_eq!(report.get("ok").and_then(Json::as_bool), Some(true));

    // No claims at all: the opcode proofs, dispatch proofs, anchor proofs,
    // and the coverage claim all need a build.
    assert!(
        report.get("claims").unwrap().as_arr().unwrap().is_empty(),
        "no-client model must not emit claims"
    );

    // The vector and artifact evidence still evaluate (no build required).
    let evidence = report.get("evidence").unwrap();
    assert_eq!(
        find_by_name(evidence, "e_vec")
            .get("ok")
            .and_then(Json::as_bool),
        Some(true)
    );
    assert_eq!(
        find_by_name(evidence, "e_art")
            .get("ok")
            .and_then(Json::as_bool),
        Some(true)
    );

    // Every layout id is an open observe obligation, plus the coverage
    // obligation in place of the claim.
    let obligations = report.get("obligations").unwrap();
    let names = obligations
        .as_arr()
        .unwrap()
        .iter()
        .map(|o| o.get("name").unwrap().as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(names.contains(&"O_observe_0c".to_string()));
    assert!(names.contains(&"O_observe_33".to_string()));
    assert!(names.contains(&"O_coverage".to_string()));

    // The decision template is still emitted (it is operator work to fill).
    assert!(out.join("decisions/5a.txt").is_file());
}
