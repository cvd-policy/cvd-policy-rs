use std::fs;
use std::path::PathBuf;

use serde_json::Value;

#[test]
fn interop_reproductions_are_valid_raw_policy_text_edits() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let definitions: Value = serde_json::from_slice(
        &fs::read(root.join("tools/interop/cases.json")).expect("read interop case definitions"),
    )
    .expect("parse interop case definitions");
    let base_path = definitions["base_policy"]
        .as_str()
        .expect("base_policy is a string");
    let base = fs::read_to_string(root.join(base_path)).expect("read baseline policy bytes");

    assert_eq!(
        definitions["typescript_commit"].as_str().map(str::len),
        Some(40),
        "interop must pin a full TypeScript source commit"
    );
    assert_eq!(definitions["now"], "2026-11-08T12:00:00Z");

    let cases = definitions["cases"].as_array().expect("cases is an array");
    assert!(!cases.is_empty(), "interop case list is not empty");
    for case in cases {
        let id = case["id"].as_str().expect("case id is a string");
        let mut raw = base.clone();
        for edit in case["edits"].as_array().expect("edits is an array") {
            let from = edit["from"].as_str().expect("edit from is a string");
            let to = edit["to"].as_str().expect("edit to is a string");
            assert_eq!(raw.matches(from).count(), 1, "{id}: edit anchor is unique");
            let index = raw.find(from).expect("unique edit anchor was found");
            raw.replace_range(index..index + from.len(), to);
        }

        serde_json::from_str::<Value>(&raw)
            .unwrap_or_else(|error| panic!("{id}: raw interop policy is invalid JSON: {error}"));
        assert!(
            case["typescript"].is_string(),
            "{id}: expected TypeScript result"
        );
        assert!(
            case["normative"].is_string(),
            "{id}: normative result is recorded"
        );
        if case["normative"] != case["typescript"] {
            assert!(
                case["difference_reason"]
                    .as_str()
                    .is_some_and(|reason| !reason.is_empty()),
                "{id}: semantic differences require a normative explanation"
            );
        }
    }
}
