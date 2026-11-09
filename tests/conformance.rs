use std::fs;
use std::path::{Path, PathBuf};

use cvd_policy::csaf::CsafState;
use cvd_policy::{
    assess_csaf, assess_csaf_for_host, assess_security_txt, evaluate_policy, EvaluationContext,
    EvaluationQuery, Policy, PolicyErrorKind, SecurityTxtRetrieval, Timestamp,
};
use serde_json::{json, Value};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: &str) -> Value {
    serde_json::from_slice(&fs::read(root().join(path)).expect("read fixture"))
        .expect("parse fixture JSON")
}

fn json_files(directory: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory).expect("read fixture directory") {
        let path = entry.expect("read fixture entry").path();
        if path.is_dir() {
            files.extend(json_files(&path));
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            files.push(path);
        }
    }
    files.sort();
    files
}

fn timestamp(value: &Value) -> Timestamp {
    Timestamp::parse(value.as_str().expect("timestamp string")).expect("valid fixture timestamp")
}

fn set_json_pointer(value: &mut Value, pointer: &str, replacement: Value) {
    if pointer.is_empty() {
        *value = replacement;
        return;
    }

    let mut segments = pointer
        .strip_prefix('/')
        .unwrap_or_else(|| panic!("JSON pointer must start with '/': {pointer}"))
        .split('/')
        .map(|segment| decode_pointer_segment(segment, pointer))
        .collect::<Vec<_>>();
    let leaf = segments.pop().expect("non-empty JSON pointer has a leaf");
    let mut parent = value;
    for segment in &segments {
        parent = match parent {
            Value::Object(object) => object
                .get_mut(segment)
                .unwrap_or_else(|| panic!("JSON pointer parent is missing in {pointer}")),
            Value::Array(array) => array
                .get_mut(pointer_array_index(segment, pointer))
                .unwrap_or_else(|| panic!("JSON pointer parent index is missing in {pointer}")),
            _ => panic!("JSON pointer parent is not a container in {pointer}"),
        };
    }

    match parent {
        Value::Object(object) => {
            object.insert(leaf, replacement);
        }
        Value::Array(array) => {
            let index = pointer_array_index(&leaf, pointer);
            *array
                .get_mut(index)
                .unwrap_or_else(|| panic!("JSON pointer leaf index is missing in {pointer}")) =
                replacement;
        }
        _ => panic!("JSON pointer parent is not a container in {pointer}"),
    }
}

fn decode_pointer_segment(segment: &str, pointer: &str) -> String {
    let mut decoded = String::with_capacity(segment.len());
    let mut characters = segment.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        decoded.push(match characters.next() {
            Some('0') => '~',
            Some('1') => '/',
            _ => panic!("invalid JSON pointer escape in {pointer}"),
        });
    }
    decoded
}

fn pointer_array_index(segment: &str, pointer: &str) -> usize {
    assert!(
        segment == "0"
            || segment
                .as_bytes()
                .first()
                .is_some_and(|first| (b'1'..=b'9').contains(first))
                && segment.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid JSON pointer array index in {pointer}"
    );
    segment
        .parse()
        .unwrap_or_else(|_| panic!("invalid JSON pointer array index in {pointer}"))
}

#[test]
fn json_pointer_fixture_edits_add_leaves_and_decode_array_paths() {
    let mut value = json!({"parent": {"items": [{"a/b": {"~key": null}}]}});
    set_json_pointer(&mut value, "/parent/new_leaf", json!(false));
    set_json_pointer(&mut value, "/parent/items/0/a~1b/~0key", json!(7));

    assert_eq!(value["parent"]["new_leaf"], false);
    assert_eq!(value["parent"]["items"][0]["a/b"]["~key"], 7);
}

fn assessed_evidence(authority: &Value) -> cvd_policy::AuthorityEvidence {
    let policy_uri = authority["cvdPolicyUri"]
        .as_str()
        .expect("policy URI claim");
    let expires = authority["securityTxtExpires"]
        .as_str()
        .expect("expiry claim");
    let text = format!(
        "Contact: mailto:security@example.com\nCVD-Policy: {policy_uri}\nExpires: {expires}\n"
    );
    let retrieval = SecurityTxtRetrieval {
        requested_uri: authority["securityTxtUri"]
            .as_str()
            .expect("security.txt URI claim")
            .to_owned(),
        final_uri: authority["securityTxtUri"]
            .as_str()
            .expect("security.txt URI claim")
            .to_owned(),
        redirect_chain: Vec::new(),
        retrieved_at: Timestamp::parse("2026-08-29T10:00:00Z")
            .expect("fixed historical retrieval instant"),
    };
    let assessment = assess_security_txt(text.as_bytes(), &retrieval);
    let evidence = assessment
        .evidence
        .expect("fixture security.txt claims establish authority");

    assert_eq!(
        evidence.discovery_host(),
        authority["discoveryHost"]
            .as_str()
            .expect("discovery host claim")
    );
    assert_eq!(
        evidence.security_txt_uri(),
        authority["securityTxtUri"]
            .as_str()
            .expect("security URI claim")
    );
    assert_eq!(evidence.cvd_policy_uri(), policy_uri);
    assert_eq!(
        evidence.security_txt_expires(),
        &timestamp(&authority["securityTxtExpires"]),
        "authority evidence must preserve the exact claimed expiry instant"
    );
    evidence
}

fn csaf_state_name(state: CsafState) -> &'static str {
    match state {
        CsafState::NotAdvertised => "not-advertised",
        CsafState::Invalid => "invalid",
        CsafState::Unsupported => "unsupported",
        CsafState::Advertised => "advertised",
    }
}

#[test]
fn policy_fixture_corpus_matches_static_status_expectations() {
    let root = root();
    let invalid_expected = read_json("vendor/spec/tests/v1/expected.json");
    let invalid_dir = root.join("vendor/spec/tests/v1/policy/invalid");
    let invalid_files = json_files(&invalid_dir);
    assert_eq!(invalid_files.len(), 47, "invalid fixture inventory changed");
    assert_eq!(
        invalid_files.len(),
        invalid_expected
            .as_object()
            .expect("invalid expectations object")
            .len()
    );

    for path in invalid_files {
        let name = path
            .file_name()
            .expect("fixture name")
            .to_str()
            .expect("UTF-8 fixture name");
        let raw = fs::read(&path).expect("read invalid policy fixture");
        let expected_layer = invalid_expected[name]["layer"]
            .as_str()
            .expect("expected validation layer");
        if name == "expired.json" {
            let value = cvd_policy::parse_json(&raw, cvd_policy::ParseLimits::default())
                .expect("expired fixture is valid JSON");
            assert!(cvd_policy::policy::validate_structure(&value).is_empty());
            assert!(cvd_policy::policy::semantic_issues(&value).is_empty());
            assert_eq!(expected_layer, "semantic");
            let policy =
                Policy::parse(&raw).expect("expiry alone does not invalidate static policy");
            let now = Timestamp::parse("2026-08-29T10:00:00Z").expect("fixed fixture instant");
            assert!(policy.validate_at(&now).is_err());
            continue;
        }

        let value = cvd_policy::parse_json(&raw, cvd_policy::ParseLimits::default())
            .unwrap_or_else(|error| {
                panic!("{name}: expected valid JSON before {expected_layer} layer: {error}")
            });
        let structure = cvd_policy::policy::validate_structure(&value);
        match expected_layer {
            "schema" => assert!(
                !structure.is_empty(),
                "{name}: schema layer must be established by structural diagnostics"
            ),
            "semantic" => {
                assert!(
                    structure.is_empty(),
                    "{name}: semantic layer requires a structurally valid policy"
                );
                assert!(
                    !cvd_policy::policy::semantic_issues(&value).is_empty(),
                    "{name}: semantic layer must be established by static semantic diagnostics"
                );
            }
            layer => panic!("{name}: unexpected invalid fixture layer {layer}"),
        }

        let expected_status = invalid_expected[name]["status"]
            .as_str()
            .expect("expected status string");
        let error = Policy::parse(&raw).expect_err("invalid fixture must be rejected");
        let expected_kind = if expected_status == "unsupported-policy" {
            PolicyErrorKind::UnsupportedVersion
        } else {
            PolicyErrorKind::Invalid
        };
        assert_eq!(error.kind, expected_kind, "unexpected status for {name}");
        assert!(
            !error.diagnostics.is_empty(),
            "missing diagnostics for {name}"
        );
    }

    let raw_expected = read_json("vendor/spec/tests/v1/raw-expected.json");
    let raw_dir = root.join("vendor/spec/tests/v1/policy/raw-invalid");
    let raw_files = json_files(&raw_dir);
    assert_eq!(raw_files.len(), 8, "raw-invalid fixture inventory changed");
    assert_eq!(
        raw_files.len(),
        raw_expected
            .as_object()
            .expect("raw expectations object")
            .len()
    );
    for path in raw_files {
        let name = path
            .file_name()
            .expect("fixture name")
            .to_str()
            .expect("UTF-8 fixture name");
        let raw = fs::read(&path).expect("read raw policy fixture");
        assert!(
            cvd_policy::parse_json(&raw, cvd_policy::ParseLimits::default()).is_err(),
            "{name}: raw-invalid source must fail the duplicate-aware JSON parser"
        );
        let error = Policy::parse(&raw).expect_err("raw-invalid policy must be rejected");
        assert_eq!(
            error.kind,
            PolicyErrorKind::Invalid,
            "unexpected raw error for {name}"
        );
    }

    let valid_expected = read_json("vendor/spec/tests/v1/valid-expected.json");
    let valid_dir = root.join("vendor/spec/tests/v1/policy/valid");
    let valid_files = json_files(&valid_dir);
    assert_eq!(valid_files.len(), 4, "valid fixture inventory changed");
    assert_eq!(
        valid_files.len(),
        valid_expected
            .as_object()
            .expect("valid expectations object")
            .len()
    );
    let now = Timestamp::parse("2026-11-08T12:00:00Z").expect("fixed validation instant");
    for path in valid_files {
        let policy = Policy::parse(&fs::read(path).expect("read valid policy fixture"))
            .expect("valid fixture parses");
        policy
            .validate_at(&now)
            .expect("valid fixture is current at the supplied instant");
    }

    let examples_dir = root.join("vendor/spec/examples/v1");
    let examples = json_files(&examples_dir);
    assert_eq!(examples.len(), 6, "policy example inventory changed");
    for path in examples {
        let policy = Policy::parse(&fs::read(path).expect("read policy example"))
            .expect("policy example parses");
        policy
            .validate_at(&now)
            .expect("policy example is current at the supplied instant");
    }
}

#[test]
fn expired_policy_is_static_valid_and_fails_at_explicit_time() {
    let raw = fs::read(root().join("vendor/spec/tests/v1/policy/invalid/expired.json"))
        .expect("read expired policy fixture");
    let policy = Policy::parse(&raw).expect("expired policy remains statically valid");
    let now = Timestamp::parse("2026-08-29T10:00:00Z").expect("fixed fixture instant");
    let error = policy
        .validate_at(&now)
        .expect_err("expired policy is invalid at now");

    assert_eq!(error.kind, PolicyErrorKind::Invalid);
    assert!(error
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "policy_expired" && diagnostic.path == "/expires"));
}

#[test]
fn security_txt_fixtures_match_assessment_expectations() {
    let fixture = read_json("vendor/spec/tests/v1/security-txt/cases.json");
    let cases = fixture.as_array().expect("security.txt fixture array");
    assert_eq!(cases.len(), 19, "security.txt fixture inventory changed");

    for case in cases {
        let context = &case["context"];
        let retrieval = SecurityTxtRetrieval {
            requested_uri: context["requestedUri"]
                .as_str()
                .expect("requested URI")
                .to_owned(),
            final_uri: context["finalUri"].as_str().expect("final URI").to_owned(),
            redirect_chain: serde_json::from_value(context["redirectChain"].clone())
                .expect("redirect chain strings"),
            retrieved_at: timestamp(&context["retrievedAt"]),
        };
        let text = case["text"].as_str().expect("security.txt fixture text");
        let assessment = assess_security_txt(text.as_bytes(), &retrieval);
        let expected_established = case["expected"]["established"]
            .as_bool()
            .expect("expected authority status");
        assert_eq!(
            assessment.evidence.is_some(),
            expected_established,
            "{}",
            case["id"]
        );

        if let Some(evidence) = assessment.evidence {
            let expected = &case["expected"];
            assert_eq!(
                evidence.discovery_host(),
                expected["discoveryHost"]
                    .as_str()
                    .expect("discovery host expectation")
            );
            assert_eq!(
                evidence.cvd_policy_uri(),
                expected["cvdPolicyUri"]
                    .as_str()
                    .expect("policy URI expectation")
            );
            assert_eq!(evidence.security_txt_uri(), retrieval.requested_uri);
        } else {
            assert!(!assessment.diagnostics.is_empty(), "{}", case["id"]);
        }
    }
}

#[test]
fn evaluation_fixtures_match_statuses_with_assessed_authority() {
    let root = root();
    let cases = read_json("vendor/spec/tests/v1/evaluation/cases.json");
    let cases = cases.as_array().expect("evaluation fixture array");
    assert_eq!(cases.len(), 55, "evaluation fixture inventory changed");
    for case in cases {
        let base = case["base"].as_str().expect("policy example name");
        let path = root.join("vendor/spec/examples/v1").join(base);
        let mut policy: Value =
            serde_json::from_slice(&fs::read(path).expect("read policy example"))
                .expect("parse policy example");
        for (pointer, replacement) in case["set"].as_object().expect("case edits object") {
            set_json_pointer(&mut policy, pointer, replacement.clone());
        }
        let raw = serde_json::to_vec(&policy).expect("serialize policy fixture once");
        let query: EvaluationQuery =
            serde_json::from_value(case["query"].clone()).expect("parse evaluation query fixture");
        let mut context = EvaluationContext::new(timestamp(&case["now"]));
        context.allow_application_json = case["options"]["allowApplicationJson"]
            .as_bool()
            .unwrap_or(false);
        let authority = if case["authority"].is_null() {
            None
        } else {
            let claim = &case["authority"];
            Some(assessed_evidence(claim))
        };
        let result = evaluate_policy(&raw, &query, authority.as_ref(), &context);

        if case["expected"]["inputValid"] == false {
            assert!(
                result.is_err(),
                "{}: invalid target must return input error",
                case["id"]
            );
        } else {
            let result = result
                .unwrap_or_else(|error| panic!("{}: unexpected input error: {error}", case["id"]));
            let expected = case["expected"]["status"]
                .as_str()
                .expect("expected permission status");
            assert_eq!(result.status.to_string(), expected, "{}", case["id"]);
        }
    }
}

#[test]
fn csaf_fixtures_match_metadata_permission_and_host_assessment() {
    let fixture =
        read_json("vendor/spec/extensions/csaf-vulnerability-report-v1/csaf-policy-cases.json");
    let cases = fixture["cases"].as_array().expect("CSAF fixture array");
    assert_eq!(cases.len(), 42, "shared CSAF fixture inventory changed");
    for case in cases {
        let id = case["id"].as_str().expect("CSAF case id");
        let input = &case["input"];
        let raw = if let Some(text) = input["policy_text"].as_str() {
            text.as_bytes().to_vec()
        } else {
            serde_json::to_vec(&input["policy"]).expect("serialize CSAF policy once")
        };
        let expected = &case["expected"];
        let metadata = assess_csaf(&raw);

        if expected["assessment"].is_null() {
            assert!(
                metadata.is_err(),
                "{id}: invalid core policy must block CSAF assessment"
            );
        } else {
            let metadata = metadata.unwrap_or_else(|error| panic!("{id}: {error}"));
            assert_eq!(
                csaf_state_name(metadata.state),
                expected["assessment"]
                    .as_str()
                    .expect("expected assessment state")
            );
            let actual_channels = metadata
                .channels
                .iter()
                .map(|channel| channel.uri.as_str())
                .collect::<Vec<_>>();
            let expected_channels = expected["declared_channels_in_contact_preference_order"]
                .as_array()
                .expect("expected channel array")
                .iter()
                .map(|channel| channel.as_str().expect("channel string"))
                .collect::<Vec<_>>();
            assert_eq!(actual_channels, expected_channels, "{id}");
        }

        let query: EvaluationQuery =
            serde_json::from_value(input["query"].clone()).expect("parse CSAF evaluation query");
        let context = EvaluationContext::new(timestamp(&input["now"]));
        let authority = if input["authority"].is_null() {
            None
        } else {
            let claim = &input["authority"];
            Some(assessed_evidence(claim))
        };
        let permission = evaluate_policy(&raw, &query, authority.as_ref(), &context)
            .unwrap_or_else(|error| panic!("{id}: unexpected evaluation input error: {error}"));
        assert_eq!(
            permission.status.to_string(),
            expected["testing_permission_status"]
                .as_str()
                .expect("expected Testing Permission status"),
            "{id}: CSAF metadata must not replace Testing Permission"
        );

        let current = assess_csaf_for_host(
            &raw,
            authority.as_ref(),
            query.policy_retrieval.as_ref(),
            &context,
        );
        assert_eq!(
            current.usable,
            expected["usable_as_current_host_csaf_statement"]
                .as_bool()
                .expect("expected host usability"),
            "{id}"
        );
        assert_eq!(
            current.capability.is_err(),
            expected["assessment"].is_null(),
            "{id}"
        );
    }
}

#[test]
fn csaf_absolute_uri_edge_cases_match_invalid_and_unsupported_rules() {
    let fixture = read_json("vendor/spec/tests/v1/csaf-reporting/extra-cases.json");
    let cases = fixture["cases"].as_array().expect("URI edge-case array");
    assert_eq!(cases.len(), 17, "URI edge-case inventory changed");
    let base: Value = serde_json::from_slice(
        &fs::read(root().join("vendor/spec/examples/v1/csaf-reporting-policy.example.json"))
            .expect("read CSAF example"),
    )
    .expect("parse CSAF example");

    for case in cases {
        let mut policy = base.clone();
        policy["extensions"][cvd_policy::csaf::CSAF_EXTENSION_ID]["channels"][0]["specification"] =
            case["specification"].clone();
        let raw = serde_json::to_vec(&policy).expect("serialize URI edge case once");
        let assessment = assess_csaf(&raw).expect("core policy remains valid");
        let expected = case["expected"].as_str().expect("expected URI state");
        assert_eq!(
            csaf_state_name(assessment.state),
            expected,
            "{}",
            case["id"]
        );
    }
}
