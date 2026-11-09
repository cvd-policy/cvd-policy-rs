//! Assesses optional CSAF report declarations without processing vulnerability reports.
//!
//! This module validates only the extension metadata embedded in a core-valid CVD
//! Policy. It never contacts either URI in the declaration and does not validate
//! CSAF reports, infer Testing Permission, or authorize report submission.
//! Local assessment does not check expiry; host assessment applies
//! [`Policy::validate_at`] with the caller's explicit evaluation time.
//!
//! # Examples
//!
//! ```
//! use cvd_policy::csaf::{assess_csaf, CsafState};
//!
//! let raw = br#"{
//!   "cvd_policy": 1,
//!   "last_updated": "2026-11-08T00:00:00Z",
//!   "expires": "2027-05-07T00:00:00Z",
//!   "organization": {"name": "Example Organization"},
//!   "contact": {"channels": ["mailto:security@example.com"]},
//!   "research": {"posture": "report_only"},
//!   "reporting_scope": {"web": [{
//!     "id": "main-web", "state": "in", "host": "example.com",
//!     "schemes": ["https"], "path_prefix": "/", "include_subdomains": false
//!   }]},
//!   "reporting": {"requested_fields": ["description"], "proof_of_exploitation": "not_requested"}
//! }"#;
//! let assessment = assess_csaf(raw)?;
//! assert_eq!(assessment.state, CsafState::NotAdvertised);
//! # Ok::<(), cvd_policy::PolicyError>(())
//! ```

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::policy::Policy;
use crate::types::{
    AuthorityEvidence, Diagnostic, EvaluationContext, PolicyError, PolicyRetrieval,
};
use crate::uri::{is_absolute_uri, is_https_uri};

/// The exact extension identifier defined for CSAF report declarations.
pub const CSAF_EXTENSION_ID: &str =
    "https://github.com/cvd-policy/spec/extensions/csaf-vulnerability-report-v1";

/// The exact CSAF 2.1 CSD04 specification URI supported by Version 1.
pub const CSAF_SPECIFICATION: &str =
    "https://docs.oasis-open.org/csaf/csaf/v2.1/csd04/csaf-v2.1-csd04.html";

/// The four outcomes of local CSAF declaration assessment.
///
/// These outcomes describe declaration metadata only; they are not Testing
/// Permission results and do not indicate that a report was accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsafState {
    /// The policy does not contain the exact CSAF extension identifier.
    NotAdvertised,
    /// The extension is present but violates a declaration data rule.
    Invalid,
    /// The extension uses critical behavior or an unsupported specification.
    Unsupported,
    /// The declaration is valid and uses the supported specification.
    Advertised,
}

/// One contact channel advertised for CSAF vulnerability reports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsafChannel {
    /// The exact URI copied from `contact.channels`.
    pub uri: String,
    /// The exact supported specification URI.
    pub specification: String,
}

/// The result of assessing CSAF declaration metadata in a core-valid policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsafAssessment {
    /// The local declaration result.
    pub state: CsafState,
    /// Usable channels in the policy's contact preference order.
    pub channels: Vec<CsafChannel>,
    /// Declaration diagnostics; non-critical errors do not invalidate the core policy.
    pub diagnostics: Vec<Diagnostic>,
}

/// The result of checking a CSAF declaration for current Discovery Host use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsafHostAssessment {
    /// Whether the declaration is usable with the supplied current-host evidence.
    pub usable: bool,
    /// Local capability result, or the core policy error that prevented assessment.
    pub capability: Result<CsafAssessment, PolicyError>,
    /// Reasons current-host use was not established.
    pub diagnostics: Vec<Diagnostic>,
}

/// Assesses CSAF metadata after duplicate-aware core policy validation.
///
/// An absent declaration is `not-advertised`; malformed declaration data is
/// `invalid`; unsupported or critical declarations are `unsupported`. Successful
/// metadata is returned atomically in contact preference order. Policy expiry is
/// intentionally left to current-host assessment.
///
/// # Examples
///
/// ```
/// use cvd_policy::csaf::{assess_csaf, CsafState};
///
/// let assessment = assess_csaf(br#"{
///   "cvd_policy": 1,
///   "last_updated": "2026-11-08T00:00:00Z",
///   "expires": "2027-05-07T00:00:00Z",
///   "organization": {"name": "Example Organization"},
///   "contact": {"channels": ["mailto:security@example.com"]},
///   "research": {"posture": "report_only"},
///   "reporting_scope": {"web": [{
///     "id": "main-web", "state": "in", "host": "example.com",
///     "schemes": ["https"], "path_prefix": "/", "include_subdomains": false
///   }]},
///   "reporting": {"requested_fields": ["description"], "proof_of_exploitation": "not_requested"}
/// }"#)?;
/// assert_eq!(assessment.state, CsafState::NotAdvertised);
/// # Ok::<(), cvd_policy::PolicyError>(())
/// ```
///
/// # Errors
///
/// Returns the core parser's error for malformed JSON, duplicate names, unsupported
/// versions, invalid core structure, invalid core semantics, or resource limits.
pub fn assess_csaf(raw: &[u8]) -> Result<CsafAssessment, PolicyError> {
    let policy = Policy::parse(raw)?;
    Ok(assess_policy(&policy))
}

/// Assesses whether an advertised declaration is current for its Discovery Host.
///
/// This check requires unexpired policy and `security.txt` evidence, valid Authority,
/// a bound HTTPS policy retrieval, and no unsupported critical policy extensions.
/// It does not require a Target or positive Testing Permission.
///
/// # Errors
///
/// Core policy errors are returned in `capability`; current-host failures are
/// reported in `diagnostics` and leave `usable` false.
pub fn assess_csaf_for_host(
    raw: &[u8],
    authority: Option<&AuthorityEvidence>,
    retrieval: Option<&PolicyRetrieval>,
    context: &EvaluationContext,
) -> CsafHostAssessment {
    let policy = match Policy::parse(raw) {
        Ok(policy) => policy,
        Err(error) => {
            return CsafHostAssessment {
                usable: false,
                diagnostics: error.diagnostics.clone(),
                capability: Err(error),
            };
        }
    };

    let mut diagnostics = Vec::new();
    if let Err(error) = policy.validate_at(&context.now) {
        diagnostics.extend(error.diagnostics);
    }

    let assessment = assess_policy(&policy);
    match assessment.state {
        CsafState::NotAdvertised => diagnostics.push(diagnostic(
            "csaf_declaration_not_advertised",
            &format!("/extensions/{}", pointer_part(CSAF_EXTENSION_ID)),
            "The policy does not advertise the CSAF vulnerability-report capability.",
        )),
        CsafState::Invalid | CsafState::Unsupported => {
            let code = if assessment.state == CsafState::Invalid {
                "csaf_declaration_invalid"
            } else {
                "csaf_declaration_unsupported"
            };
            diagnostics.extend(
                assessment
                    .diagnostics
                    .iter()
                    .map(|entry| diagnostic(code, &entry.path, &entry.message)),
            );
        }
        CsafState::Advertised => {}
    }

    if policy
        .value()
        .get("critical_extensions")
        .and_then(Value::as_array)
        .is_some_and(|extensions| !extensions.is_empty())
    {
        diagnostics.push(diagnostic(
            "policy_critical_extension_unsupported",
            "/critical_extensions",
            "The policy contains critical behavior that this host assessment does not support.",
        ));
    }

    match authority {
        Some(evidence) => {
            let retrieval_issues =
                crate::retrieval::policy_retrieval_issues(evidence, retrieval, context);
            if retrieval_issues.is_empty() {
                diagnostics.extend(crate::authority::authority_evidence_issues(
                    evidence, context,
                ));
            } else {
                diagnostics.extend(retrieval_issues);
            }
        }
        None => diagnostics.push(diagnostic(
            "authority_evidence_missing",
            "",
            "Current host use requires established Authority evidence.",
        )),
    }

    let usable = assessment.state == CsafState::Advertised && diagnostics.is_empty();
    CsafHostAssessment {
        usable,
        capability: Ok(assessment),
        diagnostics,
    }
}

fn assess_policy(policy: &Policy) -> CsafAssessment {
    let Some(extension) = policy
        .value()
        .get("extensions")
        .and_then(Value::as_object)
        .and_then(|extensions| extensions.get(CSAF_EXTENSION_ID))
    else {
        return CsafAssessment {
            state: CsafState::NotAdvertised,
            channels: Vec::new(),
            diagnostics: Vec::new(),
        };
    };

    let (issues, mut unsupported, channels) = inspect_declaration(policy.value(), extension);
    if !issues.is_empty() {
        return CsafAssessment {
            state: CsafState::Invalid,
            channels: Vec::new(),
            diagnostics: issues,
        };
    }

    let critical = policy
        .value()
        .get("critical_extensions")
        .and_then(Value::as_array)
        .is_some_and(|extensions| {
            extensions
                .iter()
                .any(|entry| entry.as_str() == Some(CSAF_EXTENSION_ID))
        });
    if critical {
        unsupported.insert(
            0,
            diagnostic(
                "extension-critical",
                "/critical_extensions",
                "The CSAF extension cannot be marked critical.",
            ),
        );
    }

    let state = if unsupported.is_empty() {
        CsafState::Advertised
    } else {
        CsafState::Unsupported
    };
    CsafAssessment {
        state,
        channels: if state == CsafState::Advertised {
            channels
        } else {
            Vec::new()
        },
        diagnostics: unsupported,
    }
}

fn inspect_declaration(
    policy: &Value,
    extension: &Value,
) -> (Vec<Diagnostic>, Vec<Diagnostic>, Vec<CsafChannel>) {
    let base_path = format!("/extensions/{}", pointer_part(CSAF_EXTENSION_ID));
    let Some(object) = extension.as_object() else {
        return (
            vec![diagnostic(
                "extension-object-invalid",
                &base_path,
                "The CSAF extension value must be an object.",
            )],
            Vec::new(),
            Vec::new(),
        );
    };

    let mut issues = Vec::new();
    let mut unsupported = Vec::new();
    for key in object.keys().filter(|key| key.as_str() != "channels") {
        issues.push(diagnostic(
            "extension-member-unknown",
            &format!("{base_path}/{}", pointer_part(key)),
            &format!("The CSAF extension does not allow the member '{key}'."),
        ));
    }

    if !object.contains_key("channels") {
        issues.push(diagnostic(
            "channels-missing",
            &format!("{base_path}/channels"),
            "The CSAF extension requires channels.",
        ));
    }
    let Some(entries) = object.get("channels").and_then(Value::as_array) else {
        issues.push(diagnostic(
            "channels-invalid",
            &format!("{base_path}/channels"),
            "The CSAF channels member must be an array.",
        ));
        return (issues, unsupported, Vec::new());
    };
    if entries.is_empty() {
        issues.push(diagnostic(
            "channels-empty",
            &format!("{base_path}/channels"),
            "The CSAF channels array must not be empty.",
        ));
    }

    let contact_channels = policy
        .pointer("/contact/channels")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut seen_uris = HashSet::new();
    let mut specifications = HashMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let entry_path = format!("{base_path}/channels/{index}");
        let Some(channel) = entry.as_object() else {
            issues.push(diagnostic(
                "channel-object-invalid",
                &entry_path,
                "Each CSAF channel must be an object.",
            ));
            continue;
        };
        for key in channel
            .keys()
            .filter(|key| key.as_str() != "uri" && key.as_str() != "specification")
        {
            issues.push(diagnostic(
                "channel-member-unknown",
                &format!("{entry_path}/{}", pointer_part(key)),
                &format!("A CSAF channel does not allow the member '{key}'."),
            ));
        }

        let uri = channel.get("uri").and_then(Value::as_str);
        match uri {
            Some(uri) => {
                if !seen_uris.insert(uri.to_owned()) {
                    issues.push(diagnostic(
                        "channel-uri-duplicate",
                        &format!("{entry_path}/uri"),
                        "A CSAF channel uri may occur only once.",
                    ));
                }
                if !valid_channel_uri(uri) {
                    issues.push(diagnostic(
                        "channel-uri-invalid",
                        &format!("{entry_path}/uri"),
                        "The CSAF channel uri must be a valid absolute mailto or https URI.",
                    ));
                }
                let references = contact_channels
                    .iter()
                    .filter(|contact| contact.as_str() == Some(uri))
                    .count();
                if references != 1 {
                    issues.push(diagnostic(
                        "channel-reference-invalid",
                        &format!("{entry_path}/uri"),
                        "The CSAF channel uri must exactly match one contact.channels entry.",
                    ));
                }
            }
            None => issues.push(diagnostic(
                "channel-uri-invalid",
                &format!("{entry_path}/uri"),
                "A CSAF channel uri must be a string.",
            )),
        }

        let specification = channel.get("specification").and_then(Value::as_str);
        match specification {
            Some(specification) if !is_absolute_uri(specification) => {
                issues.push(diagnostic(
                    "specification-invalid",
                    &format!("{entry_path}/specification"),
                    "The specification must be a syntactically valid absolute RFC 3986 URI without a fragment.",
                ));
            }
            Some(specification) if specification != CSAF_SPECIFICATION => {
                unsupported.push(diagnostic(
                    "specification-unsupported",
                    &format!("{entry_path}/specification"),
                    "This syntactically valid specification URI is not supported.",
                ));
            }
            Some(_) => {}
            None => issues.push(diagnostic(
                "specification-invalid",
                &format!("{entry_path}/specification"),
                "A CSAF channel specification must be a string.",
            )),
        }

        if let (Some(uri), Some(specification)) = (uri, specification) {
            specifications.insert(uri.to_owned(), specification.to_owned());
        }
    }

    if !issues.is_empty() {
        return (issues, unsupported, Vec::new());
    }

    let channels = contact_channels
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|uri| {
            specifications.get(uri).map(|specification| CsafChannel {
                uri: uri.to_owned(),
                specification: specification.clone(),
            })
        })
        .collect();
    (issues, unsupported, channels)
}

fn valid_channel_uri(uri: &str) -> bool {
    if !is_absolute_uri(uri) {
        return false;
    }
    let Some((scheme, _)) = uri.split_once(':') else {
        return false;
    };
    if scheme.eq_ignore_ascii_case("mailto") {
        true
    } else {
        scheme.eq_ignore_ascii_case("https") && is_https_uri(uri)
    }
}

fn pointer_part(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn diagnostic(code: &str, path: &str, message: &str) -> Diagnostic {
    Diagnostic {
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use crate::timestamp::Timestamp;
    use crate::types::{AuthorityEvidence, EvaluationContext, PolicyRetrieval};

    use super::{
        assess_csaf, assess_csaf_for_host, CsafState, CSAF_EXTENSION_ID, CSAF_SPECIFICATION,
    };

    fn raw_policy(extension: Option<Value>, critical: bool) -> Vec<u8> {
        let mut policy = json!({
            "cvd_policy": 1,
            "last_updated": "2026-11-08T00:00:00Z",
            "expires": "2027-05-07T00:00:00Z",
            "organization": { "name": "Example Organization" },
            "contact": {
                "channels": [
                    "mailto:security@example.com",
                    "https://example.com/security/contact"
                ]
            },
            "research": { "posture": "report_only" },
            "reporting_scope": {
                "web": [{
                    "id": "main-web",
                    "state": "in",
                    "host": "example.com",
                    "schemes": ["https"],
                    "path_prefix": "/",
                    "include_subdomains": false
                }]
            },
            "reporting": {
                "requested_fields": ["affected_asset", "description"],
                "proof_of_exploitation": "not_requested"
            },
            "critical_extensions": [],
            "extensions": {}
        });

        if let Some(extension) = extension {
            policy["extensions"][CSAF_EXTENSION_ID] = extension;
        }
        if critical {
            policy["critical_extensions"] = json!([CSAF_EXTENSION_ID]);
        }

        serde_json::to_vec(&policy).expect("JSON values serialize")
    }

    fn declaration(channels: &[(&str, &str)]) -> Value {
        json!({
            "channels": channels.iter().map(|(uri, specification)| json!({
                "uri": uri,
                "specification": specification
            })).collect::<Vec<_>>()
        })
    }

    #[test]
    fn state_serialization_uses_exact_kebab_case_values() {
        for (state, expected) in [
            (CsafState::NotAdvertised, "not-advertised"),
            (CsafState::Invalid, "invalid"),
            (CsafState::Unsupported, "unsupported"),
            (CsafState::Advertised, "advertised"),
        ] {
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{expected}\"")
            );
            assert_eq!(
                serde_json::from_str::<CsafState>(&format!("\"{expected}\""))
                    .expect("known state value"),
                state
            );
        }
    }

    fn context(now: &str) -> EvaluationContext {
        EvaluationContext::new(Timestamp::parse(now).expect("valid timestamp"))
    }

    fn evidence(expires: &str) -> AuthorityEvidence {
        AuthorityEvidence {
            discovery_host: "example.com".to_owned(),
            security_txt_uri: "https://example.com/.well-known/security.txt".to_owned(),
            cvd_policy_uri: "https://example.com/cvd-policy.json".to_owned(),
            security_txt_expires: Timestamp::parse(expires).expect("valid timestamp"),
        }
    }

    fn retrieval() -> PolicyRetrieval {
        PolicyRetrieval {
            requested_uri: "https://example.com/cvd-policy.json".to_owned(),
            final_uri: "https://example.com/cvd-policy.json".to_owned(),
            redirect_chain: Vec::new(),
            status_code: 200,
            media_type: "application/cvd-policy+json".to_owned(),
        }
    }

    #[test]
    fn channel_selection_follows_contact_preference_not_extension_order() {
        let raw = raw_policy(
            Some(declaration(&[
                ("https://example.com/security/contact", CSAF_SPECIFICATION),
                ("mailto:security@example.com", CSAF_SPECIFICATION),
            ])),
            false,
        );

        let assessed = assess_csaf(&raw).expect("valid core policy");
        assert_eq!(assessed.state, CsafState::Advertised);
        assert_eq!(
            assessed
                .channels
                .iter()
                .map(|channel| channel.uri.as_str())
                .collect::<Vec<_>>(),
            [
                "mailto:security@example.com",
                "https://example.com/security/contact"
            ]
        );
    }

    #[test]
    fn absent_extension_is_not_advertised() {
        let assessed = assess_csaf(&raw_policy(None, false)).expect("valid core policy");

        assert_eq!(assessed.state, CsafState::NotAdvertised);
        assert!(assessed.channels.is_empty());
    }

    #[test]
    fn invalid_channel_reference_precedes_unsupported_specification() {
        let raw = raw_policy(
            Some(declaration(&[("mailto:other@example.com", "foo:/path")])),
            false,
        );

        let assessed = assess_csaf(&raw).expect("non-critical extension errors are metadata");
        assert_eq!(assessed.state, CsafState::Invalid);
        assert!(assessed.channels.is_empty());
    }

    #[test]
    fn critical_csaf_declaration_is_unsupported_and_atomic() {
        let raw = raw_policy(
            Some(declaration(&[(
                "mailto:security@example.com",
                CSAF_SPECIFICATION,
            )])),
            true,
        );

        let assessed = assess_csaf(&raw).expect("critical use is not a core parse error");
        assert_eq!(assessed.state, CsafState::Unsupported);
        assert!(assessed.channels.is_empty());
    }

    #[test]
    fn duplicate_members_inside_extensions_remain_core_errors() {
        let raw = raw_policy(
            Some(declaration(&[(
                "mailto:security@example.com",
                CSAF_SPECIFICATION,
            )])),
            false,
        );
        let raw = String::from_utf8(raw).expect("JSON is UTF-8");
        let marker = format!("\"{CSAF_EXTENSION_ID}\":{{\"channels\":[");
        let duplicate = format!("\"{CSAF_EXTENSION_ID}\":{{\"channels\":[],\"channels\":[");
        let raw = raw.replacen(&marker, &duplicate, 1);

        assert!(assess_csaf(raw.as_bytes()).is_err());
    }

    #[test]
    fn duplicate_members_in_unknown_extensions_remain_core_errors() {
        let raw = String::from_utf8(raw_policy(None, false))
            .expect("JSON is UTF-8")
            .replace(
                "\"extensions\":{}",
                "\"extensions\":{\"https://example.com/unknown\":{\"x\":1,\"x\":2}}",
            );

        assert!(assess_csaf(raw.as_bytes()).is_err());
    }

    #[test]
    fn generic_absolute_uri_edges_follow_rfc3986_syntax() {
        for (specification, state) in [
            ("foo:", CsafState::Unsupported),
            ("foo:?x", CsafState::Unsupported),
            ("foo:#x", CsafState::Invalid),
            ("https://other.example/spec#v1", CsafState::Invalid),
            ("https://other.example/spec%23v1", CsafState::Unsupported),
            ("https://bad.example/\"", CsafState::Invalid),
            ("foo:/[::1]", CsafState::Invalid),
            ("foo:/user@[::1]", CsafState::Invalid),
            ("foo:/[v1.host]", CsafState::Invalid),
            ("foo:/path", CsafState::Unsupported),
            ("foo://[::1]/", CsafState::Unsupported),
            ("foo:///path", CsafState::Unsupported),
            ("foo://", CsafState::Unsupported),
            ("foo://user@@h/x", CsafState::Invalid),
            ("foo://h:abc/x", CsafState::Invalid),
            ("foo://h:/x", CsafState::Unsupported),
            ("foo://h:99999/x", CsafState::Unsupported),
        ] {
            let raw = raw_policy(
                Some(declaration(&[(
                    "mailto:security@example.com",
                    specification,
                )])),
                false,
            );
            assert_eq!(assess_csaf(&raw).expect("valid core policy").state, state);
        }
    }

    #[test]
    fn json_escapes_are_decoded_before_exact_channel_matching() {
        let raw = raw_policy(
            Some(declaration(&[(
                "mailto:security@example.com",
                CSAF_SPECIFICATION,
            )])),
            false,
        );
        let raw = String::from_utf8(raw).expect("JSON is UTF-8").replacen(
            "\"uri\":\"mailto:security@example.com\"",
            r#""uri":"mailto:\u0073ecurity@example.com""#,
            1,
        );

        let assessed = assess_csaf(raw.as_bytes()).expect("valid core policy");
        assert_eq!(assessed.state, CsafState::Advertised);
    }

    #[test]
    fn report_only_policy_can_be_used_with_current_host_evidence() {
        let raw = raw_policy(
            Some(declaration(&[(
                "mailto:security@example.com",
                CSAF_SPECIFICATION,
            )])),
            false,
        );
        let assessed = assess_csaf_for_host(
            &raw,
            Some(&evidence("2027-05-07T00:00:00Z")),
            Some(&retrieval()),
            &context("2026-11-08T12:00:00Z"),
        );

        assert!(assessed.usable);
        assert_eq!(
            assessed.capability.expect("valid policy").state,
            CsafState::Advertised
        );
    }

    #[test]
    fn current_host_use_requires_fresh_authority_and_retrieval() {
        let raw = raw_policy(
            Some(declaration(&[(
                "mailto:security@example.com",
                CSAF_SPECIFICATION,
            )])),
            false,
        );
        let assessed = assess_csaf_for_host(
            &raw,
            Some(&evidence("2026-11-08T12:00:00Z")),
            None,
            &context("2026-11-08T12:00:00Z"),
        );

        assert!(!assessed.usable);
        assert!(!assessed.diagnostics.is_empty());
    }

    #[test]
    fn retrieval_failure_precedes_stale_authority_diagnostics() {
        let raw = raw_policy(
            Some(declaration(&[(
                "mailto:security@example.com",
                CSAF_SPECIFICATION,
            )])),
            false,
        );
        let mut invalid_retrieval = retrieval();
        invalid_retrieval.status_code = 503;
        let assessed = assess_csaf_for_host(
            &raw,
            Some(&evidence("2026-11-08T12:00:00Z")),
            Some(&invalid_retrieval),
            &context("2026-11-08T12:00:00Z"),
        );

        assert!(!assessed.usable);
        assert_eq!(
            assessed.diagnostics.first().map(|item| item.code.as_str()),
            Some("policy_retrieval_invalid")
        );
        assert_eq!(
            assessed
                .capability
                .expect("local metadata is independent")
                .state,
            CsafState::Advertised
        );
    }

    #[test]
    fn stale_authority_is_reported_after_valid_retrieval() {
        let raw = raw_policy(
            Some(declaration(&[(
                "mailto:security@example.com",
                CSAF_SPECIFICATION,
            )])),
            false,
        );
        let assessed = assess_csaf_for_host(
            &raw,
            Some(&evidence("2026-11-08T12:00:00Z")),
            Some(&retrieval()),
            &context("2026-11-08T12:00:00Z"),
        );

        assert!(!assessed.usable);
        assert_eq!(
            assessed.diagnostics.first().map(|item| item.code.as_str()),
            Some("security_txt_expired")
        );
    }

    #[test]
    fn policy_expiry_blocks_host_use_without_changing_local_metadata() {
        let raw = String::from_utf8(raw_policy(
            Some(declaration(&[(
                "mailto:security@example.com",
                CSAF_SPECIFICATION,
            )])),
            false,
        ))
        .expect("JSON is UTF-8")
        .replace("2027-05-07T00:00:00Z", "2026-11-09T00:00:00Z");

        assert_eq!(
            assess_csaf(raw.as_bytes())
                .expect("expiry is separate from local assessment")
                .state,
            CsafState::Advertised
        );
        let host = assess_csaf_for_host(
            raw.as_bytes(),
            Some(&evidence("2027-05-07T00:00:00Z")),
            Some(&retrieval()),
            &context("2026-11-10T00:00:00Z"),
        );
        assert!(!host.usable);
        assert!(host
            .diagnostics
            .iter()
            .any(|item| item.code == "policy_expired"));
    }

    #[test]
    fn policy_expiry_precedes_critical_host_rejection() {
        let raw = String::from_utf8(raw_policy(
            Some(declaration(&[(
                "mailto:security@example.com",
                CSAF_SPECIFICATION,
            )])),
            true,
        ))
        .expect("JSON is UTF-8")
        .replace("2027-05-07T00:00:00Z", "2026-11-09T00:00:00Z");
        let host = assess_csaf_for_host(
            raw.as_bytes(),
            Some(&evidence("2027-05-07T00:00:00Z")),
            Some(&retrieval()),
            &context("2026-11-10T00:00:00Z"),
        );

        assert_eq!(
            host.diagnostics.first().map(|item| item.code.as_str()),
            Some("policy_expired")
        );
        assert!(host
            .diagnostics
            .iter()
            .any(|item| item.code == "policy_critical_extension_unsupported"));
        assert_eq!(
            host.capability
                .expect("local declaration is retained")
                .state,
            CsafState::Unsupported
        );
    }

    #[test]
    fn unrelated_unsupported_critical_extension_blocks_host_use() {
        let mut policy: Value = serde_json::from_slice(&raw_policy(
            Some(declaration(&[(
                "mailto:security@example.com",
                CSAF_SPECIFICATION,
            )])),
            false,
        ))
        .expect("valid fixture JSON");
        let other_id = "https://example.com/other-extension";
        policy["extensions"][other_id] = json!({"metadata": true});
        policy["critical_extensions"] = json!([other_id]);
        let raw = serde_json::to_vec(&policy).expect("JSON values serialize");

        assert_eq!(
            assess_csaf(&raw)
                .expect("local declaration stays advertised")
                .state,
            CsafState::Advertised
        );
        let host = assess_csaf_for_host(
            &raw,
            Some(&evidence("2027-05-07T00:00:00Z")),
            Some(&retrieval()),
            &context("2026-11-08T12:00:00Z"),
        );
        assert!(!host.usable);
        assert!(host
            .diagnostics
            .iter()
            .any(|item| { item.code == "policy_critical_extension_unsupported" }));
    }
}
