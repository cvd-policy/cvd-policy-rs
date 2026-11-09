//! Evaluates Version 1 policy statements in normative precedence order.

use std::cmp::Ordering;

use serde_json::{Number, Value};

use crate::authority::authority_evidence_issues;
use crate::number;
use crate::policy::Policy;
use crate::retrieval::policy_retrieval_issues;
use crate::scope::{matching_scope_ids, normalize_target, scope_entry_matches};
use crate::types::{
    AuthorityEvidence, Diagnostic, EvaluationContext, EvaluationPlan, EvaluationQuery, InputError,
    PermissionResult, PermissionStatus, PolicyError, PolicyErrorKind,
};

const MAX_PLAN_NUMBER_LEXEME_BYTES: usize = 4_096;

/// Evaluates the publisher's statements for a validated target and supplied evidence.
///
/// Target input is validated before policy processing. Policy failures remain ordinary
/// `PermissionResult` statuses; only invalid call input is returned as `Err`.
/// Planned numbers are compared as exact JSON decimals without floating-point conversion.
/// Caller-created numbers must have valid JSON-number lexemes no longer than 4,096 bytes;
/// invalid or oversized values make the corresponding condition unsatisfied with a diagnostic.
///
/// # Errors
/// Returns an input error when the target is not an absolute HTTP(S) URL without userinfo.
pub fn evaluate_policy(
    raw: &[u8],
    query: &EvaluationQuery,
    authority: Option<&AuthorityEvidence>,
    context: &EvaluationContext,
) -> Result<PermissionResult, InputError> {
    let target = normalize_target(&query.target)?;
    let policy = match Policy::parse(raw) {
        Ok(policy) => policy,
        Err(error) => {
            let status = if error.kind == PolicyErrorKind::UnsupportedVersion {
                PermissionStatus::UnsupportedPolicy
            } else {
                PermissionStatus::InvalidPolicy
            };
            return Ok(result(status, policy_error_diagnostics(error)));
        }
    };

    if let Err(error) = policy.validate_at(&context.now) {
        return Ok(result(
            PermissionStatus::InvalidPolicy,
            policy_error_diagnostics(error),
        ));
    }

    let understood = &query.understood_extensions;
    let critical_extensions = policy
        .value()
        .get("critical_extensions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    if critical_extensions.into_iter().any(|extension| {
        extension == crate::csaf::CSAF_EXTENSION_ID
            || !understood.iter().any(|item| item == extension)
    }) {
        return Ok(result(
            PermissionStatus::UnsupportedPolicy,
            vec![diagnostic(
                "policy_critical_extension_unsupported",
                "/critical_extensions",
                "policy requires a critical extension that this evaluation does not support",
            )],
        ));
    }
    if !is_core_activity(&query.activity)
        && !understood
            .iter()
            .any(|activity| activity == &query.activity)
    {
        return Ok(result(
            PermissionStatus::UnsupportedPolicy,
            vec![diagnostic(
                "policy_activity_unsupported",
                "/activity",
                "requested activity is not understood",
            )],
        ));
    }

    let Some(authority) = authority else {
        return Ok(result(
            PermissionStatus::AuthorityNotEstablished,
            vec![diagnostic(
                "authority_evidence_missing",
                "/authority",
                "authority evidence is required for permission evaluation",
            )],
        ));
    };
    let retrieval_issues =
        policy_retrieval_issues(authority, query.policy_retrieval.as_ref(), context);
    if !retrieval_issues.is_empty() {
        return Ok(result(
            PermissionStatus::AuthorityNotEstablished,
            retrieval_issues,
        ));
    }
    let evidence_issues = authority_evidence_issues(authority, context);
    if !evidence_issues.is_empty() {
        return Ok(result(
            PermissionStatus::AuthorityNotEstablished,
            evidence_issues,
        ));
    }

    let Ok(discovery_host) = crate::scope::normalize_host(&authority.discovery_host) else {
        return Ok(result(
            PermissionStatus::AuthorityNotEstablished,
            vec![diagnostic(
                "authority_host_mismatch",
                "/authority/discoveryHost",
                "authority evidence has an invalid discovery host",
            )],
        ));
    };
    if discovery_host != target.host {
        return Ok(result(
            PermissionStatus::AuthorityNotEstablished,
            vec![diagnostic(
                "authority_host_mismatch",
                "/target",
                "target host does not exactly match the discovery host",
            )],
        ));
    }

    let matching_ids = matching_scope_ids(&policy, &target);
    let matching_entries = policy
        .value()
        .get("reporting_scope")
        .and_then(|scope| scope.get("web"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| scope_entry_matches(entry, &target))
        .collect::<Vec<_>>();
    let mut in_ids = matching_entries
        .iter()
        .filter(|entry| entry.get("state").and_then(Value::as_str) == Some("in"))
        .filter_map(|entry| entry.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let out_ids = matching_entries
        .iter()
        .filter(|entry| entry.get("state").and_then(Value::as_str) == Some("out"))
        .filter_map(|entry| entry.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    in_ids.sort();
    let mut matched_target_ids = matching_ids;
    matched_target_ids.sort();

    if !out_ids.is_empty() {
        return Ok(result_with_targets(
            PermissionStatus::NotCovered,
            vec![diagnostic(
                "scope_target_excluded",
                "/reporting_scope/web",
                "target matches an out-of-scope entry",
            )],
            Vec::new(),
            matched_target_ids,
        ));
    }
    if in_ids.is_empty() {
        return Ok(result_with_targets(
            PermissionStatus::NotCovered,
            vec![diagnostic(
                "scope_target_not_covered",
                "/reporting_scope/web",
                "target has no matching in-scope entry",
            )],
            Vec::new(),
            matched_target_ids,
        ));
    }

    let posture = policy
        .value()
        .get("research")
        .and_then(|research| research.get("posture"))
        .and_then(Value::as_str);
    if matches!(posture, Some("report_only" | "prohibited")) {
        return Ok(result_with_targets(
            PermissionStatus::PublisherStatedProhibited,
            Vec::new(),
            Vec::new(),
            in_ids,
        ));
    }

    let rules = policy
        .value()
        .get("testing")
        .and_then(|testing| testing.get("rules"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|rule| {
            rule.get("activity").and_then(Value::as_str) == Some(query.activity.as_str())
                && rule_applies_to_targets(rule, &in_ids)
        })
        .collect::<Vec<_>>();

    let mut prohibited_ids = rules
        .iter()
        .filter(|rule| rule.get("state").and_then(Value::as_str) == Some("prohibited"))
        .filter_map(|rule| rule.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    prohibited_ids.sort();
    if !prohibited_ids.is_empty() {
        return Ok(result_with_targets(
            PermissionStatus::PublisherStatedProhibited,
            vec![diagnostic(
                "testing_rule_prohibited",
                "/testing/rules",
                "a matching prohibited rule overrides permitted rules",
            )],
            prohibited_ids,
            in_ids,
        ));
    }

    let mut permitted = rules
        .iter()
        .copied()
        .filter(|rule| rule.get("state").and_then(Value::as_str) == Some("permitted"))
        .collect::<Vec<_>>();
    permitted.sort_by(|left, right| rule_id(left).cmp(rule_id(right)));
    if permitted.is_empty() {
        return Ok(result_with_targets(
            PermissionStatus::NotCovered,
            vec![diagnostic(
                "testing_rule_missing",
                "/testing/rules",
                "no matching testing rule exists",
            )],
            Vec::new(),
            in_ids,
        ));
    }

    let satisfied_ids = permitted
        .iter()
        .filter(|rule| conditions_satisfied(rule, query.plan.as_ref()).is_none())
        .filter_map(|rule| rule.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !satisfied_ids.is_empty() {
        return Ok(result_with_targets(
            PermissionStatus::PublisherStatedPermitted,
            Vec::new(),
            satisfied_ids,
            in_ids,
        ));
    }

    let failure = permitted
        .first()
        .and_then(|rule| conditions_satisfied(rule, query.plan.as_ref()))
        .unwrap_or_else(|| {
            diagnostic(
                "conditions_missing",
                "/plan",
                "required planned values are missing",
            )
        });
    let permitted_ids = permitted
        .iter()
        .filter_map(|rule| rule.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    Ok(result_with_targets(
        PermissionStatus::ConditionsNotSatisfied,
        vec![failure],
        permitted_ids,
        in_ids,
    ))
}

fn policy_error_diagnostics(error: PolicyError) -> Vec<Diagnostic> {
    if error.diagnostics.is_empty() {
        vec![diagnostic(
            if error.kind == PolicyErrorKind::UnsupportedVersion {
                "policy_version_unsupported"
            } else {
                "policy_parse_error"
            },
            "",
            "policy processing failed without a detailed diagnostic",
        )]
    } else {
        error.diagnostics
    }
}

fn is_core_activity(activity: &str) -> bool {
    matches!(
        activity,
        "manual_testing" | "automated_scanning" | "fuzzing" | "credential_testing"
    )
}

fn rule_applies_to_targets(rule: &Value, in_ids: &[String]) -> bool {
    let Some(target_ids) = rule.get("target_ids") else {
        return rule.get("state").and_then(Value::as_str) == Some("prohibited");
    };
    target_ids.as_array().is_some_and(|target_ids| {
        target_ids.iter().any(|target_id| {
            target_id
                .as_str()
                .is_some_and(|target_id| in_ids.iter().any(|in_id| in_id == target_id))
        })
    })
}

fn rule_id(rule: &Value) -> &str {
    rule.get("id").and_then(Value::as_str).unwrap_or_default()
}

fn conditions_satisfied(rule: &Value, plan: Option<&EvaluationPlan>) -> Option<Diagnostic> {
    let conditions = rule.get("conditions")?;
    if let Some(limit) = conditions
        .get("max_requests_per_second")
        .and_then(Value::as_number)
    {
        let Some(planned) = plan.and_then(|plan| plan.requests_per_second.as_ref()) else {
            return Some(diagnostic(
                "conditions_missing",
                "/plan/requestsPerSecond",
                "the planned request rate is required",
            ));
        };
        if let Some(issue) = plan_number_issue(planned, "/plan/requestsPerSecond") {
            return Some(issue);
        }
        if number::compare(planned, limit) == Ordering::Greater {
            return Some(diagnostic(
                "conditions_exceeded",
                "/plan/requestsPerSecond",
                "planned request rate exceeds the published limit",
            ));
        }
    }
    if let Some(limit) = conditions
        .get("max_concurrent_requests")
        .and_then(Value::as_number)
    {
        let Some(planned) = plan.and_then(|plan| plan.concurrent_requests.as_ref()) else {
            return Some(diagnostic(
                "conditions_missing",
                "/plan/concurrentRequests",
                "planned concurrency is required",
            ));
        };
        if let Some(issue) = plan_number_issue(planned, "/plan/concurrentRequests") {
            return Some(issue);
        }
        if number::compare(planned, limit) == Ordering::Greater {
            return Some(diagnostic(
                "conditions_exceeded",
                "/plan/concurrentRequests",
                "planned concurrency exceeds the published limit",
            ));
        }
    }
    if let Some(token) = conditions
        .get("required_user_agent_token")
        .and_then(Value::as_str)
    {
        if !plan
            .and_then(|plan| plan.user_agent.as_ref())
            .is_some_and(|user_agent| user_agent.contains(token))
        {
            return Some(diagnostic(
                "conditions_user_agent_missing",
                "/plan/userAgent",
                "planned User-Agent does not contain the required token",
            ));
        }
    }
    if conditions
        .get("test_accounts_only")
        .and_then(Value::as_bool)
        == Some(true)
        && plan.and_then(|plan| plan.uses_only_test_accounts) != Some(true)
    {
        return Some(diagnostic(
            "conditions_test_accounts_unconfirmed",
            "/plan/usesOnlyTestAccounts",
            "use of only controlled or provided test accounts was not confirmed",
        ));
    }
    None
}

fn plan_number_issue(number: &Number, path: &str) -> Option<Diagnostic> {
    let lexeme = number.as_str();
    if lexeme.len() > MAX_PLAN_NUMBER_LEXEME_BYTES {
        return Some(diagnostic(
            "conditions_plan_number_limit_exceeded",
            path,
            "planned number exceeds the 4,096-byte exact-comparison limit",
        ));
    }

    let bytes = lexeme.as_bytes();
    let starts_with_number = bytes
        .first()
        .is_some_and(|byte| *byte == b'-' || byte.is_ascii_digit());
    let ends_with_digit = bytes.last().is_some_and(|byte| byte.is_ascii_digit());
    if !starts_with_number || !ends_with_digit || serde_json::from_str::<Number>(lexeme).is_err() {
        return Some(diagnostic(
            "conditions_plan_number_invalid",
            path,
            "planned value is not a valid JSON number",
        ));
    }
    None
}

fn result(status: PermissionStatus, diagnostics: Vec<Diagnostic>) -> PermissionResult {
    result_with_targets(status, diagnostics, Vec::new(), Vec::new())
}

fn result_with_targets(
    status: PermissionStatus,
    diagnostics: Vec<Diagnostic>,
    matched_rule_ids: Vec<String>,
    matched_target_ids: Vec<String>,
) -> PermissionResult {
    PermissionResult {
        status,
        matched_rule_ids,
        matched_target_ids,
        diagnostics,
    }
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
    use serde_json::Number;

    use crate::authority::assess_security_txt;
    use crate::types::{
        EvaluationContext, EvaluationPlan, EvaluationQuery, PolicyRetrieval, SecurityTxtRetrieval,
    };

    use super::evaluate_policy;
    use crate::types::PermissionStatus;

    const POLICY: &str = r#"{
      "cvd_policy": 1,
      "last_updated": "2026-08-29T08:00:00Z",
      "expires": "2028-02-28T08:00:00Z",
      "organization": {"name": "Example"},
      "contact": {"channels": ["mailto:security@example.com"]},
      "research": {"posture": "limited"},
      "reporting_scope": {"web": [{"id": "main", "state": "in", "host": "example.com", "schemes": ["https"], "path_prefix": "/", "include_subdomains": false}]},
      "testing": {"rules": [{"id": "manual", "activity": "manual_testing", "state": "permitted", "target_ids": ["main"]}]},
      "reporting": {"requested_fields": [], "proof_of_exploitation": "not_requested"}
    }"#;

    fn context(now: &str) -> EvaluationContext {
        EvaluationContext::new(crate::timestamp::Timestamp::parse(now).unwrap())
    }

    fn evidence(expires: &str) -> crate::types::AuthorityEvidence {
        let text = format!(
            "Contact: mailto:security@example.com\nCVD-Policy: https://example.com/policy.json\nExpires: {expires}\n"
        );
        assess_security_txt(
            text.as_bytes(),
            &SecurityTxtRetrieval {
                requested_uri: "https://example.com/.well-known/security.txt".to_owned(),
                final_uri: "https://example.com/.well-known/security.txt".to_owned(),
                redirect_chain: Vec::new(),
                retrieved_at: crate::timestamp::Timestamp::parse("2026-08-29T10:00:00Z").unwrap(),
            },
        )
        .evidence
        .unwrap()
    }

    fn query() -> EvaluationQuery {
        EvaluationQuery {
            activity: "manual_testing".to_owned(),
            target: "https://example.com/".to_owned(),
            plan: None,
            understood_extensions: Vec::new(),
            policy_retrieval: Some(PolicyRetrieval {
                requested_uri: "https://example.com/policy.json".to_owned(),
                final_uri: "https://example.com/policy.json".to_owned(),
                redirect_chain: Vec::new(),
                status_code: 200,
                media_type: "application/cvd-policy+json".to_owned(),
            }),
        }
    }

    #[test]
    fn validates_target_before_returning_a_policy_status() {
        for target in [
            "https://user@example.com/",
            "https://@example.com/",
            r"https:\\example.com\path",
            "https:///example.com/",
            "https://example.com/a b",
            "https://example.com/[x]",
            "https://example.com/ü",
        ] {
            let mut query = query();
            query.target = target.to_owned();
            let error =
                evaluate_policy(b"not JSON", &query, None, &context("2026-08-29T10:00:00Z"))
                    .unwrap_err();
            assert_eq!(
                error.diagnostics[0].code, "target_url_invalid",
                "{target:?}"
            );
        }
    }

    #[test]
    fn policy_expiry_is_rechecked_at_equality_before_extensions_and_authority() {
        let mut policy: serde_json::Value = serde_json::from_str(POLICY).unwrap();
        policy["expires"] = serde_json::Value::String("2026-08-29T10:00:00Z".to_owned());
        policy["critical_extensions"] = serde_json::json!(["https://example.org/ext/unknown"]);
        policy["extensions"] = serde_json::json!({"https://example.org/ext/unknown": true});
        let raw = serde_json::to_vec(&policy).unwrap();
        let earlier =
            evaluate_policy(&raw, &query(), None, &context("2026-08-29T09:59:59Z")).unwrap();
        assert_eq!(earlier.status, PermissionStatus::UnsupportedPolicy);
        assert_eq!(
            earlier.diagnostics[0].code,
            "policy_critical_extension_unsupported"
        );

        let result =
            evaluate_policy(&raw, &query(), None, &context("2026-08-29T10:00:00Z")).unwrap();
        assert_eq!(result.status, PermissionStatus::InvalidPolicy);
        assert_eq!(result.diagnostics[0].code, "policy_expired");
    }

    #[test]
    fn critical_csaf_extension_is_unsupported_even_when_claimed_understood() {
        let mut policy: serde_json::Value = serde_json::from_str(POLICY).unwrap();
        let extension_id = crate::csaf::CSAF_EXTENSION_ID;
        policy["critical_extensions"] = serde_json::json!([extension_id]);
        policy["extensions"] = serde_json::json!({});
        policy["extensions"][extension_id] = serde_json::json!({});
        let mut query = query();
        query.understood_extensions.push(extension_id.to_owned());
        let result = evaluate_policy(
            serde_json::to_string(&policy).unwrap().as_bytes(),
            &query,
            Some(&evidence("2027-02-28T08:00:00Z")),
            &context("2026-08-29T10:00:00Z"),
        )
        .unwrap();
        assert_eq!(result.status, PermissionStatus::UnsupportedPolicy);
    }

    #[test]
    fn invalid_retrieval_precedes_expired_authority() {
        let authority = evidence("2026-08-29T10:01:00Z");
        let mut query = query();
        query.policy_retrieval.as_mut().unwrap().status_code = 206;
        let result = evaluate_policy(
            POLICY.as_bytes(),
            &query,
            Some(&authority),
            &context("2026-08-29T10:01:00Z"),
        )
        .unwrap();

        assert_eq!(result.status, PermissionStatus::AuthorityNotEstablished);
        assert_eq!(result.diagnostics[0].code, "policy_retrieval_invalid");
    }

    #[test]
    fn evidence_that_was_fresh_becomes_invalid_at_its_expiry() {
        let policy = POLICY.as_bytes();
        let authority = evidence("2027-02-28T08:00:00Z");
        let permitted = evaluate_policy(
            policy,
            &query(),
            Some(&authority),
            &context("2026-08-29T10:00:00Z"),
        )
        .unwrap();
        assert_eq!(permitted.status, PermissionStatus::PublisherStatedPermitted);

        let stale = evaluate_policy(
            policy,
            &query(),
            Some(&authority),
            &context("2027-02-28T08:00:00Z"),
        )
        .unwrap();
        assert_eq!(stale.status, PermissionStatus::AuthorityNotEstablished);
        assert_eq!(stale.diagnostics[0].code, "security_txt_expired");
    }

    #[test]
    fn a_permitted_rule_is_positive_only_when_every_condition_is_satisfied() {
        let mut policy: serde_json::Value = serde_json::from_str(POLICY).unwrap();
        policy["testing"]["rules"][0] = serde_json::json!({
            "id": "scan",
            "activity": "automated_scanning",
            "state": "permitted",
            "target_ids": ["main"],
            "conditions": {
                "max_requests_per_second": 0.3,
                "max_concurrent_requests": 2,
                "required_user_agent_token": "ResearchBot"
            }
        });
        let raw = serde_json::to_vec(&policy).unwrap();
        let mut query = query();
        query.activity = "automated_scanning".to_owned();
        query.plan = Some(EvaluationPlan {
            requests_per_second: Some(serde_json::from_str("0.30000000000000000001").unwrap()),
            concurrent_requests: Some(Number::from(2)),
            user_agent: Some("ResearchBot/1".to_owned()),
            uses_only_test_accounts: None,
        });
        let result = evaluate_policy(
            &raw,
            &query,
            Some(&evidence("2027-02-28T08:00:00Z")),
            &context("2026-08-29T10:00:00Z"),
        )
        .unwrap();
        assert_eq!(result.status, PermissionStatus::ConditionsNotSatisfied);
        assert_eq!(result.diagnostics[0].code, "conditions_exceeded");
    }

    #[test]
    fn forged_or_oversized_plan_numbers_cannot_establish_permission() {
        let mut policy: serde_json::Value = serde_json::from_str(POLICY).unwrap();
        policy["testing"]["rules"][0]["conditions"] =
            serde_json::json!({"max_requests_per_second": 1});
        let raw = serde_json::to_vec(&policy).unwrap();
        let plan_numbers = [
            (
                Number::from_string_unchecked("-Infinity".to_owned()),
                "conditions_plan_number_invalid",
            ),
            (
                Number::from_string_unchecked(format!("1e{}", "9".repeat(4_095))),
                "conditions_plan_number_limit_exceeded",
            ),
        ];

        for (requests_per_second, diagnostic_code) in plan_numbers {
            let mut query = query();
            query.plan = Some(EvaluationPlan {
                requests_per_second: Some(requests_per_second),
                ..EvaluationPlan::default()
            });
            let result = evaluate_policy(
                &raw,
                &query,
                Some(&evidence("2027-02-28T08:00:00Z")),
                &context("2026-08-29T10:00:00Z"),
            )
            .unwrap();

            assert_eq!(result.status, PermissionStatus::ConditionsNotSatisfied);
            assert_eq!(result.diagnostics[0].code, diagnostic_code);
        }
    }

    #[test]
    fn negative_fractional_plan_number_is_compared_without_a_new_lower_bound() {
        let mut policy: serde_json::Value = serde_json::from_str(POLICY).unwrap();
        policy["testing"]["rules"][0]["conditions"] =
            serde_json::json!({"max_requests_per_second": 1});
        let raw = serde_json::to_vec(&policy).unwrap();
        let mut query = query();
        query.plan = Some(EvaluationPlan {
            requests_per_second: Some(serde_json::from_str("-0.5").unwrap()),
            ..EvaluationPlan::default()
        });
        let result = evaluate_policy(
            &raw,
            &query,
            Some(&evidence("2027-02-28T08:00:00Z")),
            &context("2026-08-29T10:00:00Z"),
        )
        .unwrap();

        assert_eq!(result.status, PermissionStatus::PublisherStatedPermitted);
    }

    #[test]
    fn large_plan_exponents_are_compared_exactly_without_float_conversion() {
        let mut policy: serde_json::Value = serde_json::from_str(POLICY).unwrap();
        policy["testing"]["rules"][0]["conditions"]["max_requests_per_second"] =
            serde_json::from_str("1e400").unwrap();
        let raw = serde_json::to_vec(&policy).unwrap();
        let mut query = query();
        query.plan = Some(EvaluationPlan {
            requests_per_second: Some(serde_json::from_str("2e400").unwrap()),
            ..EvaluationPlan::default()
        });
        let result = evaluate_policy(
            &raw,
            &query,
            Some(&evidence("2027-02-28T08:00:00Z")),
            &context("2026-08-29T10:00:00Z"),
        )
        .unwrap();

        assert_eq!(result.status, PermissionStatus::ConditionsNotSatisfied);
        assert_eq!(result.diagnostics[0].code, "conditions_exceeded");
    }
}
