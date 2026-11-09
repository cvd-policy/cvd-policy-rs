//! Parses and validates Version 1 policy documents.
//!
//! Core members are validated strictly, while extension values are retained unchanged.
//! Validation checks document structure and static semantics; it does not compare expiry
//! with the current time or interpret extension-defined data.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use language_tags::LanguageTag;
use serde_json::{Map, Number, Value};

use crate::parse::{self, ParseLimits};
use crate::scope;
use crate::timestamp::Timestamp;
use crate::types::{Diagnostic, PolicyError, PolicyErrorKind};
use crate::{number, uri};

const POLICY_MEMBERS: &[&str] = &[
    "cvd_policy",
    "last_updated",
    "expires",
    "organization",
    "contact",
    "research",
    "reporting_scope",
    "testing",
    "reporting",
    "response_targets",
    "disclosure",
    "critical_extensions",
    "extensions",
];
const POLICY_REQUIRED: &[&str] = &[
    "cvd_policy",
    "last_updated",
    "expires",
    "organization",
    "contact",
    "research",
    "reporting_scope",
    "reporting",
];
const CORE_ACTIVITIES: &[&str] = &[
    "manual_testing",
    "automated_scanning",
    "fuzzing",
    "credential_testing",
];

/// A validated Version 1 policy backed by its original JSON values.
///
/// Core objects reject unknown members. Extension member values remain arbitrary JSON and are
/// returned without normalization. Static validation checks timestamp ordering, not expiry
/// against a clock.
///
/// # Examples
///
/// ```
/// use cvd_policy::Policy;
///
/// let policy = Policy::parse(br#"{
///   "cvd_policy": 1,
///   "last_updated": "2026-01-01T00:00:00Z",
///   "expires": "2026-06-01T00:00:00Z",
///   "organization": {"name": "Example"},
///   "contact": {"channels": ["mailto:security@example.com"]},
///   "research": {"posture": "report_only"},
///   "reporting_scope": {"web": [{
///     "id": "main", "state": "in", "host": "example.com",
///     "schemes": ["https"], "path_prefix": "/", "include_subdomains": false
///   }]},
///   "reporting": {"requested_fields": [], "proof_of_exploitation": "not_requested"}
/// }"#)?;
/// assert_eq!(policy.value()["organization"]["name"], "Example");
/// # Ok::<(), cvd_policy::PolicyError>(())
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    value: Value,
}

impl Policy {
    /// Parses and validates a Version 1 policy using the default resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, duplicate object names, unsupported versions,
    /// structural or semantic errors, or exceeded default resource limits.
    pub fn parse(raw: &[u8]) -> Result<Self, PolicyError> {
        Self::parse_with_limits(raw, ParseLimits::default())
    }

    /// Parses and validates a Version 1 policy using caller-supplied resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, duplicate object names, unsupported versions,
    /// structural or semantic errors, or exceeded resource limits.
    pub fn parse_with_limits(raw: &[u8], limits: ParseLimits) -> Result<Self, PolicyError> {
        let value = parse::parse_json(raw, limits)?;
        Self::validate_value(value)
    }

    /// Validates and stores an already parsed JSON value.
    ///
    /// The default value limits are checked before any policy validation. Rejected deeply nested
    /// values are discarded iteratively to avoid recursive destruction of attacker-controlled
    /// nesting.
    ///
    /// # Errors
    ///
    /// Returns an error for exceeded resource limits, unsupported versions, or invalid structure
    /// or static semantics.
    pub fn from_value(value: Value) -> Result<Self, PolicyError> {
        if let Err(error) = parse::check_value_limits(&value, ParseLimits::default()) {
            drop_value_iteratively(value);
            return Err(error);
        }

        Self::validate_value(value)
    }

    /// Returns the validated JSON value without normalizing preserved policy data.
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// Serializes the validated policy as compact JSON.
    ///
    /// # Errors
    ///
    /// Returns an invalid-policy error if JSON serialization fails.
    pub fn to_json(&self) -> Result<String, PolicyError> {
        serde_json::to_string(&self.value).map_err(|error| {
            invalid_error(vec![diagnostic(
                "policy_serialization_failed",
                "",
                &format!("The validated policy could not be serialized: {error}"),
            )])
        })
    }

    /// Checks whether the policy is valid at the caller-supplied instant.
    ///
    /// This method reads no clock and stores no freshness or proof state. Construction has already
    /// checked static validity and timestamp ordering; this adds only the expiry check.
    ///
    /// # Errors
    ///
    /// Returns an invalid-policy error with code `policy_expired` when `expires <= now`.
    pub fn validate_at(&self, now: &Timestamp) -> Result<(), PolicyError> {
        let expires = self
            .value
            .get("expires")
            .and_then(Value::as_str)
            .and_then(|value| Timestamp::parse(value).ok());
        let Some(expires) = expires else {
            return Err(invalid_error(vec![diagnostic(
                "policy_expiry_invalid",
                "/expires",
                "The validated policy has no parseable expiry instant.",
            )]));
        };

        if &expires <= now {
            Err(invalid_error(vec![diagnostic(
                "policy_expired",
                "/expires",
                "The policy has expired at the supplied instant.",
            )]))
        } else {
            Ok(())
        }
    }

    fn validate_value(value: Value) -> Result<Self, PolicyError> {
        if let Some(error) = version_error(&value) {
            return Err(error);
        }
        let structure_issues = validate_structure(&value);
        if !structure_issues.is_empty() {
            return Err(invalid_error(structure_issues));
        }
        let semantic_issues = semantic_issues(&value);
        if semantic_issues.is_empty() {
            Ok(Self { value })
        } else {
            Err(invalid_error(semantic_issues))
        }
    }
}

/// Validates the Version 1 JSON Schema structure of an arbitrary value.
///
/// This function checks types, required and forbidden core members, schema formats, and array
/// constraints. It does not apply cross-field semantic rules or compare expiry with a clock.
pub fn validate_structure(value: &Value) -> Vec<Diagnostic> {
    if let Some(error) = version_error(value) {
        return error.diagnostics;
    }

    let mut issues = Vec::new();
    let Some(root) = check_object(value, "", POLICY_MEMBERS, POLICY_REQUIRED, &mut issues) else {
        return issues;
    };

    for field in ["last_updated", "expires"] {
        if let Some(timestamp) = root.get(field) {
            let path = format!("/{field}");
            if let Some(timestamp) = check_string(timestamp, &path, &mut issues) {
                if Timestamp::parse(timestamp).is_err() {
                    push_schema_issue(&mut issues, &path, "Expected a valid RFC 3339 date-time.");
                }
            }
        }
    }
    if let Some(value) = root.get("organization") {
        validate_organization(value, &mut issues);
    }
    if let Some(value) = root.get("contact") {
        validate_contact(value, &mut issues);
    }
    if let Some(value) = root.get("research") {
        validate_research(value, &mut issues);
    }
    if let Some(value) = root.get("reporting_scope") {
        validate_reporting_scope(value, &mut issues);
    }
    if let Some(value) = root.get("testing") {
        validate_testing(value, &mut issues);
    }
    if let Some(value) = root.get("reporting") {
        validate_reporting(value, &mut issues);
    }
    if let Some(value) = root.get("response_targets") {
        validate_response_targets(value, &mut issues);
    }
    if let Some(value) = root.get("disclosure") {
        validate_disclosure(value, &mut issues);
    }
    if let Some(value) = root.get("critical_extensions") {
        validate_critical_extensions(value, &mut issues);
    }
    if let Some(value) = root.get("extensions") {
        validate_extensions(value, &mut issues);
    }
    issues
}

/// Returns semantic diagnostics for an arbitrary JSON value.
///
/// Structural validation is independent and should be performed first. This function never
/// checks expiry against a clock or interprets extension-defined values.
pub fn semantic_issues(value: &Value) -> Vec<Diagnostic> {
    let mut issues = Vec::new();
    validate_timestamp_semantics(value, &mut issues);
    validate_uri_semantics(value, &mut issues);
    validate_scope_semantics(value, &mut issues);
    validate_policy_relations(value, &mut issues);
    issues
}

fn version_error(value: &Value) -> Option<PolicyError> {
    let version = value.get("cvd_policy")?;
    let Value::Number(version) = version else {
        return Some(invalid_error(vec![diagnostic(
            "policy_version_invalid",
            "/cvd_policy",
            "The policy version must be an integer JSON number.",
        )]));
    };

    if !number::is_integer(version) {
        return Some(invalid_error(vec![diagnostic(
            "policy_version_invalid",
            "/cvd_policy",
            "The policy version must be an integer JSON number.",
        )]));
    }

    (number::compare(version, &Number::from(1)) != Ordering::Equal).then(|| PolicyError {
        kind: PolicyErrorKind::UnsupportedVersion,
        diagnostics: vec![diagnostic(
            "policy_version_unsupported",
            "/cvd_policy",
            "The policy uses an unsupported integer format version.",
        )],
    })
}

fn validate_organization(value: &Value, issues: &mut Vec<Diagnostic>) {
    let Some(object) = check_object(value, "/organization", &["name", "uri"], &["name"], issues)
    else {
        return;
    };
    if let Some(name) = object.get("name") {
        check_string_bounds(name, "/organization/name", 1, Some(200), issues);
    }
    if let Some(uri_value) = object.get("uri") {
        validate_https_uri_schema(uri_value, "/organization/uri", issues);
    }
}

fn validate_contact(value: &Value, issues: &mut Vec<Diagnostic>) {
    let Some(object) = check_object(
        value,
        "/contact",
        &["channels", "preferred_languages", "encryption"],
        &["channels"],
        issues,
    ) else {
        return;
    };

    if let Some(channels) = object.get("channels") {
        if let Some(channels) = check_array(channels, "/contact/channels", true, issues) {
            check_unique_strings(channels, "/contact/channels", issues);
            for (index, channel) in channels.iter().enumerate() {
                let path = index_path("/contact/channels", index);
                let Some(channel) = check_string(channel, &path, issues) else {
                    continue;
                };
                let matches_schema_pattern = channel.starts_with("mailto:")
                    || channel.starts_with("tel:")
                    || (channel.starts_with("https://") && !channel.contains('#'));
                if !uri::is_uri(channel) || !matches_schema_pattern {
                    push_schema_issue(
                        issues,
                        &path,
                        "The contact channel does not match the Version 1 schema URI pattern.",
                    );
                }
            }
        }
    }

    if let Some(languages) = object.get("preferred_languages") {
        if let Some(languages) =
            check_array(languages, "/contact/preferred_languages", false, issues)
        {
            check_unique_strings(languages, "/contact/preferred_languages", issues);
            for (index, language) in languages.iter().enumerate() {
                let path = index_path("/contact/preferred_languages", index);
                if let Some(language) = check_string_bounds(language, &path, 1, Some(63), issues) {
                    if !language.split('-').all(|part| {
                        !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
                    }) {
                        push_schema_issue(issues, &path, "The language tag has invalid syntax.");
                    }
                }
            }
        }
    }

    if let Some(encryption) = object.get("encryption") {
        if let Some(encryption) = check_array(encryption, "/contact/encryption", false, issues) {
            check_unique_strings(encryption, "/contact/encryption", issues);
            for (index, identifier) in encryption.iter().enumerate() {
                validate_schema_uri(
                    identifier,
                    &index_path("/contact/encryption", index),
                    issues,
                );
            }
        }
    }
}

fn validate_research(value: &Value, issues: &mut Vec<Diagnostic>) {
    let Some(object) = check_object(
        value,
        "/research",
        &["posture", "statement"],
        &["posture"],
        issues,
    ) else {
        return;
    };
    if let Some(posture) = object.get("posture") {
        check_enum(
            posture,
            "/research/posture",
            &["open", "limited", "report_only", "prohibited"],
            issues,
        );
    }
    if let Some(statement) = object.get("statement") {
        check_string_bounds(statement, "/research/statement", 0, Some(2000), issues);
    }
}

fn validate_reporting_scope(value: &Value, issues: &mut Vec<Diagnostic>) {
    let Some(object) = check_object(value, "/reporting_scope", &["web", "products"], &[], issues)
    else {
        return;
    };
    if !object.contains_key("web") && !object.contains_key("products") {
        push_schema_issue(
            issues,
            "/reporting_scope",
            "At least one of web or products must be present.",
        );
    }
    if let Some(web) = object.get("web") {
        if let Some(entries) = check_array(web, "/reporting_scope/web", true, issues) {
            for (index, entry) in entries.iter().enumerate() {
                validate_web_scope(entry, &index_path("/reporting_scope/web", index), issues);
            }
        }
    }
    if let Some(products) = object.get("products") {
        if let Some(entries) = check_array(products, "/reporting_scope/products", true, issues) {
            for (index, entry) in entries.iter().enumerate() {
                validate_product_scope(
                    entry,
                    &index_path("/reporting_scope/products", index),
                    issues,
                );
            }
        }
    }
}

fn validate_web_scope(value: &Value, path: &str, issues: &mut Vec<Diagnostic>) {
    let Some(object) = check_object(
        value,
        path,
        &[
            "id",
            "state",
            "host",
            "schemes",
            "ports",
            "path_prefix",
            "include_subdomains",
        ],
        &[
            "id",
            "state",
            "host",
            "schemes",
            "path_prefix",
            "include_subdomains",
        ],
        issues,
    ) else {
        return;
    };
    if let Some(id) = object.get("id") {
        check_id(id, &child_path(path, "id"), issues);
    }
    if let Some(state) = object.get("state") {
        check_enum(state, &child_path(path, "state"), &["in", "out"], issues);
    }
    if let Some(host) = object.get("host") {
        if let Some(host) =
            check_string_bounds(host, &child_path(path, "host"), 1, Some(253), issues)
        {
            if host.chars().any(|character| {
                character.is_whitespace() || matches!(character, '*' | '/' | '?' | '#' | '@')
            }) {
                push_schema_issue(
                    issues,
                    &child_path(path, "host"),
                    "The scope host has invalid syntax.",
                );
            }
        }
    }
    if let Some(schemes) = object.get("schemes") {
        let path = child_path(path, "schemes");
        if let Some(schemes) = check_array(schemes, &path, true, issues) {
            check_unique_strings(schemes, &path, issues);
            for (index, scheme) in schemes.iter().enumerate() {
                check_enum(
                    scheme,
                    &index_path(&path, index),
                    &["http", "https"],
                    issues,
                );
            }
        }
    }
    if let Some(ports) = object.get("ports") {
        let path = child_path(path, "ports");
        if let Some(ports) = check_array(ports, &path, true, issues) {
            check_unique_numbers(ports, &path, issues);
            for (index, port) in ports.iter().enumerate() {
                validate_integer_range(port, &index_path(&path, index), 1, 65535, issues);
            }
        }
    }
    if let Some(prefix) = object.get("path_prefix") {
        let path = child_path(path, "path_prefix");
        if let Some(prefix) = check_string(prefix, &path, issues) {
            if !valid_path_prefix_syntax(prefix) {
                push_schema_issue(issues, &path, "The path prefix must start with / and contain no query, fragment, or malformed escape.");
            }
        }
    }
    if let Some(include_subdomains) = object.get("include_subdomains") {
        check_bool(
            include_subdomains,
            &child_path(path, "include_subdomains"),
            issues,
        );
    }
}

fn validate_product_scope(value: &Value, path: &str, issues: &mut Vec<Diagnostic>) {
    let Some(object) = check_object(
        value,
        path,
        &["id", "state", "name", "identifiers"],
        &["id", "state", "name"],
        issues,
    ) else {
        return;
    };
    if let Some(id) = object.get("id") {
        check_id(id, &child_path(path, "id"), issues);
    }
    if let Some(state) = object.get("state") {
        check_enum(state, &child_path(path, "state"), &["in", "out"], issues);
    }
    if let Some(name) = object.get("name") {
        check_string_bounds(name, &child_path(path, "name"), 1, Some(200), issues);
    }
    if let Some(identifiers) = object.get("identifiers") {
        let path = child_path(path, "identifiers");
        if let Some(identifiers) = check_array(identifiers, &path, true, issues) {
            check_unique_strings(identifiers, &path, issues);
            for (index, identifier) in identifiers.iter().enumerate() {
                validate_schema_uri(identifier, &index_path(&path, index), issues);
            }
        }
    }
}

fn validate_testing(value: &Value, issues: &mut Vec<Diagnostic>) {
    let Some(object) = check_object(value, "/testing", &["rules"], &["rules"], issues) else {
        return;
    };
    if let Some(rules) = object.get("rules") {
        if let Some(rules) = check_array(rules, "/testing/rules", true, issues) {
            for (index, rule) in rules.iter().enumerate() {
                validate_rule(rule, &index_path("/testing/rules", index), issues);
            }
        }
    }
}

fn validate_rule(value: &Value, path: &str, issues: &mut Vec<Diagnostic>) {
    let Some(object) = check_object(
        value,
        path,
        &["id", "activity", "state", "target_ids", "conditions"],
        &["id", "activity", "state"],
        issues,
    ) else {
        return;
    };
    if let Some(id) = object.get("id") {
        check_id(id, &child_path(path, "id"), issues);
    }

    let activity = object.get("activity").and_then(Value::as_str);
    if let Some(activity) = object.get("activity") {
        let activity_path = child_path(path, "activity");
        if let Some(activity) = check_string(activity, &activity_path, issues) {
            if !CORE_ACTIVITIES.contains(&activity) && !is_schema_absolute_uri(activity) {
                push_schema_issue(
                    issues,
                    &activity_path,
                    "An extension activity must match the Version 1 URI schema.",
                );
            }
        }
    }

    let state = object.get("state").and_then(Value::as_str);
    if let Some(state) = object.get("state") {
        check_enum(
            state,
            &child_path(path, "state"),
            &["permitted", "prohibited"],
            issues,
        );
    }

    if let Some(target_ids) = object.get("target_ids") {
        let target_path = child_path(path, "target_ids");
        if let Some(target_ids) = check_array(target_ids, &target_path, true, issues) {
            check_unique_strings(target_ids, &target_path, issues);
            for (index, target_id) in target_ids.iter().enumerate() {
                check_id(target_id, &index_path(&target_path, index), issues);
            }
        }
    }

    let conditions = object.get("conditions");
    if let Some(conditions) = conditions {
        validate_conditions(conditions, &child_path(path, "conditions"), issues);
    }

    if state == Some("permitted") {
        if !object.contains_key("target_ids") {
            push_schema_issue(
                issues,
                &child_path(path, "target_ids"),
                "A permitted rule must name at least one target.",
            );
        }
        let required_conditions: &[&str] = match activity {
            Some("automated_scanning" | "fuzzing") => {
                &["max_requests_per_second", "max_concurrent_requests"]
            }
            Some("credential_testing") => &[
                "max_requests_per_second",
                "max_concurrent_requests",
                "test_accounts_only",
            ],
            _ => &[],
        };
        if !required_conditions.is_empty() && conditions.is_none() {
            push_schema_issue(
                issues,
                &child_path(path, "conditions"),
                "This permitted activity requires conditions.",
            );
        }
        if let Some(condition_object) = conditions.and_then(Value::as_object) {
            for required in required_conditions {
                if !condition_object.contains_key(*required) {
                    push_schema_issue(
                        issues,
                        &child_path(&child_path(path, "conditions"), required),
                        "A required condition is missing.",
                    );
                }
            }
        }
    }
    if state == Some("prohibited") && conditions.is_some() {
        push_schema_issue(
            issues,
            &child_path(path, "conditions"),
            "A prohibited rule must not contain conditions.",
        );
    }
}

fn validate_conditions(value: &Value, path: &str, issues: &mut Vec<Diagnostic>) {
    let Some(object) = check_object(
        value,
        path,
        &[
            "max_requests_per_second",
            "max_concurrent_requests",
            "required_user_agent_token",
            "test_accounts_only",
        ],
        &[],
        issues,
    ) else {
        return;
    };
    if object.is_empty() {
        push_schema_issue(
            issues,
            path,
            "Conditions must contain at least one defined member.",
        );
    }
    if let Some(rate) = object.get("max_requests_per_second") {
        let path = child_path(path, "max_requests_per_second");
        if let Some(rate) = check_number(rate, &path, issues) {
            if !number::is_positive(rate) {
                push_schema_issue(issues, &path, "The request rate limit must be positive.");
            }
        }
    }
    if let Some(concurrency) = object.get("max_concurrent_requests") {
        validate_positive_integer(
            concurrency,
            &child_path(path, "max_concurrent_requests"),
            issues,
        );
    }
    if let Some(token) = object.get("required_user_agent_token") {
        let path = child_path(path, "required_user_agent_token");
        if let Some(token) = check_string(token, &path, issues) {
            if token.is_empty() || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
                push_schema_issue(
                    issues,
                    &path,
                    "The User-Agent token must contain only visible ASCII characters.",
                );
            }
        }
    }
    if let Some(test_accounts_only) = object.get("test_accounts_only") {
        if test_accounts_only != &Value::Bool(true) {
            push_schema_issue(
                issues,
                &child_path(path, "test_accounts_only"),
                "test_accounts_only must be true.",
            );
        }
    }
}

fn validate_reporting(value: &Value, issues: &mut Vec<Diagnostic>) {
    let Some(object) = check_object(
        value,
        "/reporting",
        &["requested_fields", "proof_of_exploitation"],
        &["requested_fields", "proof_of_exploitation"],
        issues,
    ) else {
        return;
    };
    if let Some(fields) = object.get("requested_fields") {
        if let Some(fields) = check_array(fields, "/reporting/requested_fields", false, issues) {
            check_unique_strings(fields, "/reporting/requested_fields", issues);
            const REQUESTED_FIELDS: &[&str] = &[
                "affected_asset",
                "vulnerability_type",
                "description",
                "reproduction_steps",
                "impact",
                "environment",
                "evidence",
                "researcher_contact",
                "disclosure_preference",
            ];
            for (index, field) in fields.iter().enumerate() {
                check_enum(
                    field,
                    &index_path("/reporting/requested_fields", index),
                    REQUESTED_FIELDS,
                    issues,
                );
            }
        }
    }
    if let Some(proof) = object.get("proof_of_exploitation") {
        check_enum(
            proof,
            "/reporting/proof_of_exploitation",
            &["not_requested", "requested_if_safe", "prohibited"],
            issues,
        );
    }
}

fn validate_response_targets(value: &Value, issues: &mut Vec<Diagnostic>) {
    let path = "/response_targets";
    let fields = [
        "acknowledgement_days",
        "initial_assessment_days",
        "update_interval_days",
    ];
    let Some(object) = check_object(value, path, &fields, &[], issues) else {
        return;
    };
    if object.is_empty() {
        push_schema_issue(
            issues,
            path,
            "At least one response target must be present.",
        );
    }
    for field in fields {
        if let Some(days) = object.get(field) {
            validate_positive_integer(days, &child_path(path, field), issues);
        }
    }
}

fn validate_disclosure(value: &Value, issues: &mut Vec<Diagnostic>) {
    let path = "/disclosure";
    let Some(object) = check_object(
        value,
        path,
        &["approach", "default_days", "statement"],
        &["approach"],
        issues,
    ) else {
        return;
    };
    if let Some(approach) = object.get("approach") {
        check_enum(
            approach,
            "/disclosure/approach",
            &["coordinated", "case_by_case", "no_preference"],
            issues,
        );
    }
    if let Some(days) = object.get("default_days") {
        validate_positive_integer(days, "/disclosure/default_days", issues);
    }
    if let Some(statement) = object.get("statement") {
        check_string_bounds(statement, "/disclosure/statement", 0, Some(2000), issues);
    }
}

fn validate_critical_extensions(value: &Value, issues: &mut Vec<Diagnostic>) {
    if let Some(extensions) = check_array(value, "/critical_extensions", false, issues) {
        check_unique_strings(extensions, "/critical_extensions", issues);
        for (index, extension) in extensions.iter().enumerate() {
            validate_schema_uri(
                extension,
                &index_path("/critical_extensions", index),
                issues,
            );
        }
    }
}

fn validate_extensions(value: &Value, issues: &mut Vec<Diagnostic>) {
    let Some(object) = value.as_object() else {
        push_schema_issue(
            issues,
            "/extensions",
            "Expected an object of extension identifiers and values.",
        );
        return;
    };
    for identifier in object.keys() {
        let path = child_path("/extensions", identifier);
        if !is_schema_absolute_uri(identifier) {
            push_schema_issue(
                issues,
                &path,
                "An extension identifier must match the Version 1 URI schema.",
            );
        }
    }
}

fn validate_schema_uri(value: &Value, path: &str, issues: &mut Vec<Diagnostic>) {
    let Some(value) = check_string(value, path, issues) else {
        return;
    };
    if !is_schema_absolute_uri(value) {
        push_schema_issue(
            issues,
            path,
            "Expected a URI matching the Version 1 schema.",
        );
    }
}

fn validate_https_uri_schema(value: &Value, path: &str, issues: &mut Vec<Diagnostic>) {
    let Some(value) = check_string(value, path, issues) else {
        return;
    };
    if !uri::is_uri(value) || !value.starts_with("https://") {
        push_schema_issue(
            issues,
            path,
            "Expected a URI matching the Version 1 HTTPS schema pattern.",
        );
    }
}

fn validate_timestamp_semantics(value: &Value, issues: &mut Vec<Diagnostic>) {
    let updated = value
        .get("last_updated")
        .and_then(Value::as_str)
        .and_then(|value| Timestamp::parse(value).ok());
    let expires = value
        .get("expires")
        .and_then(Value::as_str)
        .and_then(|value| Timestamp::parse(value).ok());

    if let (Some(updated), Some(expires)) = (updated, expires) {
        if expires <= updated {
            push_semantic_issue(
                issues,
                "/expires",
                "Expiry must be strictly later than last_updated.",
            );
        }
    }
}

fn validate_uri_semantics(value: &Value, issues: &mut Vec<Diagnostic>) {
    if let Some(organization_uri) = value.pointer("/organization/uri").and_then(Value::as_str) {
        if !is_rfc3986_absolute_uri(organization_uri)
            || !uri::is_https_uri(organization_uri)
            || https_has_userinfo(organization_uri)
        {
            push_semantic_issue(
                issues,
                "/organization/uri",
                "An organization URI must be an absolute HTTPS URI without userinfo or fragment.",
            );
        }
    }

    if let Some(channels) = value.pointer("/contact/channels").and_then(Value::as_array) {
        for (index, channel) in channels.iter().enumerate() {
            let Some(channel) = channel.as_str() else {
                continue;
            };
            let is_https = uri_scheme(channel) == Some("https");
            if !is_rfc3986_absolute_uri(channel)
                || (is_https && (!uri::is_https_uri(channel) || https_has_userinfo(channel)))
            {
                push_semantic_issue(
                    issues,
                    &index_path("/contact/channels", index),
                    "A contact channel must be an absolute URI without a fragment; HTTPS channels also must not contain userinfo.",
                );
            }
        }
    }

    if let Some(encryption) = value
        .pointer("/contact/encryption")
        .and_then(Value::as_array)
    {
        for (index, identifier) in encryption.iter().enumerate() {
            let Some(identifier) = identifier.as_str() else {
                continue;
            };
            if !is_rfc3986_absolute_uri(identifier) {
                push_semantic_issue(
                    issues,
                    &index_path("/contact/encryption", index),
                    "An encryption URI must be absolute and must not contain a fragment.",
                );
            }
            // shortcut: reject explicit inline data URIs; extend if V1 defines other embedded-key URI forms.
            if uri_scheme(identifier).is_some_and(|scheme| scheme.eq_ignore_ascii_case("data")) {
                push_semantic_issue(
                    issues,
                    &index_path("/contact/encryption", index),
                    "Encryption entries must reference keys or instructions, not embed their content.",
                );
            }
        }
    }

    if let Some(languages) = value
        .pointer("/contact/preferred_languages")
        .and_then(Value::as_array)
    {
        for (index, language) in languages.iter().enumerate() {
            let Some(language) = language.as_str() else {
                continue;
            };
            let valid = LanguageTag::parse(language).is_ok_and(|tag| tag.validate().is_ok());
            if !valid {
                push_semantic_issue(
                    issues,
                    &index_path("/contact/preferred_languages", index),
                    "The value is not a valid BCP 47 language tag.",
                );
            }
        }
    }

    if let Some(products) = value
        .pointer("/reporting_scope/products")
        .and_then(Value::as_array)
    {
        for (product_index, product) in products.iter().enumerate() {
            if let Some(identifiers) = product.get("identifiers").and_then(Value::as_array) {
                for (index, identifier) in identifiers.iter().enumerate() {
                    if identifier
                        .as_str()
                        .is_some_and(|identifier| !is_rfc3986_absolute_uri(identifier))
                    {
                        push_semantic_issue(
                            issues,
                            &format!(
                                "/reporting_scope/products/{product_index}/identifiers/{index}"
                            ),
                            "A product identifier must be an absolute URI without a fragment.",
                        );
                    }
                }
            }
        }
    }

    if let Some(rules) = value.pointer("/testing/rules").and_then(Value::as_array) {
        for (index, rule) in rules.iter().enumerate() {
            let Some(activity) = rule.get("activity").and_then(Value::as_str) else {
                continue;
            };
            if !CORE_ACTIVITIES.contains(&activity) && !is_rfc3986_absolute_uri(activity) {
                push_semantic_issue(
                    issues,
                    &format!("/testing/rules/{index}/activity"),
                    "An extension activity must be an absolute URI without a fragment.",
                );
            }
        }
    }

    if let Some(critical) = value.get("critical_extensions").and_then(Value::as_array) {
        for (index, identifier) in critical.iter().enumerate() {
            if identifier
                .as_str()
                .is_some_and(|identifier| !is_rfc3986_absolute_uri(identifier))
            {
                push_semantic_issue(
                    issues,
                    &index_path("/critical_extensions", index),
                    "A critical extension identifier must be absolute and must not contain a fragment.",
                );
            }
        }
    }

    if let Some(extensions) = value.get("extensions").and_then(Value::as_object) {
        for identifier in extensions.keys() {
            if !is_rfc3986_absolute_uri(identifier) {
                push_semantic_issue(
                    issues,
                    &child_path("/extensions", identifier),
                    "An extension identifier must be absolute and must not contain a fragment.",
                );
            }
        }
    }
}

fn validate_scope_semantics(value: &Value, issues: &mut Vec<Diagnostic>) {
    if let Some(entries) = value
        .pointer("/reporting_scope/web")
        .and_then(Value::as_array)
    {
        for (index, entry) in entries.iter().enumerate() {
            let Some(host) = entry.get("host").and_then(Value::as_str) else {
                continue;
            };
            let path = format!("/reporting_scope/web/{index}/host");
            let Ok(normalized) = scope::normalize_host(host) else {
                push_semantic_issue(
                    issues,
                    &path,
                    "The scope host is not a valid DNS name or IP literal without a port.",
                );
                continue;
            };
            let is_ip = normalized.parse::<IpAddr>().is_ok();
            if is_ip && entry.get("include_subdomains").and_then(Value::as_bool) == Some(true) {
                push_semantic_issue(
                    issues,
                    &format!("/reporting_scope/web/{index}/include_subdomains"),
                    "IP entries must set include_subdomains to false.",
                );
            }
            if let Some(prefix) = entry.get("path_prefix").and_then(Value::as_str) {
                if scope::normalize_path(prefix).is_err() {
                    push_semantic_issue(
                        issues,
                        &format!("/reporting_scope/web/{index}/path_prefix"),
                        "The scope path prefix is invalid.",
                    );
                }
            }
        }
    }
}

fn validate_policy_relations(value: &Value, issues: &mut Vec<Diagnostic>) {
    let mut ids = HashSet::new();
    let mut web_ids = HashMap::new();

    if let Some(entries) = value
        .pointer("/reporting_scope/web")
        .and_then(Value::as_array)
    {
        for (index, entry) in entries.iter().enumerate() {
            if let Some(id) = entry.get("id").and_then(Value::as_str) {
                if !ids.insert(id.to_owned()) {
                    push_semantic_issue(
                        issues,
                        &format!("/reporting_scope/web/{index}/id"),
                        "Scope and rule IDs must be unique across the policy.",
                    );
                }
                web_ids.insert(
                    id.to_owned(),
                    entry.get("state").and_then(Value::as_str) == Some("in"),
                );
            }
        }
    }
    if let Some(entries) = value
        .pointer("/reporting_scope/products")
        .and_then(Value::as_array)
    {
        for (index, entry) in entries.iter().enumerate() {
            if let Some(id) = entry.get("id").and_then(Value::as_str) {
                if !ids.insert(id.to_owned()) {
                    push_semantic_issue(
                        issues,
                        &format!("/reporting_scope/products/{index}/id"),
                        "Scope and rule IDs must be unique across the policy.",
                    );
                }
            }
        }
    }

    let posture = value.pointer("/research/posture").and_then(Value::as_str);
    if let Some(rules) = value.pointer("/testing/rules").and_then(Value::as_array) {
        for (index, rule) in rules.iter().enumerate() {
            let path = format!("/testing/rules/{index}");
            if let Some(id) = rule.get("id").and_then(Value::as_str) {
                if !ids.insert(id.to_owned()) {
                    push_semantic_issue(
                        issues,
                        &child_path(&path, "id"),
                        "Scope and rule IDs must be unique across the policy.",
                    );
                }
            }
            if matches!(posture, Some("report_only" | "prohibited"))
                && rule.get("state").and_then(Value::as_str) == Some("permitted")
            {
                push_semantic_issue(
                    issues,
                    &child_path(&path, "state"),
                    "A report_only or prohibited policy must not contain a permitted rule.",
                );
            }
            if let Some(target_ids) = rule.get("target_ids").and_then(Value::as_array) {
                for (target_index, target_id) in
                    target_ids.iter().filter_map(Value::as_str).enumerate()
                {
                    if web_ids.get(target_id) != Some(&true) {
                        push_semantic_issue(
                            issues,
                            &format!("{path}/target_ids/{target_index}"),
                            "A target reference must name an existing in-state web scope entry.",
                        );
                    }
                }
            }
        }
    }

    if let Some(critical) = value.get("critical_extensions").and_then(Value::as_array) {
        let extensions = value.get("extensions").and_then(Value::as_object);
        for (index, identifier) in critical.iter().filter_map(Value::as_str).enumerate() {
            if !extensions.is_some_and(|extensions| extensions.contains_key(identifier)) {
                push_semantic_issue(
                    issues,
                    &index_path("/critical_extensions", index),
                    "Every critical extension identifier must name an extension member.",
                );
            }
        }
    }
}

fn check_object<'a>(
    value: &'a Value,
    path: &str,
    allowed: &[&str],
    required: &[&str],
    issues: &mut Vec<Diagnostic>,
) -> Option<&'a Map<String, Value>> {
    let Some(object) = value.as_object() else {
        push_schema_issue(issues, path, "Expected an object.");
        return None;
    };
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            push_schema_issue(
                issues,
                &child_path(path, key),
                "Unknown core object member.",
            );
        }
    }
    for key in required {
        if !object.contains_key(*key) {
            push_schema_issue(
                issues,
                &child_path(path, key),
                "Required object member is missing.",
            );
        }
    }
    Some(object)
}

fn check_array<'a>(
    value: &'a Value,
    path: &str,
    nonempty: bool,
    issues: &mut Vec<Diagnostic>,
) -> Option<&'a [Value]> {
    let Some(array) = value.as_array() else {
        push_schema_issue(issues, path, "Expected an array.");
        return None;
    };
    if nonempty && array.is_empty() {
        push_schema_issue(issues, path, "The array must not be empty.");
    }
    Some(array)
}

fn check_string<'a>(value: &'a Value, path: &str, issues: &mut Vec<Diagnostic>) -> Option<&'a str> {
    let Some(value) = value.as_str() else {
        push_schema_issue(issues, path, "Expected a string.");
        return None;
    };
    Some(value)
}

fn check_string_bounds<'a>(
    value: &'a Value,
    path: &str,
    minimum: usize,
    maximum: Option<usize>,
    issues: &mut Vec<Diagnostic>,
) -> Option<&'a str> {
    let value = check_string(value, path, issues)?;
    let length = value.chars().count();
    if length < minimum || maximum.is_some_and(|maximum| length > maximum) {
        push_schema_issue(
            issues,
            path,
            "The string length is outside the permitted range.",
        );
    }
    Some(value)
}

fn check_enum(value: &Value, path: &str, allowed: &[&str], issues: &mut Vec<Diagnostic>) {
    let Some(value) = check_string(value, path, issues) else {
        return;
    };
    if !allowed.contains(&value) {
        push_schema_issue(issues, path, "The string is not one of the defined values.");
    }
}

fn check_number<'a>(
    value: &'a Value,
    path: &str,
    issues: &mut Vec<Diagnostic>,
) -> Option<&'a Number> {
    let Value::Number(value) = value else {
        push_schema_issue(issues, path, "Expected a JSON number.");
        return None;
    };
    Some(value)
}

fn check_bool(value: &Value, path: &str, issues: &mut Vec<Diagnostic>) {
    if !value.is_boolean() {
        push_schema_issue(issues, path, "Expected a boolean.");
    }
}

fn check_id(value: &Value, path: &str, issues: &mut Vec<Diagnostic>) {
    let Some(value) = check_string(value, path, issues) else {
        return;
    };
    let bytes = value.as_bytes();
    let valid = (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !valid {
        push_schema_issue(
            issues,
            path,
            "The identifier does not match the Version 1 ID syntax.",
        );
    }
}

fn validate_integer_range(
    value: &Value,
    path: &str,
    minimum: u64,
    maximum: u64,
    issues: &mut Vec<Diagnostic>,
) {
    let Some(value) = check_number(value, path, issues) else {
        return;
    };
    if !number::is_integer(value)
        || number::compare(value, &Number::from(minimum)) == Ordering::Less
        || number::compare(value, &Number::from(maximum)) == Ordering::Greater
    {
        push_schema_issue(
            issues,
            path,
            "Expected an integer within the permitted range.",
        );
    }
}

fn validate_positive_integer(value: &Value, path: &str, issues: &mut Vec<Diagnostic>) {
    let Some(value) = check_number(value, path, issues) else {
        return;
    };
    if !number::is_integer(value) || number::compare(value, &Number::from(1)) == Ordering::Less {
        push_schema_issue(issues, path, "Expected a positive integer.");
    }
}

fn check_unique_strings(values: &[Value], path: &str, issues: &mut Vec<Diagnostic>) {
    let mut seen = HashSet::new();
    for (index, value) in values.iter().enumerate() {
        if let Some(value) = value.as_str() {
            if !seen.insert(value) {
                push_schema_issue(
                    issues,
                    &index_path(path, index),
                    "Array items must be unique.",
                );
            }
        }
    }
}

fn check_unique_numbers(values: &[Value], path: &str, issues: &mut Vec<Diagnostic>) {
    let mut numbers = values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| value.as_number().map(|number| (index, number)))
        .collect::<Vec<_>>();
    numbers.sort_by(|(_, left), (_, right)| number::compare(left, right));
    for pair in numbers.windows(2) {
        if number::compare(pair[0].1, pair[1].1) == Ordering::Equal {
            push_schema_issue(
                issues,
                &index_path(path, pair[1].0),
                "Array items must be unique.",
            );
        }
    }
}

fn valid_path_prefix_syntax(value: &str) -> bool {
    if !value.starts_with('/') || value.contains(['?', '#']) {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn is_schema_absolute_uri(value: &str) -> bool {
    uri::is_uri(value)
        && uri_scheme(value).is_some_and(|scheme| {
            let mut bytes = scheme.bytes();
            bytes
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic())
                && bytes
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-'))
        })
}

fn is_rfc3986_absolute_uri(value: &str) -> bool {
    is_schema_absolute_uri(value) && !value.contains('#')
}

fn uri_scheme(value: &str) -> Option<&str> {
    let colon = value.find(':')?;
    Some(&value[..colon])
}

fn https_has_userinfo(value: &str) -> bool {
    if !uri_scheme(value).is_some_and(|scheme| scheme.eq_ignore_ascii_case("https")) {
        return false;
    }
    let Some(scheme_end) = value.find(':') else {
        return false;
    };
    let Some(authority_and_path) = value[scheme_end + 1..].strip_prefix("//") else {
        return false;
    };
    let authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    authority.contains('@')
}

fn drop_value_iteratively(value: Value) {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(array) => pending.extend(array),
            Value::Object(object) => {
                pending.extend(object.into_iter().map(|(key, value)| {
                    drop(key);
                    value
                }));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
}

fn push_schema_issue(issues: &mut Vec<Diagnostic>, path: &str, message: &str) {
    issues.push(diagnostic("policy_schema_invalid", path, message));
}

fn push_semantic_issue(issues: &mut Vec<Diagnostic>, path: &str, message: &str) {
    issues.push(diagnostic("policy_semantic_invalid", path, message));
}

fn diagnostic(code: &str, path: &str, message: &str) -> Diagnostic {
    Diagnostic {
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.to_owned(),
    }
}

fn invalid_error(diagnostics: Vec<Diagnostic>) -> PolicyError {
    PolicyError {
        kind: PolicyErrorKind::Invalid,
        diagnostics,
    }
}

fn child_path(path: &str, member: &str) -> String {
    format!("{path}/{}", escape_pointer(member))
}

fn index_path(path: &str, index: usize) -> String {
    format!("{path}/{index}")
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use crate::timestamp::Timestamp;
    use crate::types::PolicyErrorKind;

    use super::{semantic_issues, validate_structure, Policy};

    fn minimal_policy() -> Value {
        json!({
            "cvd_policy": 1,
            "last_updated": "2000-01-01T00:00:00Z",
            "expires": "2000-01-02T00:00:00Z",
            "organization": {"name": "Example"},
            "contact": {"channels": ["mailto:security@example.com"]},
            "research": {"posture": "report_only"},
            "reporting_scope": {"web": [{
                "id": "main",
                "state": "in",
                "host": "example.com",
                "schemes": ["https"],
                "path_prefix": "/",
                "include_subdomains": false
            }]},
            "reporting": {
                "requested_fields": [],
                "proof_of_exploitation": "not_requested"
            }
        })
    }

    #[test]
    fn static_validation_does_not_consult_a_clock() {
        assert!(Policy::from_value(minimal_policy()).is_ok());
    }

    #[test]
    fn validate_at_reports_expiry_without_needing_testing_activity() {
        let policy = Policy::from_value(minimal_policy()).unwrap();
        let now = Timestamp::parse("2000-01-02T00:00:00Z").unwrap();

        let error = policy.validate_at(&now).unwrap_err();

        assert_eq!(error.kind, PolicyErrorKind::Invalid);
        assert_eq!(error.diagnostics[0].code, "policy_expired");
        assert_eq!(error.diagnostics[0].path, "/expires");
    }

    #[test]
    fn validate_at_accepts_expiry_after_the_supplied_instant() {
        let policy = Policy::from_value(minimal_policy()).unwrap();
        let now = Timestamp::parse("2000-01-01T00:00:00Z").unwrap();

        assert!(policy.validate_at(&now).is_ok());
    }

    #[test]
    fn rejects_unknown_core_members() {
        let mut value = minimal_policy();
        value["unexpected"] = json!(true);

        let error = Policy::from_value(value).unwrap_err();

        assert_eq!(error.kind, PolicyErrorKind::Invalid);
        assert!(error
            .diagnostics
            .iter()
            .any(|issue| issue.path == "/unexpected"));
    }

    #[test]
    fn required_core_fields_are_never_defaulted() {
        for member in [
            "cvd_policy",
            "last_updated",
            "expires",
            "organization",
            "contact",
            "research",
            "reporting_scope",
            "reporting",
        ] {
            let mut value = minimal_policy();
            assert!(value.as_object_mut().unwrap().remove(member).is_some());

            let error = Policy::from_value(value).unwrap_err();

            assert_eq!(error.kind, PolicyErrorKind::Invalid, "member: {member}");
            assert!(
                error.diagnostics.iter().any(|issue| {
                    issue.code == "policy_schema_invalid" && issue.path == format!("/{member}")
                }),
                "missing required-member diagnostic for {member}: {:?}",
                error.diagnostics
            );
        }
    }

    #[test]
    fn organization_name_boundaries_count_unicode_characters() {
        let mut missing = minimal_policy();
        missing["organization"]
            .as_object_mut()
            .unwrap()
            .remove("name");
        let mut empty = minimal_policy();
        empty["organization"]["name"] = json!("");
        let mut over_limit = minimal_policy();
        over_limit["organization"]["name"] = json!("🧪".repeat(201));

        for (case, value) in [
            ("missing", missing),
            ("empty", empty),
            ("201 Unicode characters", over_limit),
        ] {
            let error = Policy::from_value(value).unwrap_err();

            assert_eq!(error.kind, PolicyErrorKind::Invalid, "case: {case}");
            assert!(
                error.diagnostics.iter().any(|issue| {
                    issue.code == "policy_schema_invalid" && issue.path == "/organization/name"
                }),
                "missing name diagnostic for {case}: {:?}",
                error.diagnostics
            );
        }

        for (case, name) in [
            ("one character", "x".to_owned()),
            ("200 Unicode characters", "🧪".repeat(200)),
        ] {
            let mut value = minimal_policy();
            value["organization"]["name"] = json!(name);

            assert!(Policy::from_value(value).is_ok(), "case: {case}");
        }
    }

    #[test]
    fn preserves_arbitrary_extension_values() {
        let mut value = minimal_policy();
        let extension = json!({"unrecognized": [true, null, {"text": "kept exactly"}]});
        value["extensions"] = json!({"https://example.com/extensions/example": extension});

        let policy = Policy::from_value(value).unwrap();

        assert_eq!(
            policy.value()["extensions"]["https://example.com/extensions/example"],
            json!({"unrecognized": [true, null, {"text": "kept exactly"}]})
        );
    }

    #[test]
    fn uri_schema_and_semantic_diagnostics_match_their_layers() {
        let mut organization_userinfo = minimal_policy();
        organization_userinfo["organization"]["uri"] = json!("https://user@example.com/");
        assert!(validate_structure(&organization_userinfo).is_empty());
        assert!(semantic_issues(&organization_userinfo)
            .iter()
            .any(|issue| issue.path == "/organization/uri"));

        let mut contact_userinfo = minimal_policy();
        contact_userinfo["contact"]["channels"] =
            json!(["https://user@example.com/security/contact"]);
        assert!(validate_structure(&contact_userinfo).is_empty());
        assert!(semantic_issues(&contact_userinfo)
            .iter()
            .any(|issue| issue.path == "/contact/channels/0"));

        let mut organization_fragment = minimal_policy();
        organization_fragment["organization"]["uri"] = json!("https://example.com/org#fragment");
        assert!(validate_structure(&organization_fragment).is_empty());
        assert!(semantic_issues(&organization_fragment)
            .iter()
            .any(|issue| issue.path == "/organization/uri"));
    }

    #[test]
    fn uri_and_timestamp_schema_failures_are_structural() {
        let mut invalid_timestamp = minimal_policy();
        invalid_timestamp["last_updated"] = json!("2026-99-99T99:99:99Z");
        assert!(validate_structure(&invalid_timestamp)
            .iter()
            .any(|issue| issue.path == "/last_updated"));
        assert!(!semantic_issues(&invalid_timestamp)
            .iter()
            .any(|issue| issue.path == "/last_updated"));

        let mut uppercase_https = minimal_policy();
        uppercase_https["organization"]["uri"] = json!("HTTPS://example.com/");
        assert!(validate_structure(&uppercase_https)
            .iter()
            .any(|issue| issue.path == "/organization/uri"));

        let mut contact_fragment = minimal_policy();
        contact_fragment["contact"]["channels"] =
            json!(["https://example.com/security/contact#fragment"]);
        assert!(validate_structure(&contact_fragment)
            .iter()
            .any(|issue| issue.path == "/contact/channels/0"));
    }

    #[test]
    fn semantic_uri_validation_requires_an_absolute_uri() {
        let mut value = minimal_policy();
        value["contact"]["channels"] = json!(["/relative"]);

        assert!(semantic_issues(&value)
            .iter()
            .any(|issue| issue.path == "/contact/channels/0"));
    }

    #[test]
    fn rejects_fragments_in_every_absolute_policy_uri_field() {
        let mut value = minimal_policy();
        value["organization"]["uri"] = json!("https://example.com/org#fragment");
        value["contact"]["channels"] = json!(["mailto:security@example.com#fragment"]);
        value["contact"]["encryption"] = json!(["https://example.com/key#fragment"]);
        value["reporting_scope"]["products"] = json!([{
            "id": "product",
            "state": "in",
            "name": "Example product",
            "identifiers": ["pkg:example/product#fragment"]
        }]);
        value["testing"] = json!({
            "rules": [{
                "id": "rule",
                "activity": "https://example.com/activity#fragment",
                "state": "prohibited"
            }]
        });
        value["critical_extensions"] = json!(["https://example.com/extension#fragment"]);
        value["extensions"] = json!({
            "https://example.com/extension#fragment": {"arbitrary": true}
        });

        let error = Policy::from_value(value).unwrap_err();
        let paths = error
            .diagnostics
            .iter()
            .map(|issue| issue.path.as_str())
            .collect::<Vec<_>>();

        for path in [
            "/organization/uri",
            "/contact/channels/0",
            "/contact/encryption/0",
            "/reporting_scope/products/0/identifiers/0",
            "/testing/rules/0/activity",
            "/critical_extensions/0",
            "/extensions/https:~1~1example.com~1extension#fragment",
        ] {
            assert!(
                paths.contains(&path),
                "missing fragment rejection at {path}: {paths:?}"
            );
        }
    }

    #[test]
    fn mailto_user_at_host_is_not_treated_as_authority_userinfo() {
        let mut value = minimal_policy();
        value["contact"]["channels"] = json!(["mailto:user@host.example"]);

        assert!(Policy::from_value(value).is_ok());
    }

    #[test]
    fn rejects_https_authority_userinfo_and_bad_scope_relationships() {
        let mut value = minimal_policy();
        value["organization"]["uri"] = json!("https://user@example.com/");
        value["testing"] = json!({
            "rules": [{
                "id": "rule",
                "activity": "manual_testing",
                "state": "permitted",
                "target_ids": ["missing"]
            }]
        });

        let error = Policy::from_value(value).unwrap_err();

        assert_eq!(error.kind, PolicyErrorKind::Invalid);
        assert!(error
            .diagnostics
            .iter()
            .any(|issue| issue.path == "/organization/uri"));
        assert!(error
            .diagnostics
            .iter()
            .any(|issue| issue.path == "/testing/rules/0/target_ids/0"));
        assert!(error.diagnostics.iter().any(|issue| {
            issue.code == "policy_semantic_invalid" && issue.path == "/testing/rules/0/state"
        }));
    }

    #[test]
    fn permitted_manual_testing_does_not_require_conditions() {
        let mut value = minimal_policy();
        value["research"]["posture"] = json!("limited");
        value["testing"] = json!({
            "rules": [{
                "id": "manual",
                "activity": "manual_testing",
                "state": "permitted",
                "target_ids": ["main"]
            }]
        });

        assert!(Policy::from_value(value).is_ok());
    }

    #[test]
    fn permitted_automated_scanning_requires_structural_conditions() {
        let mut value = minimal_policy();
        value["research"]["posture"] = json!("limited");
        value["testing"] = json!({
            "rules": [{
                "id": "scanner",
                "activity": "automated_scanning",
                "state": "permitted",
                "target_ids": ["main"]
            }]
        });

        let issues = validate_structure(&value);

        assert!(issues.iter().any(|issue| {
            issue.code == "policy_schema_invalid" && issue.path == "/testing/rules/0/conditions"
        }));
    }

    #[test]
    fn automated_scanning_condition_limits_must_be_positive() {
        let mut value = minimal_policy();
        value["research"]["posture"] = json!("limited");
        value["testing"] = json!({
            "rules": [{
                "id": "scanner",
                "activity": "automated_scanning",
                "state": "permitted",
                "target_ids": ["main"],
                "conditions": {
                    "max_requests_per_second": 0,
                    "max_concurrent_requests": 0
                }
            }]
        });

        let issues = validate_structure(&value);

        assert!(issues.iter().any(|issue| {
            issue.code == "policy_schema_invalid"
                && issue.path == "/testing/rules/0/conditions/max_requests_per_second"
        }));
        assert!(issues.iter().any(|issue| {
            issue.code == "policy_schema_invalid"
                && issue.path == "/testing/rules/0/conditions/max_concurrent_requests"
        }));
    }

    #[test]
    fn dispatches_unknown_integer_version_as_unsupported() {
        let mut value = minimal_policy();
        value["cvd_policy"] = json!(2);

        assert_eq!(
            Policy::from_value(value).unwrap_err().kind,
            PolicyErrorKind::UnsupportedVersion
        );
    }

    #[test]
    fn accepts_unbounded_positive_integer_fields_without_u64_conversion() {
        let mut value = minimal_policy();
        let days: Value = serde_json::from_str("18446744073709551616").unwrap();
        value["response_targets"] = json!({"acknowledgement_days": days});

        assert!(Policy::from_value(value).is_ok());
    }

    #[test]
    fn serialization_round_trip_preserves_escaped_extension_key_and_exact_number() {
        let raw = br#"{
            "cvd_policy": 1,
            "last_updated": "2000-01-01T00:00:00Z",
            "expires": "2000-01-02T00:00:00Z",
            "organization": {"name": "Example"},
            "contact": {"channels": ["mailto:security@example.com"]},
            "research": {"posture": "report_only"},
            "reporting_scope": {"web": [{
                "id": "main", "state": "in", "host": "example.com",
                "schemes": ["https"], "path_prefix": "/", "include_subdomains": false
            }]},
            "reporting": {"requested_fields": [], "proof_of_exploitation": "not_requested"},
            "extensions": {
                "https://example.com/extensions\u002fescaped": {
                    "integer": 1234567890123456789012345678901234567890
                }
            }
        }"#;
        let policy = Policy::parse(raw).unwrap();
        let json = policy.to_json().unwrap();
        let restored = Policy::parse(json.as_bytes()).unwrap();

        assert_eq!(policy.value(), restored.value());
        assert!(json.contains("1234567890123456789012345678901234567890"));
        assert!(!json.contains("$serde_json::private::Number"));
        assert!(restored
            .value()
            .pointer("/extensions/https:~1~1example.com~1extensions~1escaped/integer")
            .is_some());
    }

    #[test]
    fn drops_values_over_default_depth_limit_without_recursive_destruction() {
        for depth in [512, 4096] {
            let nested = (0..depth).fold(Value::Null, |value, _| Value::Array(vec![value]));
            let error = Policy::from_value(nested).unwrap_err();
            assert_eq!(error.kind, PolicyErrorKind::ResourceLimit);
        }
    }
}
