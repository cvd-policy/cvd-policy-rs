//! Shared data types for deterministic policy validation and evaluation.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use serde_json::Number;

use crate::timestamp::Timestamp;

/// A machine-readable validation or evaluation diagnostic.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Stable implementation-specific diagnostic code.
    pub code: String,
    /// Location associated with the diagnostic, when available.
    pub path: String,
    /// Human-readable explanation of the diagnostic.
    pub message: String,
}

/// A policy-processing error with machine-readable diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyError {
    /// Classification of the policy-processing failure.
    pub kind: PolicyErrorKind,
    /// Details describing the failure.
    pub diagnostics: Vec<Diagnostic>,
}

impl PolicyError {
    pub(crate) fn new(kind: PolicyErrorKind, diagnostics: Vec<Diagnostic>) -> Self {
        Self { kind, diagnostics }
    }
}

impl Display for PolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            PolicyErrorKind::Invalid => "invalid policy",
            PolicyErrorKind::UnsupportedVersion => "unsupported policy version",
            PolicyErrorKind::ResourceLimit => "policy resource limit exceeded",
        };
        write!(
            formatter,
            "{kind} ({} diagnostic(s))",
            self.diagnostics.len()
        )
    }
}

impl Error for PolicyError {}

/// The category of a policy-processing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyErrorKind {
    /// The policy is malformed or semantically invalid.
    Invalid,
    /// The policy uses an unsupported format version.
    UnsupportedVersion,
    /// Processing exceeded a configured resource limit.
    ResourceLimit,
}

/// Invalid caller-supplied evaluation input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputError {
    /// Details describing the invalid input.
    pub diagnostics: Vec<Diagnostic>,
}

impl Display for InputError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid input ({} diagnostic(s))",
            self.diagnostics.len()
        )
    }
}

impl Error for InputError {}

/// Explicit environmental inputs used for deterministic evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationContext {
    /// The instant against which policy and retrieval expiry are checked.
    pub now: Timestamp,
    /// Whether the caller enabled compatibility with `application/json` retrievals.
    pub allow_application_json: bool,
}

impl EvaluationContext {
    /// Creates an evaluation context using the supplied instant.
    ///
    /// Compatibility with `application/json` is disabled by default.
    ///
    /// # Examples
    ///
    /// ```
    /// use cvd_policy::{EvaluationContext, Timestamp};
    ///
    /// let now = Timestamp::parse("2026-01-01T00:00:00Z")?;
    /// let context = EvaluationContext::new(now);
    /// assert!(!context.allow_application_json);
    /// # Ok::<(), cvd_policy::InputError>(())
    /// ```
    pub fn new(now: Timestamp) -> Self {
        Self {
            now,
            allow_application_json: false,
        }
    }
}

/// The planned actions checked against published conditions.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluationPlan {
    /// Planned request rate, preserved as an exact JSON number.
    pub requests_per_second: Option<Number>,
    /// Planned concurrency, preserved as an exact JSON number.
    pub concurrent_requests: Option<Number>,
    /// Planned User-Agent value.
    pub user_agent: Option<String>,
    /// Whether the plan uses only test accounts.
    pub uses_only_test_accounts: Option<bool>,
}

/// The activity, target, plan, and extensions to evaluate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluationQuery {
    /// Activity identifier to evaluate.
    pub activity: String,
    /// Absolute HTTP(S) target URL.
    pub target: String,
    /// Optional planned actions checked against policy conditions.
    pub plan: Option<EvaluationPlan>,
    /// Extension identifiers understood by the caller.
    #[serde(default)]
    pub understood_extensions: Vec<String>,
    /// Optional evidence describing policy retrieval.
    pub policy_retrieval: Option<PolicyRetrieval>,
}

/// One of the seven normative Version 1 evaluation outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionStatus {
    /// A matching publisher-stated permission has satisfied its conditions.
    PublisherStatedPermitted,
    /// A matching publisher-stated prohibition applies.
    PublisherStatedProhibited,
    /// The target is not covered by a matching reporting scope and rule.
    NotCovered,
    /// Valid authority evidence for the discovery host is unavailable.
    AuthorityNotEstablished,
    /// No matching permitted rule has all required conditions satisfied.
    ConditionsNotSatisfied,
    /// The policy is invalid or expired.
    InvalidPolicy,
    /// The policy version or required behavior is unsupported.
    UnsupportedPolicy,
}

impl Display for PermissionStatus {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let status = match self {
            Self::PublisherStatedPermitted => "publisher-stated-permitted",
            Self::PublisherStatedProhibited => "publisher-stated-prohibited",
            Self::NotCovered => "not-covered",
            Self::AuthorityNotEstablished => "authority-not-established",
            Self::ConditionsNotSatisfied => "conditions-not-satisfied",
            Self::InvalidPolicy => "invalid-policy",
            Self::UnsupportedPolicy => "unsupported-policy",
        };
        formatter.write_str(status)
    }
}

/// The status and matching evidence from policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionResult {
    /// Normative outcome of policy evaluation.
    pub status: PermissionStatus,
    /// IDs of matching testing rules.
    pub matched_rule_ids: Vec<String>,
    /// IDs of matching web targets.
    pub matched_target_ids: Vec<String>,
    /// Diagnostics reported while evaluating the policy.
    pub diagnostics: Vec<Diagnostic>,
}

/// Caller-supplied retrieval evidence for a `security.txt` representation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityTxtRetrieval {
    /// URI initially requested by the caller.
    pub requested_uri: String,
    /// URI from which the representation was retrieved.
    pub final_uri: String,
    /// URIs visited during redirects, in order.
    pub redirect_chain: Vec<String>,
    /// Time at which the representation was retrieved.
    pub retrieved_at: Timestamp,
}

/// Caller-supplied HTTP retrieval evidence for a policy representation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRetrieval {
    /// URI initially requested by the caller.
    pub requested_uri: String,
    /// URI from which the representation was retrieved.
    pub final_uri: String,
    /// URIs visited during redirects, in order.
    pub redirect_chain: Vec<String>,
    /// HTTP status code returned for the final representation.
    pub status_code: u16,
    /// Media type reported for the final representation.
    pub media_type: String,
}

/// Authority evidence accepted from successful `security.txt` assessment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityEvidence {
    pub(crate) discovery_host: String,
    pub(crate) security_txt_uri: String,
    pub(crate) cvd_policy_uri: String,
    pub(crate) security_txt_expires: Timestamp,
}

impl AuthorityEvidence {
    /// Returns the originally requested discovery host.
    pub fn discovery_host(&self) -> &str {
        &self.discovery_host
    }

    /// Returns the originally requested `security.txt` URI.
    pub fn security_txt_uri(&self) -> &str {
        &self.security_txt_uri
    }

    /// Returns the policy URI advertised by `security.txt`.
    pub fn cvd_policy_uri(&self) -> &str {
        &self.cvd_policy_uri
    }

    /// Returns the expiration instant advertised by `security.txt`.
    pub fn security_txt_expires(&self) -> &Timestamp {
        &self.security_txt_expires
    }
}

/// The result of assessing a retrieved `security.txt` representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityAssessment {
    /// Evidence present only when authority was successfully established.
    pub evidence: Option<AuthorityEvidence>,
    /// Diagnostics emitted during assessment.
    pub diagnostics: Vec<Diagnostic>,
    /// Whether the retrieved representation contains a recognized signature.
    pub signed: bool,
    /// Human-readable policy URIs preserved from the representation.
    pub human_policy_uris: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::PermissionStatus;

    #[test]
    fn permission_status_uses_exact_wire_values() {
        let cases = [
            (
                PermissionStatus::PublisherStatedPermitted,
                "publisher-stated-permitted",
            ),
            (
                PermissionStatus::PublisherStatedProhibited,
                "publisher-stated-prohibited",
            ),
            (PermissionStatus::NotCovered, "not-covered"),
            (
                PermissionStatus::AuthorityNotEstablished,
                "authority-not-established",
            ),
            (
                PermissionStatus::ConditionsNotSatisfied,
                "conditions-not-satisfied",
            ),
            (PermissionStatus::InvalidPolicy, "invalid-policy"),
            (PermissionStatus::UnsupportedPolicy, "unsupported-policy"),
        ];

        for (status, wire_value) in cases {
            assert_eq!(status.to_string(), wire_value);
            assert_eq!(
                serde_json::to_string(&status).unwrap(),
                format!("\"{wire_value}\"")
            );
            assert_eq!(
                serde_json::from_str::<PermissionStatus>(&format!("\"{wire_value}\"")).unwrap(),
                status
            );
        }
    }
}
