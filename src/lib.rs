#![forbid(unsafe_code)]

//! A deterministic Rust library for interpreting CVD Policy Version 1 documents.
//!
//! This crate follows the experimental Version 1 candidate in the normative English
//! specification. It performs no network or filesystem I/O and does not read the
//! system clock. Callers supply evaluation time explicitly through [`EvaluationContext`].
//!
//! Version 1 is a pre-standard candidate, not an RFC or an IETF consensus document.
//! Package versioning is independent of the policy document's `cvd_policy` format version.
//!
//! [`EvaluationContext`]: crate::EvaluationContext

pub mod authority;
pub mod csaf;
pub mod evaluate;
pub(crate) mod number;
pub mod parse;
pub mod policy;
pub mod publish;
pub mod retrieval;
pub mod scope;
pub mod timestamp;
pub mod types;
pub(crate) mod uri;

#[doc(inline)]
pub use authority::assess_security_txt;
#[doc(inline)]
pub use csaf::{
    assess_csaf, assess_csaf_for_host, CsafAssessment, CsafChannel, CsafHostAssessment, CsafState,
    CSAF_EXTENSION_ID, CSAF_SPECIFICATION,
};
#[doc(inline)]
pub use evaluate::evaluate_policy;
#[doc(inline)]
pub use parse::{parse_json, ParseLimits};
#[doc(inline)]
pub use policy::Policy;
#[doc(inline)]
pub use publish::{generate_policy, merge_security_txt, security_txt, SecurityTxtOptions};
#[doc(inline)]
pub use retrieval::policy_retrieval_issues;
#[doc(inline)]
pub use scope::NormalizedTarget;
#[doc(inline)]
pub use timestamp::Timestamp;
#[doc(inline)]
pub use types::{
    AuthorityAssessment, AuthorityEvidence, Diagnostic, EvaluationContext, EvaluationPlan,
    EvaluationQuery, InputError, PermissionResult, PermissionStatus, PolicyError, PolicyErrorKind,
    PolicyRetrieval, SecurityTxtRetrieval,
};
