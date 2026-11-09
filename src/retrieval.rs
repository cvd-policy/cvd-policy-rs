//! Validates supplied HTTPS policy-retrieval evidence without performing network I/O.

use std::collections::HashSet;

use url::Url;

use crate::types::{AuthorityEvidence, Diagnostic, EvaluationContext, PolicyRetrieval};
use crate::uri;

const MAX_REDIRECT_HOPS: usize = 5;

/// Reports whether a complete policy representation is bound to the advertised Policy URI.
///
/// Only status 200 and the Version 1 media type are accepted. The compatibility media type is
/// accepted only when enabled in `context`; this function never performs a request.
pub fn policy_retrieval_issues(
    authority: &AuthorityEvidence,
    retrieval: Option<&PolicyRetrieval>,
    context: &EvaluationContext,
) -> Vec<Diagnostic> {
    let Some(retrieval) = retrieval else {
        return invalid("policy retrieval evidence is missing");
    };
    if retrieval.status_code != 200 {
        return invalid("policy retrieval did not return HTTP 200");
    }

    let media_type = retrieval
        .media_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media_type != "application/cvd-policy+json"
        && !(context.allow_application_json && media_type == "application/json")
    {
        return invalid("policy retrieval media type is not accepted");
    }

    if retrieval.requested_uri != authority.cvd_policy_uri
        || !valid_https_uri(&retrieval.requested_uri)
        || !valid_https_uri(&retrieval.final_uri)
        || retrieval.redirect_chain.len() > MAX_REDIRECT_HOPS
        || retrieval
            .redirect_chain
            .iter()
            .any(|uri| !valid_https_uri(uri))
        || !redirect_chain_is_consistent(retrieval)
    {
        return invalid("policy retrieval is not bound to its advertised HTTPS URI");
    }
    Vec::new()
}

fn valid_https_uri(value: &str) -> bool {
    if !uri::is_https_uri(value) {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && raw_authority(value).is_some_and(|authority| !authority.contains('@'))
}

fn redirect_chain_is_consistent(retrieval: &PolicyRetrieval) -> bool {
    if retrieval
        .redirect_chain
        .last()
        .map_or(retrieval.requested_uri.as_str(), String::as_str)
        != retrieval.final_uri
    {
        return false;
    }
    let mut visited = HashSet::with_capacity(retrieval.redirect_chain.len() + 1);
    visited.insert(retrieval.requested_uri.as_str());
    retrieval
        .redirect_chain
        .iter()
        .all(|uri| visited.insert(uri.as_str()))
}

fn raw_authority(value: &str) -> Option<&str> {
    let colon = value.find(':')?;
    let rest = &value[colon + 1..];
    let prefix_len = rest.bytes().take_while(|byte| *byte == b'/').count();
    if prefix_len < 2 {
        return None;
    }
    let authority = &rest[prefix_len..];
    let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    Some(&authority[..end])
}

fn invalid(message: &str) -> Vec<Diagnostic> {
    vec![Diagnostic {
        code: "policy_retrieval_invalid".to_owned(),
        path: "/policyRetrieval".to_owned(),
        message: message.to_owned(),
    }]
}

#[cfg(test)]
mod tests {
    use crate::authority::assess_security_txt;
    use crate::types::{EvaluationContext, PolicyRetrieval, SecurityTxtRetrieval};

    use super::policy_retrieval_issues;

    fn authority() -> crate::types::AuthorityEvidence {
        let assessment = assess_security_txt(
            b"Contact: mailto:security@example.com\nCVD-Policy: https://example.com/policy.json\nExpires: 2027-02-28T08:00:00Z\n",
            &SecurityTxtRetrieval {
                requested_uri: "https://example.com/.well-known/security.txt".to_owned(),
                final_uri: "https://example.com/.well-known/security.txt".to_owned(),
                redirect_chain: Vec::new(),
                retrieved_at: crate::timestamp::Timestamp::parse("2026-08-29T10:00:00Z")
                    .unwrap(),
            },
        );
        assessment.evidence.unwrap()
    }

    fn context() -> EvaluationContext {
        EvaluationContext::new(crate::timestamp::Timestamp::parse("2026-08-29T10:00:00Z").unwrap())
    }

    fn retrieval() -> PolicyRetrieval {
        PolicyRetrieval {
            requested_uri: "https://example.com/policy.json".to_owned(),
            final_uri: "https://example.com/policy.json".to_owned(),
            redirect_chain: Vec::new(),
            status_code: 200,
            media_type: "application/cvd-policy+json".to_owned(),
        }
    }

    #[test]
    fn accepts_the_advertised_uri_and_all_https_redirect_chain() {
        let mut retrieval = retrieval();
        retrieval.final_uri = "https://cdn.example/policy.json".to_owned();
        retrieval.redirect_chain.push(retrieval.final_uri.clone());
        assert!(policy_retrieval_issues(&authority(), Some(&retrieval), &context()).is_empty());
    }

    #[test]
    fn compatibility_media_type_requires_explicit_opt_in() {
        let mut retrieval = retrieval();
        retrieval.media_type = "Application/JSON; charset=utf-8".to_owned();
        assert!(!policy_retrieval_issues(&authority(), Some(&retrieval), &context()).is_empty());

        let mut context = context();
        context.allow_application_json = true;
        assert!(policy_retrieval_issues(&authority(), Some(&retrieval), &context).is_empty());
    }

    #[test]
    fn rejects_mismatched_uri_and_bad_status() {
        let mut mismatched_uri = retrieval();
        mismatched_uri.requested_uri = "https://attacker.example/policy.json".to_owned();
        assert!(
            !policy_retrieval_issues(&authority(), Some(&mismatched_uri), &context()).is_empty()
        );

        let mut bad_status = retrieval();
        bad_status.status_code = 206;
        assert!(!policy_retrieval_issues(&authority(), Some(&bad_status), &context()).is_empty());
    }

    #[test]
    fn retrieval_validation_does_not_preempt_authority_expiry() {
        let stale = EvaluationContext::new(
            crate::timestamp::Timestamp::parse("2027-02-28T08:00:00Z").unwrap(),
        );
        assert!(policy_retrieval_issues(&authority(), Some(&retrieval()), &stale).is_empty());
    }
}
