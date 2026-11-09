use std::error::Error;

use cvd_policy::csaf::{assess_csaf_for_host, CsafState, CSAF_SPECIFICATION};
use cvd_policy::{
    assess_security_txt, evaluate_policy, EvaluationContext, EvaluationQuery, Policy,
    PolicyRetrieval, SecurityTxtRetrieval, Timestamp,
};

const NOW: &str = "2026-11-08T12:00:00Z";
const POLICY: &str = r#"{
  "cvd_policy": 1,
  "last_updated": "2026-11-08T00:00:00Z",
  "expires": "2027-05-07T00:00:00Z",
  "organization": {"name": "External Consumer"},
  "contact": {"channels": ["mailto:security@example.com"]},
  "research": {"posture": "report_only"},
  "reporting_scope": {"web": [{
    "id": "main", "state": "in", "host": "example.com",
    "schemes": ["https"], "path_prefix": "/", "include_subdomains": false
  }]},
  "reporting": {"requested_fields": ["description"], "proof_of_exploitation": "not_requested"},
  "extensions": {
    "https://github.com/cvd-policy/spec/extensions/csaf-vulnerability-report-v1": {
      "channels": [{
        "uri": "mailto:security@example.com",
        "specification": "https://docs.oasis-open.org/csaf/csaf/v2.1/csd04/csaf-v2.1-csd04.html"
      }]
    }
  }
}"#;
const SECURITY_TXT: &str = "Contact: mailto:security@example.com\nCVD-Policy: https://example.com/cvd-policy.json\nExpires: 2027-05-07T00:00:00Z\n";

fn main() -> Result<(), Box<dyn Error>> {
    let policy = Policy::parse(POLICY.as_bytes())?;
    let now = Timestamp::parse(NOW)?;
    policy.validate_at(&now)?;

    let security_txt_retrieval = SecurityTxtRetrieval {
        requested_uri: "https://example.com/.well-known/security.txt".to_owned(),
        final_uri: "https://example.com/.well-known/security.txt".to_owned(),
        redirect_chain: Vec::new(),
        retrieved_at: Timestamp::parse("2026-11-08T11:00:00Z")?,
    };
    let authority = assess_security_txt(SECURITY_TXT.as_bytes(), &security_txt_retrieval)
        .evidence
        .ok_or("security.txt did not establish authority")?;

    let retrieval = PolicyRetrieval {
        requested_uri: authority.cvd_policy_uri().to_owned(),
        final_uri: authority.cvd_policy_uri().to_owned(),
        redirect_chain: Vec::new(),
        status_code: 200,
        media_type: "application/cvd-policy+json".to_owned(),
    };
    let context = EvaluationContext::new(now);
    let query = EvaluationQuery {
        activity: "manual_testing".to_owned(),
        target: "https://example.com/".to_owned(),
        plan: None,
        understood_extensions: Vec::new(),
        policy_retrieval: Some(retrieval.clone()),
    };
    let permission = evaluate_policy(POLICY.as_bytes(), &query, Some(&authority), &context)?;
    let csaf = assess_csaf_for_host(
        POLICY.as_bytes(),
        Some(&authority),
        Some(&retrieval),
        &context,
    );
    let capability = csaf.capability?;

    assert_eq!(permission.status.to_string(), "publisher-stated-prohibited");
    assert_eq!(capability.state, CsafState::Advertised);
    assert!(capability.channels.iter().any(|channel| {
        channel.uri == "mailto:security@example.com" && channel.specification == CSAF_SPECIFICATION
    }));
    assert!(csaf.usable);
    println!(
        "now={NOW} parse=valid authority=established permission={} csaf=advertised usable={}",
        permission.status, csaf.usable
    );
    Ok(())
}
