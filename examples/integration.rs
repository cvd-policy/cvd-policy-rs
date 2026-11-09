use std::error::Error;

use cvd_policy::csaf::{assess_csaf, assess_csaf_for_host, CsafState, CSAF_SPECIFICATION};
use cvd_policy::{
    assess_security_txt, evaluate_policy, EvaluationContext, EvaluationQuery, Policy,
    PolicyRetrieval, SecurityTxtRetrieval, Timestamp,
};

const NOW: &str = "2026-11-08T12:00:00Z";
const POLICY: &[u8] =
    include_bytes!("../vendor/spec/examples/v1/csaf-reporting-policy.example.json");
const SECURITY_TXT: &[u8] = b"Contact: mailto:security@example.com\nCVD-Policy: https://example.com/cvd-policy.json\nExpires: 2027-05-07T00:00:00Z\n";

fn main() -> Result<(), Box<dyn Error>> {
    let policy = Policy::parse(POLICY)?;
    let now = Timestamp::parse(NOW)?;
    policy.validate_at(&now)?;

    let authority = assess_security_txt(
        SECURITY_TXT,
        &SecurityTxtRetrieval {
            requested_uri: "https://example.com/.well-known/security.txt".to_owned(),
            final_uri: "https://example.com/.well-known/security.txt".to_owned(),
            redirect_chain: Vec::new(),
            retrieved_at: Timestamp::parse("2026-11-08T11:00:00Z")?,
        },
    )
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
    let permission = evaluate_policy(POLICY, &query, Some(&authority), &context)?;
    let declaration = assess_csaf(POLICY)?;
    let host_assessment =
        assess_csaf_for_host(POLICY, Some(&authority), Some(&retrieval), &context);
    let host_capability = host_assessment.capability?;

    assert_eq!(permission.status.to_string(), "publisher-stated-prohibited");
    assert_eq!(declaration.state, CsafState::Advertised);
    assert_eq!(declaration.channels[0].specification, CSAF_SPECIFICATION);
    assert!(host_assessment.usable);
    println!(
        "now={NOW} parse=valid authority=established permission={} csaf={:?} usable={}",
        permission.status, host_capability.state, host_assessment.usable
    );
    Ok(())
}
