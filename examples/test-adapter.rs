use std::error::Error;
use std::io::{self, BufRead, Write};

use cvd_policy::csaf::{assess_csaf, assess_csaf_for_host};
use cvd_policy::{
    assess_security_txt, evaluate_policy, AuthorityEvidence, EvaluationContext, EvaluationQuery,
    Policy, PolicyError, PolicyErrorKind, SecurityTxtRetrieval, Timestamp,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    id: Option<String>,
    operation: String,
    policy_text: String,
    now: String,
    #[serde(default)]
    allow_application_json: bool,
    security_txt: Option<String>,
    security_txt_retrieval: Option<SecurityTxtRetrieval>,
    query: Option<EvaluationQuery>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut output = stdout.lock();

    for line in stdin.lock().lines() {
        let line = line?;
        let request: Request = serde_json::from_str(&line)?;
        let response = handle(request)?;
        serde_json::to_writer(&mut output, &response)?;
        writeln!(output)?;
    }
    Ok(())
}

fn handle(request: Request) -> Result<Value, Box<dyn Error>> {
    let now = Timestamp::parse(&request.now)?;
    let mut context = EvaluationContext::new(now);
    context.allow_application_json = request.allow_application_json;
    let id = request
        .id
        .as_ref()
        .map_or(Value::Null, |value| json!(value));

    let response = match request.operation.as_str() {
        "parse" => parse(&request.policy_text, &context),
        "security-txt" => security_txt(&request)?,
        "evaluate" => evaluate(&request, &context)?,
        "csaf" => csaf(&request, &context)?,
        operation => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported test-adapter operation: {operation}"),
            )
            .into());
        }
    };
    let mut response = response;
    response["id"] = id;
    Ok(response)
}

fn parse(raw: &str, context: &EvaluationContext) -> Value {
    let layers = match cvd_policy::parse_json(raw.as_bytes(), cvd_policy::ParseLimits::default()) {
        Ok(value) => {
            let structure = cvd_policy::policy::validate_structure(&value);
            let semantic = cvd_policy::policy::semantic_issues(&value);
            let layer = if !structure.is_empty() {
                "schema"
            } else if !semantic.is_empty() {
                "semantic"
            } else {
                "valid"
            };
            json!({
                "layer": layer,
                "structuralDiagnostics": structure,
                "semanticDiagnostics": semantic,
            })
        }
        Err(error) => json!({
            "layer": "parse",
            "parseDiagnostics": error.diagnostics,
        }),
    };
    match Policy::parse(raw.as_bytes()) {
        Ok(policy) => {
            let current = policy
                .validate_at(&context.now)
                .map_or_else(error_outcome, |_| json!({"status": "valid"}));
            json!({"static": {"status": "valid"}, "current": current, "layers": layers})
        }
        Err(error) => json!({"static": error_outcome(error), "current": null, "layers": layers}),
    }
}

fn security_txt(request: &Request) -> Result<Value, Box<dyn Error>> {
    let (Some(text), Some(retrieval)) = (&request.security_txt, &request.security_txt_retrieval)
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "security-txt operation requires securityTxt and securityTxtRetrieval",
        )
        .into());
    };
    let assessment = assess_security_txt(text.as_bytes(), retrieval);
    let evidence = assessment.evidence.map(|evidence| {
        json!({
            "discoveryHost": evidence.discovery_host(),
            "securityTxtUri": evidence.security_txt_uri(),
            "cvdPolicyUri": evidence.cvd_policy_uri(),
            "securityTxtExpires": evidence.security_txt_expires().to_string(),
        })
    });
    Ok(json!({
        "established": evidence.is_some(),
        "evidence": evidence,
        "diagnostics": assessment.diagnostics,
    }))
}

fn evaluate(request: &Request, context: &EvaluationContext) -> Result<Value, Box<dyn Error>> {
    let query = request.query.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "evaluate operation requires query",
        )
    })?;
    let authority = assess_authority(request)?;
    match evaluate_policy(
        request.policy_text.as_bytes(),
        query,
        authority.as_ref(),
        context,
    ) {
        Ok(result) => Ok(json!({"inputValid": true, "result": result})),
        Err(error) => Ok(json!({"inputValid": false, "diagnostics": error.diagnostics})),
    }
}

fn csaf(request: &Request, context: &EvaluationContext) -> Result<Value, Box<dyn Error>> {
    let query = request.query.as_ref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "csaf operation requires query")
    })?;
    let authority = assess_authority(request)?;
    let metadata = match assess_csaf(request.policy_text.as_bytes()) {
        Ok(assessment) => json!({
            "state": assessment.state,
            "channels": assessment
                .channels
                .iter()
                .map(|channel| json!({
                    "uri": channel.uri,
                    "specification": channel.specification,
                }))
                .collect::<Vec<_>>(),
            "diagnostics": assessment.diagnostics,
        }),
        Err(error) => error_outcome(error),
    };
    let host = assess_csaf_for_host(
        request.policy_text.as_bytes(),
        authority.as_ref(),
        query.policy_retrieval.as_ref(),
        context,
    );
    let permission = evaluate_policy(
        request.policy_text.as_bytes(),
        query,
        authority.as_ref(),
        context,
    );

    Ok(json!({
        "metadata": metadata,
        "hostUsable": host.usable,
        "hostDiagnostics": host.diagnostics,
        "permission": permission.map_or_else(
            |error| json!({"inputValid": false, "diagnostics": error.diagnostics}),
            |result| json!({"inputValid": true, "result": result}),
        ),
    }))
}

fn assess_authority(request: &Request) -> Result<Option<AuthorityEvidence>, Box<dyn Error>> {
    match (&request.security_txt, &request.security_txt_retrieval) {
        (Some(text), Some(retrieval)) => {
            Ok(assess_security_txt(text.as_bytes(), retrieval).evidence)
        }
        (None, None) => Ok(None),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "securityTxt and securityTxtRetrieval must be supplied together",
        )
        .into()),
    }
}

fn error_outcome(error: PolicyError) -> Value {
    let status = match error.kind {
        PolicyErrorKind::Invalid => "invalid-policy",
        PolicyErrorKind::UnsupportedVersion => "unsupported-policy",
        PolicyErrorKind::ResourceLimit => "resource-limit",
    };
    json!({"status": status, "diagnostics": error.diagnostics})
}
