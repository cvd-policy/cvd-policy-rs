//! Builds Version 1 policies and updates unsigned `security.txt` files.
//!
//! The functions validate publisher-supplied HTTPS URIs without rewriting them.
//! Signed `security.txt` text is never modified because any edit invalidates its
//! cleartext signature.

use serde_json::Value;

use crate::policy::Policy;
use crate::types::{Diagnostic, InputError, PolicyError};
use crate::uri::is_https_uri;

// Keep merge-time copying bounded independently of the authority parser's larger limit.
const MAX_SECURITY_TXT_BYTES: usize = 32 * 1024;

/// Generates a validated Version 1 policy, defaulting only a missing version.
///
/// An explicitly supplied `cvd_policy` value is preserved so invalid versions
/// are rejected instead of silently rewritten.
///
/// # Examples
///
/// ```
/// use cvd_policy::publish::generate_policy;
/// use serde_json::json;
///
/// let policy = generate_policy(json!({
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
/// }))?;
/// assert_eq!(policy.value()["cvd_policy"], 1);
/// # Ok::<(), cvd_policy::PolicyError>(())
/// ```
///
/// # Errors
///
/// Returns the core policy error when the input is not a valid Version 1 policy.
pub fn generate_policy(input: Value) -> Result<Policy, PolicyError> {
    let mut input = input;
    if let Some(object) = input.as_object_mut() {
        if !object.contains_key("cvd_policy") {
            object.insert("cvd_policy".to_owned(), Value::from(1));
        }
    }
    Policy::from_value(input)
}

/// Options for publishing a generated `security.txt` file.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecurityTxtOptions {
    /// Absolute HTTPS URI where the policy is published.
    pub policy_uri: String,
    /// Optional absolute HTTPS URI identifying this `security.txt` file.
    pub security_txt_uri: Option<String>,
    /// Optional human-readable policy URIs, emitted in order.
    pub human_policy_uris: Vec<String>,
}

/// Renders the policy's contacts and metadata as a complete `security.txt` file.
///
/// The supplied URIs are checked as absolute HTTPS URIs and are emitted exactly
/// as provided. The output uses LF line endings and ends with a newline.
///
/// # Errors
///
/// Returns an input error if an output field cannot be read from the validated
/// policy or a supplied URI is invalid or contains a line break.
pub fn security_txt(policy: &Policy, options: &SecurityTxtOptions) -> Result<String, InputError> {
    validate_https(&options.policy_uri, "/policy_uri")?;
    if let Some(uri) = &options.security_txt_uri {
        validate_https(uri, "/security_txt_uri")?;
    }
    for (index, uri) in options.human_policy_uris.iter().enumerate() {
        validate_https(uri, &format!("/human_policy_uris/{index}"))?;
    }

    let value = policy.value();
    let channels = string_values(value.pointer("/contact/channels"), "/contact/channels")?;
    let expires = required_string(value.pointer("/expires"), "/expires")?;
    let encryption =
        optional_string_values(value.pointer("/contact/encryption"), "/contact/encryption")?;
    let languages = optional_string_values(
        value.pointer("/contact/preferred_languages"),
        "/contact/preferred_languages",
    )?;

    let mut lines = Vec::new();
    for channel in channels {
        ensure_single_line(channel, "/contact/channels")?;
        lines.push(format!("Contact: {channel}"));
    }
    ensure_single_line(expires, "/expires")?;
    lines.push(format!("Expires: {expires}"));
    for uri in encryption {
        ensure_single_line(uri, "/contact/encryption")?;
        lines.push(format!("Encryption: {uri}"));
    }
    if !languages.is_empty() {
        for language in &languages {
            ensure_single_line(language, "/contact/preferred_languages")?;
        }
        lines.push(format!("Preferred-Languages: {}", languages.join(", ")));
    }
    if let Some(uri) = &options.security_txt_uri {
        lines.push(format!("Canonical: {uri}"));
    }
    for uri in &options.human_policy_uris {
        lines.push(format!("Policy: {uri}"));
    }
    lines.push(format!("CVD-Policy: {}", options.policy_uri));
    Ok(format!("{}\n", lines.join("\n")))
}

/// Replaces all `CVD-Policy` fields without changing other file content.
///
/// Field names are matched case-insensitively. Comments, other fields, their
/// order and multiplicity, and uniform LF or CRLF endings are preserved. Inputs
/// over 32 KiB or with mixed/bare-CR endings are rejected instead of normalized.
/// Cleartext-signed input is rejected rather than invalidating its signature.
///
/// # Examples
///
/// ```
/// use cvd_policy::publish::merge_security_txt;
///
/// let merged = merge_security_txt(
///     "Contact: mailto:security@example.com\n",
///     "https://example.com/cvd-policy.json",
/// )?;
/// assert!(merged.ends_with("CVD-Policy: https://example.com/cvd-policy.json\n"));
/// # Ok::<(), cvd_policy::InputError>(())
/// ```
///
/// # Errors
///
/// Returns an input error for an invalid policy URI, line breaks in the URI,
/// input over 32 KiB, mixed or bare-CR endings, or cleartext-signed input.
pub fn merge_security_txt(raw: &str, policy_uri: &str) -> Result<String, InputError> {
    if raw.len() > MAX_SECURITY_TXT_BYTES {
        return Err(input_error(
            "security_txt_resource_limit",
            "",
            "security.txt exceeds the merge byte limit.",
        ));
    }
    if is_signed_security_txt(raw) {
        return Err(input_error(
            "security_txt_signed",
            "",
            "Cannot modify a signed security.txt; re-sign it manually.",
        ));
    }
    validate_https(policy_uri, "/policy_uri")?;

    let newline = newline_style(raw)?;
    let mut lines: Vec<String> = raw
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line).to_owned())
        .collect();
    let replacement = format!("CVD-Policy: {policy_uri}");

    let mut found = false;
    let mut updated = Vec::with_capacity(lines.len() + 1);
    for line in lines.drain(..) {
        if field_name(&line).is_some_and(|name| name.eq_ignore_ascii_case("CVD-Policy")) {
            if !found {
                updated.push(replacement.clone());
                found = true;
            }
        } else {
            updated.push(line);
        }
    }

    if !found {
        if let Some(index) = updated.iter().rposition(|line| field_name(line).is_some()) {
            updated.insert(index + 1, replacement);
        } else if raw.is_empty() {
            updated = vec![replacement, String::new()];
        } else if raw.ends_with('\n') {
            let index = updated.len().saturating_sub(1);
            updated.insert(index, replacement);
        } else {
            updated.push(replacement);
            updated.push(String::new());
        }
    }

    Ok(updated.join(newline))
}

fn validate_https(uri: &str, path: &str) -> Result<(), InputError> {
    if uri.contains('\r') || uri.contains('\n') || !is_https_uri(uri) {
        return Err(input_error(
            "https_uri_invalid",
            path,
            "Expected an absolute HTTPS URI without userinfo, fragment, or line breaks.",
        ));
    }
    Ok(())
}

fn required_string<'a>(value: Option<&'a Value>, path: &str) -> Result<&'a str, InputError> {
    value.and_then(Value::as_str).ok_or_else(|| {
        input_error(
            "policy_field_invalid",
            path,
            "The validated policy is missing a required string field.",
        )
    })
}

fn string_values<'a>(value: Option<&'a Value>, path: &str) -> Result<Vec<&'a str>, InputError> {
    let Some(values) = value.and_then(Value::as_array) else {
        return Err(input_error(
            "policy_field_invalid",
            path,
            "The validated policy is missing a required string array.",
        ));
    };
    values
        .iter()
        .map(|value| {
            value.as_str().ok_or_else(|| {
                input_error(
                    "policy_field_invalid",
                    path,
                    "The validated policy contains a non-string array entry.",
                )
            })
        })
        .collect()
}

fn optional_string_values<'a>(
    value: Option<&'a Value>,
    path: &str,
) -> Result<Vec<&'a str>, InputError> {
    match value {
        None => Ok(Vec::new()),
        Some(value) => string_values(Some(value), path),
    }
}

fn ensure_single_line(value: &str, path: &str) -> Result<(), InputError> {
    if value.contains('\r') || value.contains('\n') {
        return Err(input_error(
            "security_txt_line_break",
            path,
            "A security.txt field value cannot contain a line break.",
        ));
    }
    Ok(())
}

fn is_signed_security_txt(raw: &str) -> bool {
    raw.split('\n').any(|line| {
        line.strip_suffix('\r')
            .unwrap_or(line)
            .starts_with("-----BEGIN PGP SIGNED MESSAGE-----")
    })
}

fn newline_style(raw: &str) -> Result<&'static str, InputError> {
    let bytes = raw.as_bytes();
    let mut has_lf = false;
    let mut has_crlf = false;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' if bytes.get(index + 1) == Some(&b'\n') => {
                has_crlf = true;
                index += 2;
            }
            b'\r' => {
                return Err(input_error(
                    "security_txt_newline_invalid",
                    "",
                    "Bare carriage returns are not supported as line endings.",
                ));
            }
            b'\n' => {
                has_lf = true;
                index += 1;
            }
            _ => index += 1,
        }
    }
    if has_lf && has_crlf {
        return Err(input_error(
            "security_txt_newline_mixed",
            "",
            "Mixed LF and CRLF line endings cannot be merged without normalization.",
        ));
    }
    Ok(if has_crlf { "\r\n" } else { "\n" })
}

fn field_name(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let separator = trimmed.find(':')?;
    let name = trimmed[..separator].trim_end_matches([' ', '\t']);
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }
    Some(name)
}

fn input_error(code: &str, path: &str, message: &str) -> InputError {
    InputError {
        diagnostics: vec![Diagnostic {
            code: code.to_owned(),
            path: path.to_owned(),
            message: message.to_owned(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use crate::policy::Policy;
    use crate::types::PolicyErrorKind;

    use super::{
        generate_policy, merge_security_txt, security_txt, SecurityTxtOptions,
        MAX_SECURITY_TXT_BYTES,
    };

    fn policy_value() -> Value {
        json!({
            "cvd_policy": 1,
            "last_updated": "2026-11-08T00:00:00Z",
            "expires": "2027-05-07T00:00:00Z",
            "organization": { "name": "Example Organization" },
            "contact": {
                "channels": ["mailto:security@example.com"],
                "preferred_languages": ["en", "de"],
                "encryption": ["https://example.com/security/pgp-key.txt"]
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
            }
        })
    }

    fn policy() -> Policy {
        Policy::from_value(policy_value()).expect("valid core policy")
    }

    #[test]
    fn generation_adds_v1_only_when_the_version_is_missing() {
        let mut input = policy_value();
        input.as_object_mut().expect("object").remove("cvd_policy");
        let generated = generate_policy(input).expect("missing version defaults to V1");
        assert_eq!(generated.value()["cvd_policy"], 1);

        let mut wrong_version = policy_value();
        wrong_version["cvd_policy"] = json!(2);
        let error = generate_policy(wrong_version).expect_err("explicit versions are preserved");
        assert_eq!(error.kind, PolicyErrorKind::UnsupportedVersion);
    }

    #[test]
    fn generation_enforces_in_memory_policy_resource_limits() {
        let mut input = policy_value();
        input["extensions"] = json!({
            "https://example.com/large-extension": "x".repeat(
                crate::parse::ParseLimits::default().max_bytes
            )
        });

        let error = generate_policy(input).expect_err("in-memory values use policy limits");
        assert_eq!(error.kind, PolicyErrorKind::ResourceLimit);
    }

    #[test]
    fn complete_security_txt_keeps_original_https_uri_strings() {
        let output = security_txt(
            &policy(),
            &SecurityTxtOptions {
                policy_uri: "https://Example.com:443/cvd-policy.json".to_owned(),
                security_txt_uri: Some(
                    "https://Example.com:443/.well-known/security.txt".to_owned(),
                ),
                human_policy_uris: vec!["https://Example.com:443/policy".to_owned()],
            },
        )
        .expect("valid options");

        assert_eq!(
            output,
            concat!(
                "Contact: mailto:security@example.com\n",
                "Expires: 2027-05-07T00:00:00Z\n",
                "Encryption: https://example.com/security/pgp-key.txt\n",
                "Preferred-Languages: en, de\n",
                "Canonical: https://Example.com:443/.well-known/security.txt\n",
                "Policy: https://Example.com:443/policy\n",
                "CVD-Policy: https://Example.com:443/cvd-policy.json\n"
            )
        );
    }

    #[test]
    fn publisher_uri_fields_reject_newline_injection() {
        let error = security_txt(
            &policy(),
            &SecurityTxtOptions {
                policy_uri: "https://example.com/policy\nContact: mailto:attacker@example.com"
                    .to_owned(),
                ..SecurityTxtOptions::default()
            },
        );
        assert!(error.is_err());

        assert!(merge_security_txt(
            "Contact: mailto:security@example.com\n",
            "https://example.com/policy\r\nContact: mailto:attacker@example.com"
        )
        .is_err());
    }

    #[test]
    fn merge_replaces_only_cvd_policy_and_preserves_crlf_and_other_fields() {
        let raw = concat!(
            "# Keep this comment\r\n",
            "Contact: mailto:security@example.com\r\n",
            "Policy: https://example.com/human-policy\r\n",
            "Policy: https://example.com/second-human-policy\r\n",
            "cVd-PoLiCy: https://old.example/policy\r\n",
            "Canonical: https://example.com/.well-known/security.txt\r\n",
            "CVD-POLICY: https://duplicate.example/policy\r\n"
        );
        let merged = merge_security_txt(raw, "https://Example.com:443/policy").expect("valid URI");

        assert_eq!(
            merged,
            concat!(
                "# Keep this comment\r\n",
                "Contact: mailto:security@example.com\r\n",
                "Policy: https://example.com/human-policy\r\n",
                "Policy: https://example.com/second-human-policy\r\n",
                "CVD-Policy: https://Example.com:443/policy\r\n",
                "Canonical: https://example.com/.well-known/security.txt\r\n"
            )
        );
    }

    #[test]
    fn signed_security_txt_is_never_modified() {
        let raw = concat!(
            "-----BEGIN PGP SIGNED MESSAGE-----\n",
            "Hash: SHA256\n\n",
            "Contact: mailto:security@example.com\n",
            "-----BEGIN PGP SIGNATURE-----\n",
            "signature\n",
            "-----END PGP SIGNATURE-----\n"
        );

        assert!(merge_security_txt(raw, "https://example.com/policy").is_err());
    }

    #[test]
    fn merge_bounds_input_and_rejects_endings_it_cannot_preserve() {
        let oversized = "x".repeat(MAX_SECURITY_TXT_BYTES + 1);
        let size_error = merge_security_txt(&oversized, "https://example.com/policy")
            .expect_err("oversized input is bounded");
        assert_eq!(
            size_error.diagnostics[0].code,
            "security_txt_resource_limit"
        );

        let mixed = merge_security_txt(
            "Contact: mailto:security@example.com\r\nPolicy: https://example.com/policy\n",
            "https://example.com/policy",
        )
        .expect_err("mixed line endings are not normalized");
        assert_eq!(mixed.diagnostics[0].code, "security_txt_newline_mixed");

        let bare_cr = merge_security_txt(
            "Contact: mailto:security@example.com\rPolicy: https://example.com/policy",
            "https://example.com/policy",
        )
        .expect_err("bare carriage return is not an accepted line ending");
        assert_eq!(bare_cr.diagnostics[0].code, "security_txt_newline_invalid");
    }
}
