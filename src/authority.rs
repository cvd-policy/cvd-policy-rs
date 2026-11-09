//! Assesses RFC 9116 security.txt bytes as deterministic authority evidence.

use std::collections::HashSet;
use std::str;

use url::{Host, Url};

use crate::scope::normalize_host;
use crate::types::{
    AuthorityAssessment, AuthorityEvidence, Diagnostic, EvaluationContext, SecurityTxtRetrieval,
};
use crate::uri;

const MAX_SECURITY_TXT_LINES: usize = 1_000;
const MAX_SECURITY_TXT_LINE_BYTES: usize = 2_048;
const MAX_REDIRECT_HOPS: usize = 5;
const SIGNED_BEGIN: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const SIGNATURE_BEGIN: &str = "-----BEGIN PGP SIGNATURE-----";
const SIGNATURE_END: &str = "-----END PGP SIGNATURE-----\r\n";

/// Assesses `security.txt` bytes without fetching or cryptographically verifying them.
///
/// Authority is established only when the file, retrieval chain, Contact, Expires, Canonical,
/// and `CVD-Policy` requirements all pass. OpenPGP cleartext framing is recognized but not
/// cryptographically verified.
///
/// # Examples
///
/// ```
/// use cvd_policy::{assess_security_txt, SecurityTxtRetrieval, Timestamp};
///
/// let retrieval = SecurityTxtRetrieval {
///     requested_uri: "https://example.com/.well-known/security.txt".to_owned(),
///     final_uri: "https://example.com/.well-known/security.txt".to_owned(),
///     redirect_chain: Vec::new(),
///     retrieved_at: Timestamp::parse("2026-08-29T10:00:00Z")?,
/// };
/// let assessment = assess_security_txt(
///     b"Contact: mailto:security@example.com\nCVD-Policy: https://example.com/policy.json\nExpires: 2027-02-28T08:00:00Z\n",
///     &retrieval,
/// );
/// assert!(assessment.evidence.is_some());
/// # Ok::<(), cvd_policy::InputError>(())
/// ```
pub fn assess_security_txt(raw: &[u8], retrieval: &SecurityTxtRetrieval) -> AuthorityAssessment {
    let signed = raw.starts_with(SIGNED_BEGIN.as_bytes());
    if raw.len() > crate::parse::ParseLimits::default().max_bytes {
        return failure(
            "security_txt_parse_error",
            "security.txt exceeds its byte limit",
            signed,
            Vec::new(),
        );
    }
    let Ok(source) = str::from_utf8(raw) else {
        return failure(
            "security_txt_parse_error",
            "security.txt is not UTF-8",
            signed,
            Vec::new(),
        );
    };

    let (text, signed) = match cleartext(source) {
        Ok(result) => result,
        Err(()) => {
            return failure(
                "security_txt_parse_error",
                "invalid OpenPGP cleartext framing",
                signed,
                Vec::new(),
            );
        }
    };
    let fields = match parse_fields(&text) {
        Ok(fields) => fields,
        Err(()) => {
            return failure(
                "security_txt_parse_error",
                "invalid security.txt field syntax or resource limit",
                signed,
                Vec::new(),
            );
        }
    };

    let human_policy_uris = values(&fields, "policy");
    let contacts = values(&fields, "contact");
    let expires_values = values(&fields, "expires");
    let policy_values = values(&fields, "cvd-policy");
    if contacts.is_empty() {
        return failure(
            "security_txt_contact_missing",
            "security.txt has no Contact field",
            signed,
            human_policy_uris,
        );
    }
    if !contacts.iter().any(|value| uri::is_uri(value)) {
        return failure(
            "security_txt_contact_invalid",
            "security.txt has no valid absolute Contact URI",
            signed,
            human_policy_uris,
        );
    }
    if expires_values.is_empty() {
        return failure(
            "security_txt_expires_missing",
            "security.txt has no Expires field",
            signed,
            human_policy_uris,
        );
    }
    if expires_values.len() != 1 {
        return failure(
            "security_txt_expires_duplicate",
            "security.txt has multiple Expires fields",
            signed,
            human_policy_uris,
        );
    }
    if policy_values.is_empty() {
        return failure(
            "security_txt_cvd_policy_missing",
            "security.txt has no CVD-Policy field",
            signed,
            human_policy_uris,
        );
    }
    if policy_values.len() != 1 {
        return failure(
            "security_txt_cvd_policy_duplicate",
            "security.txt has multiple CVD-Policy fields",
            signed,
            human_policy_uris,
        );
    }

    let expires = match crate::timestamp::Timestamp::parse(&expires_values[0]) {
        Ok(expires) => expires,
        Err(_) => {
            return failure(
                "security_txt_expires_invalid",
                "Expires is not a valid RFC 3339 timestamp",
                signed,
                human_policy_uris,
            )
        }
    };
    if expires <= retrieval.retrieved_at {
        return failure(
            "security_txt_expired",
            "Expires is not later than retrieval time",
            signed,
            human_policy_uris,
        );
    }

    let policy_uri = &policy_values[0];
    if https_uri_host(policy_uri).is_none() {
        return failure(
            "security_txt_cvd_policy_uri_invalid",
            "CVD-Policy must be an absolute HTTPS URI without userinfo or fragment",
            signed,
            human_policy_uris,
        );
    }

    let Some(discovery_host) = requested_security_txt_host(&retrieval.requested_uri) else {
        return failure(
            "security_txt_redirect_invalid",
            "requested security.txt URI must be the HTTPS well-known endpoint",
            signed,
            human_policy_uris,
        );
    };
    if https_uri_host(&retrieval.final_uri).is_none()
        || retrieval.redirect_chain.len() > MAX_REDIRECT_HOPS
        || retrieval
            .redirect_chain
            .iter()
            .any(|uri| https_uri_host(uri).is_none())
        || !redirect_chain_is_consistent(retrieval)
    {
        return failure(
            "security_txt_redirect_invalid",
            "security.txt redirect evidence is invalid",
            signed,
            human_policy_uris,
        );
    }

    let canonicals = values(&fields, "canonical");
    if !canonicals.is_empty()
        && !canonicals
            .iter()
            .any(|canonical| canonical == &retrieval.requested_uri)
    {
        return failure(
            "security_txt_canonical_mismatch",
            "Canonical does not exactly name the requested security.txt URI",
            signed,
            human_policy_uris,
        );
    }
    let final_host = https_uri_host(&retrieval.final_uri).expect("final URI was validated above");
    if final_host != discovery_host
        && !canonicals
            .iter()
            .any(|canonical| canonical == &retrieval.requested_uri)
    {
        return failure(
            "security_txt_canonical_mismatch",
            "cross-host redirect lacks the exact requested Canonical URI",
            signed,
            human_policy_uris,
        );
    }

    AuthorityAssessment {
        evidence: Some(AuthorityEvidence {
            discovery_host,
            security_txt_uri: retrieval.requested_uri.clone(),
            cvd_policy_uri: policy_uri.clone(),
            security_txt_expires: expires,
        }),
        diagnostics: Vec::new(),
        signed,
        human_policy_uris,
    }
}

/// Revalidates opaque authority evidence at the supplied evaluation instant.
pub fn authority_evidence_issues(
    evidence: &AuthorityEvidence,
    context: &EvaluationContext,
) -> Vec<Diagnostic> {
    let Some(discovery_host) = requested_security_txt_host(&evidence.security_txt_uri) else {
        return vec![diagnostic(
            "authority_host_mismatch",
            "/authority/securityTxtUri",
            "authority evidence has an invalid requested security.txt URI",
        )];
    };
    let Ok(normalized_host) = normalize_host(&evidence.discovery_host) else {
        return vec![diagnostic(
            "authority_host_mismatch",
            "/authority/discoveryHost",
            "authority evidence has an invalid discovery host",
        )];
    };
    if normalized_host != evidence.discovery_host || discovery_host != evidence.discovery_host {
        return vec![diagnostic(
            "authority_host_mismatch",
            "/authority/discoveryHost",
            "authority evidence does not consistently identify its original discovery host",
        )];
    }
    if https_uri_host(&evidence.cvd_policy_uri).is_none() {
        return vec![diagnostic(
            "security_txt_cvd_policy_uri_invalid",
            "/authority/cvdPolicyUri",
            "authority evidence has an invalid advertised Policy URI",
        )];
    }
    if evidence.security_txt_expires <= context.now {
        return vec![diagnostic(
            "security_txt_expired",
            "/authority/securityTxtExpires",
            "security.txt authority evidence has expired",
        )];
    }
    Vec::new()
}

fn cleartext(source: &str) -> Result<(String, bool), ()> {
    if !source.starts_with(SIGNED_BEGIN) {
        return Ok((source.to_owned(), false));
    }
    let signed_begin = format!("{SIGNED_BEGIN}\r\n");
    let rest = source.strip_prefix(&signed_begin).ok_or(())?;
    let (headers, clear_and_signature) = rest.split_once("\r\n\r\n").ok_or(())?;
    let hash_lines = headers.split("\r\n").collect::<Vec<_>>();
    if hash_lines.is_empty()
        || hash_lines.iter().any(|line| {
            let Some(value) = line.strip_prefix("Hash: ") else {
                return true;
            };
            value.is_empty()
                || value.split(',').any(|token| {
                    token.is_empty()
                        || !token.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(
                                    byte,
                                    b'!' | b'#'
                                        | b'$'
                                        | b'%'
                                        | b'&'
                                        | b'\''
                                        | b'*'
                                        | b'+'
                                        | b'-'
                                        | b'.'
                                        | b'^'
                                        | b'_'
                                        | b'`'
                                        | b'|'
                                        | b'~'
                                )
                        })
                })
        })
    {
        return Err(());
    }

    let signature_marker = format!("{SIGNATURE_BEGIN}\r\n");
    let marker_start = clear_and_signature.find(&signature_marker).ok_or(())?;
    let bytes = clear_and_signature.as_bytes();
    if marker_start == 0 || bytes[marker_start - 1] != b'\n' {
        return Err(());
    }
    let clear_end = if marker_start > 1 && bytes[marker_start - 2] == b'\r' {
        marker_start - 2
    } else {
        marker_start - 1
    };
    let clear = &clear_and_signature[..clear_end];
    let signature = &clear_and_signature[marker_start + signature_marker.len()..];
    let armor = signature.strip_suffix(SIGNATURE_END).ok_or(())?;
    if !signature_data_is_framed(armor) {
        return Err(());
    }

    let mut body = String::with_capacity(clear.len() + 1);
    for (index, line) in clear.split('\n').enumerate() {
        if index > 0 {
            body.push('\n');
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.contains('\r') {
            return Err(());
        }
        body.push_str(line.strip_prefix("- ").unwrap_or(line));
    }
    body.push('\n');
    Ok((body, true))
}

fn signature_data_is_framed(armor: &str) -> bool {
    let (headers, payload) = if let Some(payload) = armor.strip_prefix("\r\n") {
        ("", payload)
    } else if let Some((headers, payload)) = armor.split_once("\r\n\r\n") {
        (headers, payload)
    } else {
        return false;
    };
    if !headers.is_empty()
        && headers.split("\r\n").any(|header| {
            let Some((name, value)) = header.split_once(": ") else {
                return true;
            };
            name.is_empty()
                || value.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return false;
    }
    let payload_lines = payload
        .strip_suffix("\r\n")
        .unwrap_or(payload)
        .split("\r\n");
    let mut any = false;
    for line in payload_lines {
        if line.is_empty() {
            return false;
        }
        let data = line.strip_prefix('=').unwrap_or(line);
        if data.is_empty()
            || !data
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return false;
        }
        any = true;
    }
    any
}

fn parse_fields(text: &str) -> Result<Vec<(String, String)>, ()> {
    if text.len() > crate::parse::ParseLimits::default().max_bytes || !text.ends_with('\n') {
        return Err(());
    }
    let mut fields = Vec::new();
    let mut lines = 0;
    for raw_line in text.split_terminator('\n') {
        lines += 1;
        if lines > MAX_SECURITY_TXT_LINES || raw_line.len() > MAX_SECURITY_TXT_LINE_BYTES {
            return Err(());
        }
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.contains('\r') {
            return Err(());
        }
        if line.starts_with('#') || line.bytes().all(|byte| matches!(byte, b' ' | b'\t')) {
            continue;
        }
        let Some(separator) = line.find(':') else {
            return Err(());
        };
        let name = &line[..separator];
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| (33..=57).contains(&byte) || (59..=126).contains(&byte))
        {
            return Err(());
        }
        let raw_value = &line[separator + 1..];
        let Some(value) = raw_value.strip_prefix(' ') else {
            return Err(());
        };
        let value = value.trim_matches([' ', '\t']);
        if value.is_empty()
            || value
                .chars()
                .any(|character| character.is_control() && character != '\t')
        {
            return Err(());
        }
        fields.push((name.to_ascii_lowercase(), value.to_owned()));
    }
    Ok(fields)
}

fn values(fields: &[(String, String)], name: &str) -> Vec<String> {
    fields
        .iter()
        .filter(|(field, _)| field == name)
        .map(|(_, value)| value.clone())
        .collect()
}

fn redirect_chain_is_consistent(retrieval: &SecurityTxtRetrieval) -> bool {
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

fn https_uri_host(value: &str) -> Option<String> {
    if !uri::is_https_uri(value) {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if url.scheme() != "https"
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || raw_authority(value).is_none_or(|authority| authority.contains('@'))
    {
        return None;
    }
    match url.host()? {
        Host::Domain(domain) => normalize_host(domain).ok(),
        Host::Ipv4(address) => Some(address.to_string()),
        Host::Ipv6(address) => Some(address.to_string()),
    }
}

fn requested_security_txt_host(value: &str) -> Option<String> {
    let host = https_uri_host(value)?;
    let colon = value.find(':')?;
    let remainder = value.get(colon + 1..)?.strip_prefix("//")?;
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    if authority_end == 0 || &remainder[authority_end..] != "/.well-known/security.txt" {
        return None;
    }
    Some(host)
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

fn failure(
    code: &str,
    message: &str,
    signed: bool,
    human_policy_uris: Vec<String>,
) -> AuthorityAssessment {
    AuthorityAssessment {
        evidence: None,
        diagnostics: vec![diagnostic(code, "", message)],
        signed,
        human_policy_uris,
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
    use crate::types::{EvaluationContext, SecurityTxtRetrieval};

    use super::{assess_security_txt, authority_evidence_issues};

    fn retrieval() -> SecurityTxtRetrieval {
        SecurityTxtRetrieval {
            requested_uri: "https://example.com/.well-known/security.txt".to_owned(),
            final_uri: "https://example.com/.well-known/security.txt".to_owned(),
            redirect_chain: Vec::new(),
            retrieved_at: crate::timestamp::Timestamp::parse("2026-08-29T10:00:00Z").unwrap(),
        }
    }

    #[test]
    fn accepts_general_absolute_contact_uris_and_preserves_policy_links() {
        let assessment = assess_security_txt(
            b"Contact: dns:security.example?type=OPENPGPKEY\nPolicy: https://example.com/human\nPolicy: https://example.com/other\nCVD-Policy: https://policies.example/policy.json\nExpires: 2027-02-28T08:00:00Z\n",
            &retrieval(),
        );
        let evidence = assessment.evidence.unwrap();
        assert_eq!(evidence.discovery_host(), "example.com");
        assert_eq!(
            evidence.security_txt_uri(),
            "https://example.com/.well-known/security.txt"
        );
        assert_eq!(
            assessment.human_policy_uris,
            ["https://example.com/human", "https://example.com/other"]
        );
    }

    #[test]
    fn accepts_contact_uri_fragments_but_rejects_them_for_cvd_policy() {
        let contact = assess_security_txt(
            b"Contact: https://example.com/contact#security\nCVD-Policy: https://example.com/policy.json\nExpires: 2027-02-28T08:00:00Z\n",
            &retrieval(),
        );
        assert!(contact.evidence.is_some());

        let policy_uri = assess_security_txt(
            b"Contact: https://example.com/contact#security\nCVD-Policy: https://example.com/policy.json#current\nExpires: 2027-02-28T08:00:00Z\n",
            &retrieval(),
        );
        assert_eq!(
            policy_uri.diagnostics[0].code,
            "security_txt_cvd_policy_uri_invalid"
        );
    }

    #[test]
    fn requires_the_exact_requested_well_known_security_txt_path() {
        for requested_uri in [
            "https://example.com/security.txt",
            "https://example.com/.well-known/../.well-known/security.txt",
            "https://example.com/.well-known/security.txt?query",
            "https://example.com/.well-known/security.txt#fragment",
            "https:///example.com/.well-known/security.txt",
        ] {
            let mut retrieval = retrieval();
            retrieval.requested_uri = requested_uri.to_owned();
            retrieval.final_uri = requested_uri.to_owned();
            let assessment = assess_security_txt(
                b"Contact: mailto:security@example.com\nCVD-Policy: https://example.com/policy.json\nExpires: 2027-02-28T08:00:00Z\n",
                &retrieval,
            );
            assert_eq!(
                assessment.diagnostics[0].code, "security_txt_redirect_invalid",
                "{requested_uri}"
            );
        }
    }

    #[test]
    fn requires_an_exact_canonical_for_same_and_cross_host_redirects() {
        let mut context = retrieval();
        context.final_uri = "https://cdn.example/security.txt".to_owned();
        context.redirect_chain = vec![context.final_uri.clone()];
        let bad = assess_security_txt(
            b"Contact: mailto:security@example.com\nCVD-Policy: https://example.com/policy.json\nExpires: 2027-02-28T08:00:00Z\nCanonical: https://cdn.example/security.txt\n",
            &context,
        );
        assert_eq!(bad.diagnostics[0].code, "security_txt_canonical_mismatch");

        let good = assess_security_txt(
            b"Contact: mailto:security@example.com\nCVD-Policy: https://example.com/policy.json\nExpires: 2027-02-28T08:00:00Z\nCanonical: https://example.com/.well-known/security.txt\n",
            &context,
        );
        assert_eq!(
            good.evidence.unwrap().security_txt_uri(),
            "https://example.com/.well-known/security.txt"
        );
    }

    #[test]
    fn expiry_at_retrieval_instant_and_insecure_redirect_fail_closed() {
        let expired = assess_security_txt(
            b"Contact: mailto:security@example.com\nCVD-Policy: https://example.com/policy.json\nExpires: 2026-08-29T10:00:00Z\n",
            &retrieval(),
        );
        assert_eq!(expired.diagnostics[0].code, "security_txt_expired");

        let mut context = retrieval();
        context.final_uri = "http://example.com/security.txt".to_owned();
        context.redirect_chain = vec![context.final_uri.clone()];
        let assessment = assess_security_txt(
            b"Contact: mailto:security@example.com\nCVD-Policy: https://example.com/policy.json\nExpires: 2027-02-28T08:00:00Z\n",
            &context,
        );
        assert_eq!(
            assessment.diagnostics[0].code,
            "security_txt_redirect_invalid"
        );
    }

    #[test]
    fn recognizes_cleartext_signature_framing_without_verifying_cryptography() {
        let signed = b"-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA256\r\n\r\nContact: mailto:security@example.com\r\nCVD-Policy: https://example.com/policy.json\r\nExpires: 2027-02-28T08:00:00Z\r\n-----BEGIN PGP SIGNATURE-----\r\n\r\nAA==\r\n-----END PGP SIGNATURE-----\r\n";
        let assessment = assess_security_txt(signed, &retrieval());
        assert!(assessment.signed);
        assert!(assessment.evidence.is_some());

        let malformed =
            assess_security_txt(b"-----BEGIN PGP SIGNED MESSAGE-----\ninvalid", &retrieval());
        assert!(malformed.signed);
        assert_eq!(malformed.diagnostics[0].code, "security_txt_parse_error");
    }

    #[test]
    fn accepts_mixed_lf_and_crlf_in_signed_cleartext() {
        let signed = b"-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA256\r\n\r\nContact: mailto:security@example.com\nCVD-Policy: https://example.com/policy.json\r\nExpires: 2027-02-28T08:00:00Z\n-----BEGIN PGP SIGNATURE-----\r\n\r\nAA==\r\n-----END PGP SIGNATURE-----\r\n";
        let assessment = assess_security_txt(signed, &retrieval());
        assert!(assessment.evidence.is_some());
    }

    #[test]
    fn optional_signature_armor_headers_are_validated_when_present() {
        assert!(super::signature_data_is_framed("\r\nAA==\r\n"));
        assert!(super::signature_data_is_framed(
            "Version: 1\r\n\r\nAA==\r\n"
        ));
        assert!(!super::signature_data_is_framed(
            "Invalid Header\r\n\r\nAA==\r\n"
        ));
    }

    #[test]
    fn authority_evidence_expires_at_equality() {
        let assessment = assess_security_txt(
            b"Contact: mailto:security@example.com\nCVD-Policy: https://example.com/policy.json\nExpires: 2026-08-29T10:00:00.000000001Z\n",
            &retrieval(),
        );
        let evidence = assessment.evidence.unwrap();
        let context = EvaluationContext::new(
            crate::timestamp::Timestamp::parse("2026-08-29T10:00:00.000000001Z").unwrap(),
        );
        assert_eq!(
            authority_evidence_issues(&evidence, &context)[0].code,
            "security_txt_expired"
        );
    }

    #[test]
    fn rejects_unbounded_security_txt_input() {
        let source = vec![b'a'; crate::parse::ParseLimits::default().max_bytes + 1];
        let assessment = assess_security_txt(&source, &retrieval());
        assert_eq!(assessment.diagnostics[0].code, "security_txt_parse_error");
    }
}
