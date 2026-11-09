//! Normalizes web targets and applies Version 1 reporting-scope matching.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde_json::Value;
use url::{Host, Url};

use crate::types::{Diagnostic, InputError};
use crate::{number, policy::Policy};

/// A normalized HTTP(S) target used for deterministic scope matching.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedTarget {
    /// Lowercase scheme without a trailing colon.
    pub scheme: String,
    /// Lowercase A-label DNS name or canonical IP literal without IPv6 brackets.
    pub host: String,
    /// Explicit port or the scheme's default port.
    pub port: u16,
    /// Normalized RFC 3986 path without query or fragment; non-ASCII bytes must be percent-encoded.
    pub path: String,
}

/// Normalizes a DNS name or IP literal for Version 1 comparisons.
///
/// One trailing DNS root dot is removed. IPv4 and IPv6 values use their canonical textual
/// representation; DNS names are converted to lowercase ASCII A-label form by `url`.
/// Scope hosts are DNS names or IP literals, not URI reg-names, so percent escapes are rejected.
///
/// # Errors
/// Returns a diagnostic when `value` is not a valid DNS name or IP literal.
pub fn normalize_host(value: &str) -> Result<String, Diagnostic> {
    let invalid = || diagnostic("policy_scope_invalid", "", "invalid scope host");
    if value.is_empty()
        || value.contains('%')
        || value.chars().any(|character| {
            character.is_whitespace() || matches!(character, '/' | '\\' | '?' | '#' | '@' | '*')
        })
    {
        return Err(invalid());
    }

    let bracketed = value.starts_with('[') || value.ends_with(']');
    let unbracketed = match (value.strip_prefix('['), value.strip_suffix(']')) {
        (Some(inner), Some(_)) => inner.strip_suffix(']').ok_or_else(invalid)?,
        (Some(_), None) | (None, Some(_)) => return Err(invalid()),
        (None, None) => value,
    };

    if let Ok(ipv6) = unbracketed.parse::<Ipv6Addr>() {
        return Ok(ipv6.to_string());
    }
    if bracketed || unbracketed.contains(':') {
        return Err(invalid());
    }

    match Host::parse(unbracketed).map_err(|_| invalid())? {
        Host::Ipv4(address) => Ok(address.to_string()),
        Host::Ipv6(address) => Ok(address.to_string()),
        Host::Domain(domain) => {
            let domain = domain.strip_suffix('.').unwrap_or(&domain);
            if domain.is_empty()
                || domain.len() > 253
                || domain
                    .split('.')
                    .any(|label| label.is_empty() || label.len() > 63)
            {
                return Err(invalid());
            }
            Ok(domain.to_ascii_lowercase())
        }
    }
}

/// Normalizes a path according to the Version 1 path-matching rules.
///
/// Accepts RFC 3986 URI path characters (`pchar` and `/`); raw non-ASCII characters must be
/// percent-encoded as UTF-8. Percent-encoded octets are never decoded. Only literal RFC 3986
/// dot-segments are removed.
///
/// # Errors
/// Returns a diagnostic for invalid URI path syntax, query or fragment syntax, or malformed escape.
pub fn normalize_path(value: &str) -> Result<String, Diagnostic> {
    if value.is_empty() {
        return Ok("/".to_owned());
    }
    if !value.starts_with('/') || value.contains(['?', '#']) {
        return Err(diagnostic("policy_scope_invalid", "", "invalid scope path"));
    }

    let bytes = value.as_bytes();
    let mut uppercase = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some((&high, &low)) = bytes.get(index + 1).zip(bytes.get(index + 2)) else {
                return Err(diagnostic(
                    "policy_scope_invalid",
                    "",
                    "invalid percent escape in path",
                ));
            };
            let (Some(high), Some(low)) = ((high as char).to_digit(16), (low as char).to_digit(16))
            else {
                return Err(diagnostic(
                    "policy_scope_invalid",
                    "",
                    "invalid percent escape in path",
                ));
            };
            uppercase.push('%');
            uppercase.push(char::from_digit(high, 16).unwrap().to_ascii_uppercase());
            uppercase.push(char::from_digit(low, 16).unwrap().to_ascii_uppercase());
            index += 3;
        } else if is_path_character(bytes[index]) {
            uppercase.push(char::from(bytes[index]));
            index += 1;
        } else {
            return Err(diagnostic(
                "policy_scope_invalid",
                "",
                "invalid URI path character",
            ));
        }
    }

    Ok(remove_dot_segments(&uppercase))
}

/// Validates and normalizes an absolute HTTP(S) target before policy processing.
///
/// The WHATWG URL parser supplies scheme, host, and effective port. The original path is retained
/// so URL-parser normalization cannot decode encoded dots or collapse encoded slashes.
/// Paths use RFC 3986 URI syntax, so non-ASCII path characters must be UTF-8 percent-encoded;
/// Unicode host names remain accepted and are normalized to IDNA A-labels.
///
/// # Errors
/// Returns a machine-readable input error for invalid target syntax or an unsupported scheme.
pub fn normalize_target(value: &str) -> Result<NormalizedTarget, InputError> {
    let input_error = || InputError {
        diagnostics: vec![diagnostic(
            "target_url_invalid",
            "/target",
            "target must be an absolute HTTP or HTTPS URL without userinfo",
        )],
    };
    if value.chars().next().is_some_and(char::is_whitespace)
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.contains('\\')
    {
        return Err(input_error());
    }
    let url = Url::parse(value).map_err(|_| input_error())?;
    let scheme = url.scheme();
    if !matches!(scheme, "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || raw_authority(value).is_none_or(|authority| authority.contains('@'))
    {
        return Err(input_error());
    }

    let host = match url.host().ok_or_else(input_error)? {
        Host::Domain(domain) => normalize_host(domain).map_err(|_| input_error())?,
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };
    let port = url.port_or_known_default().ok_or_else(input_error)?;
    let path = raw_path(value)
        .and_then(|path| normalize_path(path).ok())
        .ok_or_else(input_error)?;

    Ok(NormalizedTarget {
        scheme: scheme.to_owned(),
        host,
        port,
        path,
    })
}

/// Returns whether one web-scope entry matches all normalized target dimensions.
pub fn scope_entry_matches(entry: &Value, target: &NormalizedTarget) -> bool {
    let Some(host) = entry.get("host").and_then(Value::as_str) else {
        return false;
    };
    let Ok(host) = normalize_host(host) else {
        return false;
    };
    let include_subdomains = entry
        .get("include_subdomains")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let is_ip = host.parse::<Ipv4Addr>().is_ok() || host.parse::<Ipv6Addr>().is_ok();
    let host_matches = target.host == host
        || (!is_ip && include_subdomains && target.host.ends_with(&format!(".{host}")));
    if !host_matches {
        return false;
    }

    let Some(schemes) = entry.get("schemes").and_then(Value::as_array) else {
        return false;
    };
    if !schemes
        .iter()
        .any(|scheme| scheme.as_str() == Some(&target.scheme))
    {
        return false;
    }

    let port_matches = match entry.get("ports") {
        Some(Value::Array(ports)) => ports.iter().any(|port| {
            port.as_number().is_some_and(|port| {
                number::is_integer(port)
                    && number::compare(port, &serde_json::Number::from(target.port))
                        == std::cmp::Ordering::Equal
            })
        }),
        Some(_) => false,
        None => target.port == if target.scheme == "https" { 443 } else { 80 },
    };
    if !port_matches {
        return false;
    }

    let Some(prefix) = entry.get("path_prefix").and_then(Value::as_str) else {
        return false;
    };
    let Ok(prefix) = normalize_path(prefix) else {
        return false;
    };
    path_matches(&prefix, &target.path)
}

/// Returns sorted IDs of all web-scope entries matching `target`.
pub fn matching_scope_ids(policy: &Policy, target: &NormalizedTarget) -> Vec<String> {
    let Some(entries) = policy
        .value()
        .get("reporting_scope")
        .and_then(|scope| scope.get("web"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };

    let mut ids = entries
        .iter()
        .filter(|entry| scope_entry_matches(entry, target))
        .filter_map(|entry| entry.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn path_matches(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || if prefix.ends_with('/') {
            path.starts_with(prefix)
        } else {
            path == prefix || path.starts_with(&format!("{prefix}/"))
        }
}

fn remove_dot_segments(path: &str) -> String {
    let mut input = path;
    let mut output = String::with_capacity(path.len());
    while !input.is_empty() {
        if input.starts_with("../") {
            input = &input[3..];
        } else if input.starts_with("./") || input.starts_with("/./") {
            input = &input[2..];
        } else if input == "/." {
            input = "/";
        } else if input.starts_with("/../") {
            input = &input[3..];
            remove_last_segment(&mut output);
        } else if input == "/.." {
            input = "/";
            remove_last_segment(&mut output);
        } else if input == "." || input == ".." {
            input = "";
        } else {
            let next_slash = input[1..].find('/').map_or(input.len(), |index| index + 1);
            output.push_str(&input[..next_slash]);
            input = &input[next_slash..];
        }
    }
    if output.is_empty() {
        "/".to_owned()
    } else {
        output
    }
}

fn remove_last_segment(output: &mut String) {
    if let Some(index) = output.rfind('/') {
        output.truncate(index);
    } else {
        output.clear();
    }
}

fn is_path_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'/' | b'-'
                | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn raw_authority(value: &str) -> Option<&str> {
    let colon = value.find(':')?;
    let rest = value.get(colon + 1..)?.strip_prefix("//")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    (!authority.is_empty()).then_some(authority)
}

fn raw_path(value: &str) -> Option<&str> {
    let colon = value.find(':')?;
    let remainder = value.get(colon + 1..)?.strip_prefix("//")?;
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    if authority_end == 0 {
        return None;
    }
    let path_and_suffix = &remainder[authority_end..];
    let path_end = path_and_suffix
        .find(['?', '#'])
        .unwrap_or(path_and_suffix.len());
    Some(&path_and_suffix[..path_end])
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
    use serde_json::json;

    use super::{normalize_host, normalize_path, normalize_target, scope_entry_matches};
    use crate::policy::Policy;

    #[test]
    fn canonicalizes_ipv6_and_idna_hosts() {
        assert_eq!(normalize_host("[2001:0DB8:0:0::1]").unwrap(), "2001:db8::1");
        assert_eq!(
            normalize_host("[2001:db8::1]").unwrap(),
            normalize_host("2001:db8::1").unwrap()
        );
        assert_eq!(
            normalize_host("BÜCHER.Example.").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(
            normalize_target("https://[2001:db8::1]/").unwrap().host,
            "2001:db8::1"
        );
    }

    #[test]
    fn preserves_encoded_octets_and_repeated_slashes_while_removing_literal_dots() {
        let pchar_path = "/AZaz09-._~!$&'()*+,;=:@//";
        assert_eq!(normalize_path(pchar_path).unwrap(), pchar_path);
        assert_eq!(
            normalize_path("/a//b/../%2f/%2e%2e").unwrap(),
            "/a//%2F/%2E%2E"
        );
        assert_eq!(
            normalize_target("https://example.com/a/%2e%2e//b")
                .unwrap()
                .path,
            "/a/%2E%2E//b"
        );
        assert_eq!(
            normalize_target("https://example.com/a/../api")
                .unwrap()
                .path,
            "/api"
        );
        assert_eq!(
            normalize_path("/%C3%BC/%20/%5B").unwrap(),
            "/%C3%BC/%20/%5B"
        );
        assert_eq!(
            normalize_target("https://example.com/%C3%BC/%20/%5B")
                .unwrap()
                .path,
            "/%C3%BC/%20/%5B"
        );
    }

    #[test]
    fn matches_path_prefixes_on_segment_boundaries_and_host_labels() {
        let entry = json!({
            "host": "example.com",
            "schemes": ["https"],
            "path_prefix": "/api",
            "include_subdomains": true
        });
        assert!(scope_entry_matches(
            &entry,
            &normalize_target("https://a.example.com/api/v1").unwrap()
        ));
        assert!(!scope_entry_matches(
            &entry,
            &normalize_target("https://aexample.com/api/v1").unwrap()
        ));
        assert!(!scope_entry_matches(
            &entry,
            &normalize_target("https://example.com/apix").unwrap()
        ));
    }

    #[test]
    fn rejects_invalid_paths_and_mixed_target_errors() {
        assert!(normalize_path("/api%2").is_err());
        assert!(normalize_path("/api?query").is_err());
        for path in ["/a b", "/[x]", "/ü", "/\"", "/{x}", "/|", "/^", "/`"] {
            assert!(normalize_path(path).is_err(), "{path:?}");
        }
        assert!(normalize_target("https://example.com/%zz").is_err());
        assert!(normalize_target("https://@example.com/").is_err());
        assert!(normalize_host("[example.com]").is_err());
        assert!(normalize_host("ex%61mple.com").is_err());
    }

    #[test]
    fn invalid_scope_path_is_a_semantic_policy_error() {
        let policy = json!({
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
                "path_prefix": "/a b",
                "include_subdomains": false
            }]},
            "reporting": {
                "requested_fields": [],
                "proof_of_exploitation": "not_requested"
            }
        });

        let error = Policy::from_value(policy).unwrap_err();
        assert_eq!(error.diagnostics[0].code, "policy_semantic_invalid");
        assert_eq!(
            error.diagnostics[0].path,
            "/reporting_scope/web/0/path_prefix"
        );
    }

    #[test]
    fn rejects_url_parser_repairs_but_keeps_idna_hosts() {
        for target in [
            "https:\\\\example.com\\path",
            "https:///example.com/path",
            " https://example.com/path",
            "https://example.com/\u{7f}",
            "https://example.com/a b",
            "https://example.com/[x]",
            "https://example.com/ü",
        ] {
            let error = normalize_target(target).unwrap_err();
            assert_eq!(
                error.diagnostics[0].code, "target_url_invalid",
                "{target:?}"
            );
        }
        assert_eq!(
            normalize_target("https://BÜCHER.example/path")
                .unwrap()
                .host,
            "xn--bcher-kva.example"
        );
    }
}
