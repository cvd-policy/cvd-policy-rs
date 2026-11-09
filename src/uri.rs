//! RFC 3986 URI syntax checks without normalization or resolution.

use fluent_uri::Uri;

/// Returns whether `value` is a syntactically valid RFC 3986 URI.
///
/// Fragments are allowed. The input is parsed as written; no URL repair,
/// normalization, resolution, or percent-decoding is performed.
pub(crate) fn is_uri(value: &str) -> bool {
    Uri::parse(value).is_ok()
}

/// Returns whether `value` is an RFC 3986 absolute URI without a fragment.
///
/// An absolute URI includes a scheme; RFC 3986 also permits empty paths and
/// empty authorities for schemes whose syntax allows them.
pub(crate) fn is_absolute_uri(value: &str) -> bool {
    Uri::parse(value).is_ok_and(|uri| !uri.has_fragment())
}

/// Returns whether `value` is an absolute HTTPS URI with a nonempty host.
///
/// Userinfo and fragments are rejected. Ports follow generic RFC 3986 syntax:
/// an empty port and a numeric port above 65,535 are syntactically accepted;
/// this function does not assert that a URI is usable for a network request.
pub(crate) fn is_https_uri(value: &str) -> bool {
    let Ok(uri) = Uri::parse(value) else {
        return false;
    };
    if !uri.scheme().as_str().eq_ignore_ascii_case("https") || uri.has_fragment() {
        return false;
    }
    let Some(authority) = uri.authority() else {
        return false;
    };
    !authority.as_str().is_empty() && !authority.host().is_empty() && authority.userinfo().is_none()
}

#[cfg(test)]
mod tests {
    use super::{is_absolute_uri, is_https_uri, is_uri};

    #[test]
    fn matches_all_seventeen_shared_rfc3986_edge_cases() {
        let cases = [
            ("foo:", true, true),
            ("foo:?x", true, true),
            ("foo:#x", true, false),
            ("https://other.example/spec#v1", true, false),
            ("https://other.example/spec%23v1", true, true),
            ("https://bad.example/\"", false, false),
            ("foo:/[::1]", false, false),
            ("foo:/user@[::1]", false, false),
            ("foo:/[v1.host]", false, false),
            ("foo:/path", true, true),
            ("foo://[::1]/", true, true),
            ("foo:///path", true, true),
            ("foo://", true, true),
            ("foo://user@@h/x", false, false),
            ("foo://h:abc/x", false, false),
            ("foo://h:/x", true, true),
            ("foo://h:99999/x", true, true),
        ];

        for (value, valid, absolute) in cases {
            assert_eq!(is_uri(value), valid, "URI syntax for {value:?}");
            assert_eq!(
                is_absolute_uri(value),
                absolute,
                "absolute URI for {value:?}"
            );
        }
    }

    #[test]
    fn accepts_additional_rfc3986_authority_forms_without_normalizing() {
        for value in ["foo://user:pass@h/path", "foo://[v1.a]/", "foo:////////"] {
            assert!(is_uri(value), "{value}");
            assert!(is_absolute_uri(value), "{value}");
        }
        assert!(!is_uri("foo://h/?q=[x]"));
        assert!(!is_uri("foo:///[]"));
    }

    #[test]
    fn requires_an_https_authority_without_userinfo_or_fragment() {
        for value in [
            "https://example.com/",
            "HTTPS://example.com/policy",
            "https://example.com:/policy",
            "https://example.com:99999/policy",
        ] {
            assert!(is_https_uri(value), "{value}");
        }
        for value in [
            "https:/example.com/policy",
            "https:///policy",
            "https://:443/policy",
            "https://user@example.com/policy",
            "https://example.com/policy#",
            "http://example.com/policy",
        ] {
            assert!(!is_https_uri(value), "{value}");
        }
    }
}
