# CVD Policy Format Version 1 Candidate

**Status:** Experimental pre-standard candidate  
**Format version:** `1`  
**Date:** 2026-09-01
**License:** CC0-1.0  
**Translation:** [Deutsch (informative)](SPEC.de.md)

This document is the normative English specification for the Version 1 candidate. It is intended to inform a possible initial Internet-Draft and can change before or during IETF review. It is not an RFC and does not represent IETF consensus.

## 1. Conventions and terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are interpreted as described by BCP 14 (RFC 2119 and RFC 8174) only when they appear in capitals.

Each normative requirement has a stable identifier in square brackets. `v1/requirements.json` maps every identifier to executable tests.

- **Publisher:** the party publishing a policy.
- **Discovery host:** the normalized host originally used to retrieve `security.txt`, before redirects.
- **Policy URI:** the URI in the proposed `CVD-Policy` field.
- **Target:** an absolute HTTP(S) URL evaluated for one activity.
- **Authority evidence:** the result of successfully assessing `security.txt`; it is not an ownership certificate.
- **Reporting scope:** assets and products for which reports are accepted.
- **Testing permission:** an explicit publisher statement in a matching testing rule.

## 2. Status and non-goals

[DOC-001] A Version 1 document MUST contain the JSON number `1` in `cvd_policy`; strings and 0.x values are not Version 1.

[DOC-017] A missing or non-integer `cvd_policy` member MUST produce `invalid-policy`. An unknown integer version MUST produce `unsupported-policy`.

[DOC-002] Implementations MUST keep package versions separate from the document format version.

`CVD-Policy` and `application/cvd-policy+json` are proposed identifiers and are not registered by IANA. Version 1 is a pre-standard candidate, not a stable or published standard.

This format does not:

- prove ownership or control of an asset;
- provide legal advice, legal authorization, or guaranteed safe harbor;
- cause software to perform testing;
- define vulnerability-report submission, authentication, retries, attachments, or transport;
- replace the human-readable `Policy` field in RFC 9116;
- define product-version range syntax.

A structured report-submission protocol can be specified separately in the future. A contact URI may point to an existing form without making that form part of this format.

## 3. JSON processing and validation layers

[DOC-003] Policy text MUST be UTF-8 JSON conforming to RFC 8259, with exactly one top-level value that is an object.

[DOC-004] A parser MUST reject comments, trailing commas, multiple JSON texts, non-JSON numbers, and duplicate member names at every nesting level.

[DOC-005] Automatic discovery and evaluation MUST use a duplicate-aware text parser before ordinary object validation.

A JavaScript object supplied after `JSON.parse` cannot be checked retrospectively for duplicate members. Object validation can still perform schema and semantic checks but cannot claim duplicate-member safety.

Validation has four distinct layers:

1. text parsing and duplicate detection;
2. format-version selection and JSON Schema validation;
3. semantic validation;
4. expiry, supported-extension, authority, target, scope, rule, and condition evaluation.

[DOC-006] A validator MUST NOT insert defaults or coerce types while validating a Version 1 document.

[DOC-007] Every core object MUST reject unknown properties; extension data is allowed only under `extensions`.

## 4. Document model

Required top-level members are:

```text
cvd_policy
last_updated
expires
organization
contact
research
reporting_scope
reporting
```

Optional members are:

```text
testing
response_targets
disclosure
critical_extensions
extensions
```

[DOC-008] Missing optional members MUST NOT create testing permission. In particular, missing `testing` means no testing permission.

[DOC-019] Core object members are exactly as follows; every unlisted member is forbidden by [DOC-007]:

| Object | Required members | Optional members |
| --- | --- | --- |
| policy | `cvd_policy`, `last_updated`, `expires`, `organization`, `contact`, `research`, `reporting_scope`, `reporting` | `testing`, `response_targets`, `disclosure`, `critical_extensions`, `extensions` |
| `organization` | `name` | `uri` |
| `contact` | `channels` | `preferred_languages`, `encryption` |
| `research` | `posture` | `statement` |
| `reporting_scope` | at least one of `web`, `products` | the other listed member |
| web scope entry | `id`, `state`, `host`, `schemes`, `path_prefix`, `include_subdomains` | `ports` |
| product scope entry | `id`, `state`, `name` | `identifiers` |
| `testing` | `rules` | none |
| testing rule | `id`, `activity`, `state` | `target_ids`, `conditions`, subject to [TEST-004] and [TEST-008] |
| `conditions` | at least one defined condition member | the other defined condition members |
| `reporting` | `requested_fields`, `proof_of_exploitation` | none |
| `response_targets` | at least one defined response-target member | the other defined response-target members |
| `disclosure` | `approach` | `default_days`, `statement` |
| `extensions` | none | absolute-URI member names with extension-defined values |

Arrays declared non-empty elsewhere MUST contain at least one item. `reporting.requested_fields`, `contact.preferred_languages`, `contact.encryption`, and `critical_extensions` MAY be empty; all other optional arrays, when present, MUST be non-empty.

### 4.1 Time

`last_updated` and `expires` are RFC 3339 date-time strings.

[DOC-009] `expires` MUST represent an instant strictly later than `last_updated`.

[DOC-010] An expired policy MUST produce the normative status `invalid-policy` and MUST NOT produce testing permission. A detailed expiry diagnostic is informative and implementation-specific.

Evaluation accepts an injected `now`. A lifetime of approximately one year is a non-normative operational recommendation, not a validation limit.

### 4.2 Organization

```json
{
  "name": "Example Organization",
  "uri": "https://example.com/"
}
```

[DOC-011] `organization.name` MUST be a non-empty string.

[DOC-012] If present, `organization.uri` MUST be an absolute HTTPS URI without userinfo.

Organization metadata does not establish authority.

### 4.3 Contact

```json
{
  "channels": [
    "mailto:security@example.com",
    "https://example.com/security/contact"
  ],
  "preferred_languages": ["en", "de"],
  "encryption": ["https://example.com/security/pgp-key.txt"]
}
```

[DOC-013] `contact.channels` MUST be non-empty. Every entry MUST be an absolute URI using only the `mailto`, `tel`, or `https` scheme, and the array MUST NOT contain an identical duplicate.

[DOC-014] HTTPS contact URIs MUST NOT contain userinfo or a fragment.

Channel order expresses preference. Language order does not.

[DOC-015] Every `preferred_languages` value MUST be a valid BCP 47 language tag.

[DOC-016] `encryption` values MUST be absolute URIs and MUST contain references rather than embedded key material.

### 4.4 Research posture

`research.posture` is one of:

- `open`: research is generally welcomed, but only matching explicit rules state testing permission;
- `limited`: research is welcomed only under explicit rules;
- `report_only`: reports are accepted and active testing under this policy is not permitted;
- `prohibited`: the publisher states that active testing is prohibited.

[TEST-001] `open` MUST NOT imply permission without a matching `permitted` testing rule.

[TEST-002] A `report_only` or `prohibited` policy MUST NOT contain a `permitted` testing rule.

`research.statement` is explanatory text and has no evaluation effect.

### 4.5 Reporting scope

`reporting_scope` describes reportable assets and products. It does not itself state testing permission.

[SCOP-001] Every scope and testing-rule `id` MUST be unique across the document.

[DOC-018] Every scope and rule ID MUST be 1 through 128 ASCII characters, start with an ASCII letter or digit, and otherwise contain only ASCII letters, digits, `.`, `_`, or `-`. IDs and ID references are compared as exact case-sensitive strings.

#### 4.5.1 Web entries

```json
{
  "id": "main-web",
  "state": "in",
  "host": "example.com",
  "schemes": ["https"],
  "ports": [443],
  "path_prefix": "/",
  "include_subdomains": false
}
```

[SCOP-002] `host` MUST be a normalized DNS name, IPv4 literal, or IPv6 literal without scheme, port, path, userinfo, wildcard, query, or fragment.

[SCOP-003] DNS names MUST be converted to lowercase ASCII A-label form for comparison, and one trailing dot MUST be removed.

[SCOP-004] IPv4 and IPv6 literals MUST be compared in canonical form and an IP entry MUST set `include_subdomains` to `false`.

[SCOP-005] `schemes` MUST contain at least one of `http` or `https` and no other scheme.

If `ports` is absent, only the default port for the matched scheme applies: 80 for HTTP and 443 for HTTPS. A non-default port is in scope only when explicitly listed.

[SCOP-006] `path_prefix` MUST begin with `/` and MUST NOT contain query or fragment syntax.

[SCOP-010] Scope `path_prefix` and Target paths MUST use the same normalization: an empty path becomes `/`; RFC 3986 dot-segments are removed; repeated slashes are preserved; hexadecimal digits in percent-encoded triplets are converted to uppercase; and no percent-encoded octet is decoded for matching. A percent sign not followed by exactly two hexadecimal digits is invalid. An encoded slash therefore remains distinct from `/`.

Path matching uses the normalized URL pathname without query or fragment. It is case-sensitive. `/` matches every path. A prefix ending in `/` matches paths beginning with that prefix. Any other prefix matches the exact path or that prefix followed by `/`. Thus `/api` matches `/api`, `/api/`, and `/api/v1`, but not `/apix`.

`include_subdomains: true` matches proper DNS subdomains on label boundaries as well as the named host. It does not establish authority for those hosts; each target host still needs its own discovery evidence.

[SCOP-007] A matching `out` entry MUST override every matching `in` entry regardless of array order.

[SCOP-008] Scope and rule array order MUST NOT change an evaluation result.

#### 4.5.2 Product entries

```json
{
  "id": "example-product",
  "state": "in",
  "name": "Example Product",
  "identifiers": ["pkg:npm/example-product"]
}
```

[SCOP-009] Product entries MUST be treated only as reporting metadata and MUST NOT produce automatic testing permission.

Product identifiers MUST be absolute RFC 3986 URIs, compared as exact case-sensitive strings without scheme-specific equivalence processing. Version-range syntax is outside Version 1.

### 4.6 Testing rules

Core activities are:

- `manual_testing`: manually initiated investigation not covered by a more specific core activity;
- `automated_scanning`: automated detection or vulnerability checking against a web or network service;
- `fuzzing`: automated transmission of generated or mutated inputs;
- `credential_testing`: testing only with researcher-controlled or explicitly provided test accounts; credential stuffing, password spraying, and third-party credentials are excluded.

[TEST-003] An extension activity identifier MUST be an absolute URI; an unknown unqualified token such as `automated_scaning` is invalid. Activity identifiers, including extension URI identifiers, are compared as exact case-sensitive strings.

Rules use `state: permitted` or `state: prohibited`. Version 1 does not define `allowed`, `testing.default`, or `explicit_order`.

[TEST-004] A `permitted` rule MUST contain at least one `target_id`.

[TEST-005] A `prohibited` rule without `target_ids` MUST apply to every web target in reporting scope.

[TEST-006] Every `target_id` MUST reference an existing web entry whose state is `in`; product and `out` references are invalid.

[TEST-007] A matching `prohibited` rule MUST override every matching `permitted` rule.

[TEST-008] A `prohibited` rule MUST NOT contain `conditions`; a prohibition is unconditional once the rule applies.

No matching rule means no testing permission.

#### 4.6.1 Conditions

Version 1 defines only:

- `max_requests_per_second`: positive number;
- `max_concurrent_requests`: positive integer;
- `required_user_agent_token`: non-empty visible ASCII string, matched case-sensitively as a complete substring of the planned User-Agent;
- `test_accounts_only`: the literal `true`.

[COND-001] Unknown properties in `conditions` MUST make the policy structurally invalid.

[COND-002] A permitted `automated_scanning` or `fuzzing` rule MUST include both rate and concurrency limits.

[COND-003] A permitted `credential_testing` rule MUST include both limits and `test_accounts_only: true`.

[COND-004] A client MUST treat a missing planned value required by a condition as unsatisfied and MUST NOT ignore an unknown condition.

A condition is satisfied only when the planned rate and concurrency are present and no greater than their limits, the User-Agent contains the required token, and use of only controlled or provided test accounts is explicitly confirmed when required.

### 4.7 Reporting preferences

`reporting.requested_fields` contains zero or more of:

```text
affected_asset
vulnerability_type
description
reproduction_steps
impact
environment
evidence
researcher_contact
disclosure_preference
```

[REP-001] Requested fields MUST be interpreted as preferences; a missing requested field MUST NOT by itself cause a report to be rejected.

`proof_of_exploitation` is `not_requested`, `requested_if_safe`, or `prohibited`.

[REP-002] `requested_if_safe` MUST NOT be interpreted to request access to third-party data, persistence, exfiltration, lateral movement, damage, availability impairment, or further exploitation.

### 4.8 Response targets and disclosure

`response_targets` may contain only positive-integer `acknowledgement_days`, `initial_assessment_days`, and `update_interval_days`. Acknowledgement and initial-assessment periods start when the publisher receives the initial report; each update interval starts when the preceding substantive update is sent. They are published targets, not technical or legal guarantees, and do not affect testing evaluation.

`disclosure.approach` is `coordinated`, `case_by_case`, or `no_preference`. Optional positive-integer `default_days` starts when the publisher receives the initial report and is a coordination preference, not automatic permission to disclose. Optional `statement` is explanatory.

### 4.9 Extensions

Extension identifiers are absolute RFC 3986 URIs and are compared as exact case-sensitive strings. Extension data is stored only as values in `extensions`; `critical_extensions` is an array of unique extension identifiers.

[EXT-001] Every identifier in `critical_extensions` MUST have a same-named member in `extensions`.

[EXT-002] An unknown critical extension MUST produce `unsupported-policy` for permission evaluation.

[EXT-003] An unknown non-critical extension MAY be ignored as metadata and MUST NOT weaken a core prohibition or condition.

[EXT-004] An extension that changes permission, prohibition, or conditions MUST be listed as critical.

#### CSAF Vulnerability Report declaration

This optional, non-critical declaration identifies existing contact channels at which a publisher states that it accepts reports conforming to the CSAF Vulnerability Report Profile. It does not define report transmission, a submission API, or CSAF report validation. Core policy implementations are not required to process it.

The extension identifier is `https://github.com/cvd-policy/spec/extensions/csaf-vulnerability-report-v1`. The supported specification URI is `https://docs.oasis-open.org/csaf/csaf/v2.1/csd04/csaf-v2.1-csd04.html`, binding the declaration to Profile 9, Vulnerability Report, Section 4.9 of CSAF Version 2.1 Committee Specification Draft 04 (21 October 2026, work in progress). Implementations compare the specification as an exact case-sensitive string after JSON decoding. The corresponding CSAF report has `document.csaf_version` `2.1` and `document.category` `csaf_vulnerability_report`.

The extension value contains only a non-empty `channels` array. Each item contains only string members `uri` and `specification`. A URI exactly matches one `contact.channels` value after JSON decoding, uses `mailto` or `https`, and occurs at most once. Matching does not normalize URIs or resolve redirects. `tel` is not allowed. The extension array order has no meaning; selection preserves `contact.channels` order. Each specification is an absolute RFC 3986 URI. A syntactically valid URI other than the supported value is unsupported, not structurally invalid. The identifier and specification are not fetched.

[CSR-001] The one supported value of `specification` MUST be the exact CSAF 2.1 CSD04 URI above.

[CSR-002] The extension object MUST contain only the required non-empty `channels` array of objects with exactly the required string members `uri` and `specification`.

[CSR-003] Each `uri` MUST exactly match a contact channel after JSON decoding, use `mailto` or `https`, and occur at most once; no URI normalization or redirect resolution is performed.

[CSR-004] Extension channel order has no meaning; clients selecting channels MUST preserve the preference order of `contact.channels`.

[CSR-005] Each `specification` MUST be an absolute RFC 3986 URI; a valid URI other than the exact supported binding is unsupported.

[CSR-006] Assessment MUST NOT fetch the extension identifier or `specification` URI.

Assessment is separate from core validation and Testing Permission. Duplicate member names remain global policy errors. After successful text parsing, version selection, core structural validation, and core semantic validation, the assessment order is:

1. Missing extension data yields `not-advertised`.
2. Any declaration structure, URI, uniqueness, or contact-reference error yields `invalid`. Check these errors before unsupported specifications.
3. A critical declaration or a syntactically valid unsupported specification yields `unsupported`.
4. Otherwise the result is `advertised` for all listed channels.

Results are atomic. No channels are usable for `not-advertised`, `invalid`, or `unsupported`, and partial success is forbidden. These states do not assert rejection of CSAF reports.

[CSR-007] Assessment MUST use the order and atomicity above.

[CSR-008] This extension MUST NOT appear in `critical_extensions`; if it does, a recognizing implementation MUST treat its use as unsupported critical behavior at permission-evaluation step 6, unless an earlier step determines the result.

[CSR-009] Errors in a non-critical declaration MUST NOT alter core validity or Testing Permission. Declaration assessment remains separate from core structural and semantic validation, without relaxing duplicate-key or core-member rules.

[CSR-010] Before using an advertised result as a current Discovery Host statement, a client MUST verify valid Authority and bound policy retrieval, freshness of the policy and `security.txt`, and supported critical behavior. This requires no Target, activity, or positive Testing Permission. A `report_only` policy can advertise CSAF support.

[CSR-011] A publisher MUST list only channels at which it offers to receive reports conforming to the bound CSAF profile. The declaration is its statement of that offer. A client MUST NOT present a valid declaration as proof that a channel was tested, a report conforms to CSAF, or a finding was accepted or confirmed.

[CSR-012] The declaration does not specify report transmission, a request method, an intake API, authentication, attachment handling, acknowledgements, or case management. In particular, a client MUST NOT infer that a declared HTTPS contact URI is a POST endpoint or that reading the declaration authorizes report transmission.

[CSR-013] The declaration MUST NOT require CSAF for every report or justify rejecting human-readable reports. Core reporting preferences remain unchanged; CSAF requirements govern CSAF conformance only.

[CSR-014] A client MUST NOT infer CSAF publisher identity, affected status, or vulnerability from policy organization or scope. Reporting Scope does not establish vulnerability. The `CSAF` field in `security.txt` is for discovery of provider metadata for distribution, not report reception or an intake endpoint; policy extensions are separate from CSAF extensions.

## 5. Discovery with security.txt

The proposed field is:

```text
CVD-Policy: https://example.com/cvd-policy.json
```

[DISC-001] A `CVD-Policy` value MUST be exactly one absolute HTTPS URI without userinfo or fragment.

[DISC-002] Field names MUST be parsed case-insensitively and automatic processing MUST reject multiple `CVD-Policy` fields rather than choosing one.

[DISC-003] A consumer MUST NOT guess `/.well-known/cvd.json` or any other policy path when the field is missing.

The policy host may differ from the discovery host. Filename and extension have no normative meaning. Existing `Policy` fields remain human-policy links; their order and multiplicity are preserved.

`CVD-Policy` is proposed and unregistered. A local generator can suggest `https://example.com/cvd-policy.json`, but that path is not a discovery default.

### 5.1 Assessing security.txt

Assessment input includes:

```ts
interface SecurityTxtRetrievalContext {
  requestedUri: string;
  finalUri: string;
  redirectChain: string[];
  retrievedAt: Date;
}
```

[DISC-004] Authority evidence MUST NOT be created unless the file is parseable, contains at least one valid `Contact`, exactly one syntactically valid `Expires` whose timestamp is later than `retrievedAt`, and exactly one valid `CVD-Policy`. A malformed `Expires` and a valid but expired `Expires` are distinct diagnostic conditions, but neither establishes authority.

[DISC-005] Retrieval context URIs and every redirect hop MUST use HTTPS and redirect processing MUST preserve the original discovery host.

For a redirect whose final host differs from the requested host, at least one valid `Canonical` field in the resulting file has to equal the originally requested security.txt URI.

[DISC-006] A cross-host security.txt redirect without that exact original `Canonical` value MUST NOT establish authority. Any detailed canonical-mismatch diagnostic is informative and implementation-specific.

[DISC-008] Whenever one or more `Canonical` fields are present, at least one value MUST exactly equal the originally requested security.txt URI before authority is established. This applies without redirects and to same-host redirects.

OpenPGP cleartext signatures are recognized by their RFC 9116 framing. This specification does not require core software to verify them.

[DISC-007] Software that cannot genuinely re-sign a signed security.txt MUST NOT rewrite it automatically.

## 6. Authority model

[AUTH-001] Automatic permission evaluation MUST require an `AuthorityEvidence` object produced by successful security.txt assessment; a caller-supplied host string alone is insufficient.

Authority evidence contains:

```ts
interface AuthorityEvidence {
  established: true;
  discoveryHost: string;
  securityTxtUri: string;
  cvdPolicyUri: string;
  securityTxtExpires: string;
}
```

[AUTH-002] The discovery host MUST remain the host from the originally requested security.txt URI, regardless of security.txt redirects, policy hosting, or policy redirects.

[AUTH-003] The normalized target host MUST exactly equal the normalized discovery host before a positive permission status is possible.

[AUTH-004] Parent domains, subdomains, CNAME targets, shared addresses, shared certificates, organization claims, scope wildcards, policy location, filenames, and redirects MUST NOT create or transfer authority.

[AUTH-005] Authority evidence MUST be bound to its advertised `cvdPolicyUri`. The evaluated policy representation MUST have been retrieved from that exact URI or from the final URI of its recorded all-HTTPS redirect chain. An evaluator MUST NOT combine arbitrary policy JSON with authority evidence for another Policy URI.

A different port on the same exact host can be covered when reporting scope explicitly matches it. Two discovery hosts can independently point to one centrally hosted policy, but each evaluation uses evidence from that host's own discovery.

## 7. Policy representation retrieval

The proposed, unregistered media type is `application/cvd-policy+json`.

[FETCH-001] Network clients MUST accept `application/cvd-policy+json`. A separately enabled compatibility mode MAY accept `application/json` with a notice; this mode MUST NOT broaden acceptance to other media types. HTML, plain text, and other unexpected representations MUST be rejected for automatic evaluation.

[FETCH-002] A network client MUST retrieve a Policy URI with HTTPS `GET` as defined by RFC 9110, send an `Accept` field preferring `application/cvd-policy+json` (and listing `application/json` only when compatibility mode is enabled), and accept only a `200 OK` response as a complete policy representation. `204 No Content`, `206 Partial Content`, and every other status are not complete policy representations. Every redirect hop MUST use HTTPS. A client MUST NOT automatically send ambient credentials, cookies, `Authorization`, or `Proxy-Authorization`, and MUST NOT forward such fields across redirects.

Local files have no HTTP media type. Finite redirect limits, timeouts, response-size limits, address filtering, and credential isolation belong in clients or adapters. Deterministic core evaluation validates supplied retrieval evidence and does not perform network requests.

## 8. Evaluation

### 8.1 Query and result

```ts
interface EvaluationQuery {
  activity: string;
  target: string;
  plan?: {
    requestsPerSecond?: number;
    concurrentRequests?: number;
    userAgent?: string;
    usesOnlyTestAccounts?: boolean;
  };
  understoodExtensions?: string[];
}
```

`target` accepts only an absolute HTTP or HTTPS URL without userinfo. Product identifiers and all other URI schemes are not evaluation targets. Scheme and host are normalized by the URL parser; omitted ports become 80 or 443; query and fragment do not affect scope matching.

Target syntax is validated before policy evaluation. Invalid target input produces a typed input-validation failure with machine-readable issues and no evaluation status. It MUST NOT produce `not-covered` or any other normative evaluation status.

A completed policy evaluation produces exactly one of these seven normative statuses:

```text
publisher-stated-permitted
publisher-stated-prohibited
not-covered
authority-not-established
conditions-not-satisfied
invalid-policy
unsupported-policy
```

[EVAL-001] The primary public result MUST NOT be a Boolean named `allowed`, `authorized`, or `safe`.

[EVAL-002] Calling software MUST treat every status other than `publisher-stated-permitted` as no established testing permission.

`publisher-stated-permitted` means only that the policy published through established discovery contains a matching permission statement whose machine-checkable conditions are satisfied. It is not legal advice, proof of ownership, authorization by this software, or guaranteed safe harbor.

A status-bearing result can contain sorted matching rule and target IDs, validation issues, and implementation-specific diagnostics. Detailed diagnostic identifiers are not part of the normative interoperability contract.

[EVAL-005] If one or more applicable `permitted` rules are fully satisfied, the result MUST be `publisher-stated-permitted`. Implementations MAY report all satisfied rule IDs informatively. Draft 00 defines neither lexicographic rule selection nor one aggregated constraint object; callers retain each satisfied rule's own conditions.

### 8.2 Required order

[EVAL-003] After successful target input validation and normalization, an evaluator MUST perform these steps in order:

1. duplicate-aware JSON parsing;
2. format-version check;
3. JSON Schema validation;
4. semantic validation;
5. policy expiry check;
6. unknown critical-extension check;
7. authority-evidence and policy-retrieval binding check;
8. exact target/discovery-host check;
9. reporting-scope matching;
10. `out` exclusion;
11. research-posture check;
12. matching-rule collection;
13. prohibition precedence;
14. all permitted-rule condition evaluation;
15. stable status-bearing result construction.

### 8.3 Status precedence

The first applicable outcome in evaluation order wins:

- `invalid-policy`: parse, duplicate, schema, semantic, reference, posture conflict, target-independent policy error, or expiry failure;
- `unsupported-policy`: unsupported format version, unknown critical extension, or requested extension activity not understood by the client;
- `authority-not-established`: missing/invalid authority evidence or target/discovery-host mismatch;
- `not-covered`: a syntactically valid normalized target has no matching `in` web scope, matches an `out` web scope, or has no matching testing rule;
- `publisher-stated-prohibited`: `report_only`, `prohibited`, or a matching prohibited rule;
- `conditions-not-satisfied`: permitted rules match but none has all conditions satisfied;
- `publisher-stated-permitted`: at least one permitted rule is fully satisfied and no earlier outcome applies.

[EVAL-004] A positive status MUST require a valid unexpired policy, supported critical behavior, established authority, exact target/discovery host equality, matching `in` scope, no matching `out`, no matching prohibition, and one fully satisfied permitted rule.

## 9. Machine-readable errors and informative diagnostics

[ERR-001] Input-validation and policy-processing failures MUST be machine-readable and identify affected locations when available. Localized prose MUST NOT be the only API contract. Implementations are not required to use identical detailed diagnostic identifiers.

[ERR-002] Only failures that validate evaluation-call input, such as an invalid Target URL, are structurally outside status-bearing evaluation results. Policy parsing, version dispatch, schema, semantic, reference, and expiry failures remain normal status-bearing results; in particular, `invalid-policy` is a normative evaluation status.

The following identifiers are informative diagnostics used by the reference implementation. They are not a normative registry and conformance does not require another implementation to emit them:

```text
policy_parse_error
policy_duplicate_member
policy_schema_invalid
policy_version_unsupported
policy_time_order_invalid
policy_expired
policy_uri_invalid
policy_language_tag_invalid
policy_scope_invalid
policy_scope_id_duplicate
policy_target_reference_invalid
policy_posture_conflict
policy_critical_extension_missing
policy_critical_extension_unsupported
policy_activity_unsupported
security_txt_parse_error
security_txt_contact_missing
security_txt_contact_invalid
security_txt_expires_missing
security_txt_expires_duplicate
security_txt_expires_invalid
security_txt_expired
security_txt_cvd_policy_missing
security_txt_cvd_policy_duplicate
security_txt_cvd_policy_uri_invalid
security_txt_canonical_mismatch
security_txt_redirect_invalid
authority_evidence_missing
authority_host_mismatch
target_url_invalid
scope_target_not_covered
scope_target_excluded
testing_rule_missing
testing_rule_prohibited
testing_rule_permitted
conditions_missing
conditions_exceeded
conditions_user_agent_missing
conditions_test_accounts_unconfirmed
```

`target_url_invalid` belongs to a typed input-validation failure and never carries a normative evaluation status. `policy_condition_invalid` is omitted because Version 1 defines no distinct cross-field condition failure beyond schema validation and the existing specific semantic diagnostics.

## 10. Security considerations

[SEC-001] Every security-sensitive ambiguity in parsing, authority, scope, rule matching, conditions, or extensions MUST fail closed.

A compromised host can publish misleading data. Authority evidence records publication through that host; it does not prove ownership, organizational control, or legal permission. Consumers should corroborate high-risk decisions independently.

Policies and security.txt files are untrusted input. Network clients should enforce HTTPS, redirect and body limits, timeouts, media types, no credential forwarding, and default blocking of loopback, link-local, private, reserved, and metadata addresses.

Rate and concurrency values describe publisher statements; this project does not execute scans or enforce remote systems. A parser should bound input size, nesting, and resource use.

## 11. Privacy considerations

[PRIV-001] Implementations MUST NOT transmit policy text, security.txt text, target details, or researcher plan data unless the user explicitly invokes a network operation that requires it.

Contact and researcher information can be personal data. Interfaces should minimize retention, avoid analytics and tracking, and explain where network requests go. `requested_if_safe` never justifies collecting third-party data or extending exploitation.

## 12. IANA considerations

This candidate requests no registration. A future Internet-Draft can request registration of the proposed `CVD-Policy` security.txt field and `application/cvd-policy+json` media type. No well-known policy URI is defined by Version 1.
