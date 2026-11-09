---
title: Machine-Readable Coordinated Vulnerability Disclosure Policies
abbrev: Machine-Readable CVD Policies
docname: draft-behring-cvd-policy-01
date: 2026-11-08
category: std
ipr: trust200902
area: Security
keyword: Internet-Draft
stand_alone: true
submissiontype: IETF
pi: [toc, sortrefs, symrefs]

author:
  - ins: B. L. Behring
    name: Ben Luca Behring
    org: Skalvar Technologies
    email: behring@skalvar.de
    country: Germany
  - ins: M. Berg
    name: Marco Berg
    org: Skalvar Technologies
    email: berg@skalvar.de
    country: Germany

normative:
  RFC2119:
  RFC3339:
  RFC3986:
  RFC5646:
  RFC5890:
  RFC5891:
  RFC5952:
  RFC6838:
  RFC6839:
  RFC8174:
  RFC8259:
  RFC9110:
  RFC9116:
  CSAF-2.1-CSD04:
    title: Common Security Advisory Framework Version 2.1
    author:
      - ins: S. Hagen
        name: Stefan Hagen
        role: editor
      - ins: T. Schmidt
        name: Thomas Schmidt
        role: editor
    date: 2026-10-21
    seriesinfo:
      OASIS: Committee Specification Draft 04
    refcontent: Work in Progress
    target: https://docs.oasis-open.org/csaf/csaf/v2.1/csd04/csaf-v2.1-csd04.html
informative:
  RFC7942:
  RFC8615:
  RFC8792:
  JSON-SCHEMA-2020-12:
    title: JSON Schema Core, Draft 2020-12
    target: "https://json-schema.org/draft/2020-12/json-schema-core.html"
  CVD-POLICY-SPEC:
    title: CVD Policy Version 1 Specification, Schema, and Conformance Corpus
    target: "https://github.com/cvd-policy/spec/commit/e8b26c05482c2cee9872adcc8fa2fd18b2e53214"
    date: 2026-09-03
  CVD-POLICY-CORE:
    title: TypeScript Reference Implementation for CVD Policy Version 1
    target: "https://github.com/cvd-policy/web/commit/0221629e2bb6702ccc24ddb84fcaf5dc7df87c8d"
    date: 2026-09-29

--- abstract

This document defines a JSON format for machine-readable Coordinated
Vulnerability Disclosure (CVD) policies.  It also defines the proposed
`CVD-Policy` field for discovery through `security.txt` and requests
registration of the `application/cvd-policy+json` media type.  The format
complements `security.txt` and human-readable policy documents.  A policy does
not prove ownership and does not establish legal authorization to test, legal
safe harbor, or the safety of an activity.

An optional extension lets a publisher identify contact channels for reports
conforming to the CSAF Vulnerability Report Profile. This declaration does not
define report transport or change the policy's testing statements.

--- middle

# Introduction

Coordinated Vulnerability Disclosure depends on publishers communicating where
reports are accepted and under which conditions security research is expected.
`security.txt` {{RFC9116}} provides standardized discovery of contact and
human-readable policy information, but it does not define a machine-readable
policy model for scope, testing statements, or conditions.

This document defines a strict JSON policy format, discovery by a proposed
`security.txt` field, retrieval and authority rules, deterministic scope and
testing evaluation, and an extension model.  The format records statements made
by a publisher.  It does not determine ownership, legal authorization, or legal
safe harbor.

A policy and a vulnerability report serve different purposes. The policy
describes a publisher's standing instructions. A report describes a particular
finding. This document uses the Common Security Advisory Framework (CSAF)
{{CSAF-2.1-CSD04}} for the structured report-format declaration in
{{csaf-reporting}}; it does not define a competing report schema.

The proposed field and media type are not registered at the time this document
is written.  The registrations requested by this document are specified in
{{iana-considerations}}.

# Conventions and Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals.

This document uses the following terms:

Publisher:
: The party that publishes a CVD policy.

Discovery Host:
: The normalized host from the URI originally used to retrieve `security.txt`,
  before redirects.

Policy URI:
: The URI carried by the proposed `CVD-Policy` field.

Target:
: An absolute HTTP or HTTPS URL evaluated for one testing activity.

Authority:
: Evidence that a policy was discovered through an assessed `security.txt` for
  the exact Discovery Host.  Authority is not an ownership certificate.

Reporting Scope:
: Assets and products for which the publisher states that reports are accepted.

Testing Permission:
: An explicit publisher statement in a matching testing rule whose conditions
  are satisfied.

# Problem Statement

Human-readable policies cannot be evaluated consistently by automated clients.
A client needs to distinguish reporting scope from testing permission, bind a
policy to the host that actually advertised it, reject ambiguous JSON, apply
exclusions and prohibitions independently of array order, and fail closed when
conditions or critical extensions are not understood.

A JSON document fetched from an arbitrary location cannot establish authority
for the hosts it names.  Without discovery-host binding, a compromised or
unrelated host could publish statements about third-party targets.  Without
strict result semantics, a UI or automation could also turn an incomplete
publisher statement into an unsafe Boolean decision.

# Design Goals and Non-Goals

The design goals are:

- deterministic parsing, validation, scope matching, and evaluation;
- exact binding between a Target host and its Discovery Host;
- separation of Reporting Scope from Testing Permission;
- fail-closed processing of conditions, prohibitions, and critical extensions;
- support for one policy document referenced independently by multiple hosts;
- useful reporting preferences without defining report transport;
- a precise declaration of CSAF report support for existing contact channels,
  without requiring a report-processing implementation; and
- machine-readable status and diagnostic values that do not claim legal effect.

The following are outside the scope of this document:

- vulnerability-report transmission and intake endpoints;
- attachment upload, report authentication, and ticket or case management;
- website architecture, command-line interfaces, TypeScript APIs, and package
  versioning;
- legal authorization to test or guaranteed safe harbor; and
- an Activity or extension registry in this revision.

Version 1 does not define a state named `allowed`, a default testing decision, an
explicit-order mode, or order-dependent first-match processing.  Software
package versions are independent of the document format version.

<!-- requirements: DOC-002; disposition: normative -->

# Discovery Using security.txt

A publisher advertises a Policy URI with the proposed `CVD-Policy` field in the
`security.txt` file defined by {{RFC9116}}.  Field names are compared
case-insensitively.  `CVD-Policy` contains exactly one absolute HTTPS URI as
specified by {{RFC3986}}.  The
URI MUST NOT contain userinfo or a fragment.

A `security.txt` file MUST contain no more than one `CVD-Policy` field.
Automatic processing MUST reject multiple appearances and MUST NOT choose one
by field order.  The existing `Policy` field remains the mechanism for linking
to a human-readable policy.

<!-- requirements: DISC-001 DISC-002; disposition: normative -->

A client MUST NOT guess `/.well-known/cvd.json` or any other policy path when
`CVD-Policy` is absent.  This document does not request a new well-known URI
suffix {{RFC8615}}.

<!-- requirements: DISC-003; disposition: normative -->

Before creating Authority evidence, a client MUST successfully parse and assess
the retrieved `security.txt`.  The file MUST contain at least one valid
`Contact`, exactly one syntactically valid `Expires` whose timestamp is later
than the retrieval time, and exactly one valid `CVD-Policy`.  A malformed
`Expires` and a valid but expired `Expires` are distinct diagnostic conditions.
Neither condition establishes Authority.

<!-- requirements: DISC-004; disposition: normative -->

The originally requested `security.txt` URI, the final URI, and every redirect
hop MUST use HTTPS.  Redirect processing MUST preserve the original Discovery
Host.  If the final host differs from the originally requested host, at least
one valid `Canonical` field in the resulting file MUST exactly equal the
originally requested `security.txt` URI.  Otherwise, assessment MUST NOT
establish Authority.  Detailed canonical-mismatch diagnostics are
implementation-specific and informative.

Whenever one or more `Canonical` fields are present, at least one value MUST
exactly equal the originally requested `security.txt` URI before Authority is
established.  This requirement applies without a redirect and to same-host
redirects.

<!-- requirements: DISC-005 DISC-006 DISC-008; disposition: normative -->

An OpenPGP cleartext signature can protect `security.txt` as described by
{{RFC9116}}.  Software that cannot genuinely re-sign a signed file MUST NOT
rewrite it automatically.  Core assessment software is not required to verify
such signatures; a client claiming signature verification has to perform that
verification independently.

<!-- requirements: DISC-007; disposition: normative -->

External hosting of the JSON policy is permitted.  The Policy URI host does not
become the Discovery Host and does not gain Authority over any Target.

# Policy Retrieval

The media type defined by this document is
`application/cvd-policy+json`.  Network clients MUST accept that media type.  A
separately enabled compatibility mode MAY accept `application/json` while
presenting a notice; it MUST NOT broaden acceptance to other media types.  A
client performing automatic evaluation MUST reject HTML, plain text, and other
unexpected representations.

<!-- requirements: FETCH-001; disposition: normative -->

A network client MUST retrieve the Policy URI with HTTPS `GET` as defined by
{{RFC9110}}.  It MUST send an `Accept` field preferring
`application/cvd-policy+json` and MUST list `application/json` only when the
compatibility mode is enabled.  Only `200 OK` is a complete Policy
representation.  `204 No Content`, `206 Partial Content`, and every other
status are not complete Policy representations.  Every redirect hop MUST use
HTTPS.  A client MUST NOT automatically send ambient credentials, cookies,
`Authorization`, or `Proxy-Authorization`, and MUST NOT forward such fields
across redirects.

<!-- requirements: FETCH-002; disposition: normative -->

A retrieved representation is processed as UTF-8 JSON under
{{structural-and-semantic-validation}}.  Clients should apply finite redirect,
response-size, time, and resource limits and block automatic access to
loopback, link-local, private, reserved, and metadata addresses.  Redirects of
the JSON policy do not change the Discovery Host recorded during
`security.txt` assessment.

Clients should retain the retrieval time, final Policy URI, redirect chain,
media type, and validators such as `ETag` or `Last-Modified`.  A cached policy
should not be treated as current after its `expires` instant or after the
associated `security.txt` evidence expires.

# Authority and Delegation

Automatic permission evaluation MUST require Authority evidence produced by
successful assessment of the Discovery Host's `security.txt`.  A host string
provided by a caller, organization metadata in the JSON document, or the
location from which the JSON document was retrieved is insufficient.

<!-- requirements: AUTH-001; disposition: normative -->

Authority evidence records the original Discovery Host, the assessed
`security.txt` URI, the Policy URI, and the `security.txt` expiry instant.  The
Discovery Host MUST remain the host of the originally requested `security.txt`
URI regardless of `security.txt` redirects, policy hosting, or policy
redirects.

<!-- requirements: AUTH-002; disposition: normative -->

Before a positive testing-permission status is possible, the normalized Target
host MUST exactly equal the normalized Discovery Host.

<!-- requirements: AUTH-003; disposition: normative -->

Parent domains, subdomains, CNAME targets, shared IP addresses, shared
certificates, organization claims, scope wildcards, policy location, filenames,
and redirects MUST NOT create, inherit, or transfer Authority.  Each subdomain
therefore needs discovery through its own `security.txt`.  Multiple Discovery
Hosts MAY independently reference one shared policy document; each evaluation
uses the evidence created for that exact host.

<!-- requirements: AUTH-004; disposition: normative -->

Authority evidence MUST be bound to its advertised Policy URI.  The evaluated
Policy representation MUST have been retrieved from that exact URI or from the
final URI of its recorded all-HTTPS redirect chain.  An evaluator MUST NOT
combine arbitrary Policy JSON with Authority evidence for another Policy URI.

<!-- requirements: AUTH-005; disposition: normative -->

A non-default port on the same exact host can be covered only by an explicit
Reporting Scope entry.  Port coverage does not relax the exact-host Authority
check.

# CVD Policy Document

A Version 1 policy is one JSON object with these required members:
`cvd_policy`, `last_updated`, `expires`, `organization`, `contact`, `research`,
`reporting_scope`, and `reporting`.  The optional members are `testing`,
`response_targets`, `disclosure`, `critical_extensions`, and `extensions`.
Missing optional members MUST NOT create Testing Permission.  In particular,
missing `testing` means that no Testing Permission is established.

<!-- requirements: DOC-008; disposition: normative -->

Core object members are exactly as follows.  Every unlisted member is forbidden:

- `organization` requires `name` and optionally contains `uri`;
- `contact` requires `channels` and optionally contains
  `preferred_languages` and `encryption`;
- `research` requires `posture` and optionally contains `statement`;
- `reporting_scope` contains `web`, `products`, or both;
- a web entry requires `id`, `state`, `host`, `schemes`, `path_prefix`, and
  `include_subdomains`, and optionally contains `ports`;
- a product entry requires `id`, `state`, and `name`, and optionally contains
  `identifiers`;
- `testing` requires only `rules`;
- a testing rule requires `id`, `activity`, and `state`, and optionally contains
  `target_ids` and, only when permitted, `conditions`;
- `conditions` contains one or more defined condition members;
- `reporting` requires `requested_fields` and `proof_of_exploitation` and has no
  optional members;
- `response_targets` contains one or more of `acknowledgement_days`,
  `initial_assessment_days`, and `update_interval_days`;
- `disclosure` requires `approach` and optionally contains `default_days` and
  `statement`; and
- `extensions` has absolute-URI member names and extension-defined values.

Arrays declared non-empty MUST contain at least one item.
`reporting.requested_fields`, `contact.preferred_languages`,
`contact.encryption`, and `critical_extensions` MAY be empty; other optional
arrays, when present, MUST be non-empty.

<!-- requirements: DOC-019; disposition: normative -->

## Version

The `cvd_policy` member identifies the document format.  A Version 1 document
MUST contain the JSON number `1`; the string `"1"` and every 0.x value are not
Version 1 documents.  A missing or non-integer `cvd_policy` member MUST produce
`invalid-policy`.  An unknown integer version MUST produce
`unsupported-policy`.  Implementations MUST keep software package versions
separate from this document format value.

<!-- requirements: DOC-001 DOC-017; disposition: normative -->

## Timestamps

`last_updated` and `expires` are date-time strings conforming to {{RFC3339}}.
`expires` MUST identify an instant strictly later than `last_updated`.  An
expired policy MUST produce the normative status `invalid-policy` and MUST NOT
produce Testing Permission.  Detailed expiry diagnostics are informative and
implementation-specific.  Evaluators MUST compare expiry with an explicitly
supplied or recorded evaluation time.

<!-- requirements: DOC-009 DOC-010; disposition: normative -->

## Organization

`organization` contains the required non-empty string `name` and the optional
`uri`.  If present, `uri` MUST be an absolute HTTPS URI without userinfo.
Organization metadata does not establish Authority.

<!-- requirements: DOC-011 DOC-012; disposition: normative -->

## Contact

`contact.channels` is an ordered, non-empty array of unique contact URIs.  Every
entry MUST be an absolute URI using only the `mailto`, `tel`, or `https` scheme.
An HTTPS contact URI MUST NOT contain userinfo or a fragment.  Array order
states channel preference.

`contact.preferred_languages`, when present, is an array of unique language tags
conforming to BCP 47 {{RFC5646}}.  Its order has no defined meaning.
`contact.encryption`, when present, is an array of unique absolute URIs that
reference encryption keys or instructions.  It MUST NOT embed key material.

<!-- requirements: DOC-013 DOC-014 DOC-015 DOC-016; disposition: normative -->

## Research Posture

`research.posture` is one of `open`, `limited`, `report_only`, or `prohibited`.
The optional `research.statement` is explanatory text and has no evaluation
effect.

`open` states a generally welcoming posture but MUST NOT imply Testing
Permission without a matching `permitted` rule.  `report_only` states that
reports are accepted but active testing under this Policy is not permitted.  A
policy with `report_only` or `prohibited` posture MUST NOT contain a `permitted`
testing rule.  Such a posture produces `publisher-stated-prohibited` only after
the evaluation has
established Authority and matching Reporting Scope as specified in
{{testing-permission-evaluation}}.

<!-- requirements: TEST-001 TEST-002; disposition: normative -->

## Reporting Scope

`reporting_scope` contains a non-empty `web` array, a non-empty `products`
array, or both.  Every scope-entry ID and testing-rule ID MUST be unique across
the entire document.  Every ID MUST be 1 through 128 ASCII characters, start
with an ASCII letter or digit, and otherwise contain only ASCII letters,
digits, `.`, `_`, or `-`.  IDs and references are compared as exact,
case-sensitive strings.

<!-- requirements: SCOP-001 DOC-018; disposition: normative -->

A web entry contains:

- `id`: a document-wide identifier;
- `state`: `in` or `out`;
- `host`: a DNS name, IPv4 literal, or IPv6 literal;
- `schemes`: a non-empty unique array containing `http`, `https`, or both;
- optional `ports`: a non-empty unique array of integers from 1 through 65535;
- `path_prefix`: an absolute-path prefix beginning with `/`; and
- `include_subdomains`: a Boolean.

The `host` value MUST NOT contain a scheme, port, path, userinfo, wildcard,
query, or fragment.  An IP-literal entry MUST set `include_subdomains` to
`false`.  `schemes` MUST be non-empty and unique and MUST contain no value other
than `http` or `https`.  `path_prefix` MUST NOT contain query or fragment
syntax.

<!-- requirements: SCOP-002 SCOP-004 SCOP-005 SCOP-006; disposition: normative -->

If `ports` is absent, only the default port for the matched scheme applies: 80
for HTTP and 443 for HTTPS.  A non-default port is covered only when explicitly
listed.

A matching `out` entry MUST override every matching `in` entry.  Scope and rule
array order MUST NOT change an evaluation result.

<!-- requirements: SCOP-007 SCOP-008; disposition: normative -->

A product entry contains `id`, `state`, a non-empty `name`, and an optional
non-empty array of unique `identifiers`.  Every product identifier MUST be an
absolute RFC 3986 URI and is compared as an exact, case-sensitive string
without scheme-specific equivalence processing.  Product entries are reporting
metadata only and MUST NOT produce automatic Testing Permission.  Version-range
syntax is not defined by Version 1.

<!-- requirements: SCOP-009; disposition: normative -->

## Testing Rules

`testing.rules`, when present, is a non-empty array.  Each rule contains a
unique `id`, an `activity`, a `state`, optional `target_ids`, and optional
`conditions`.

The core activity identifiers are:

- `manual_testing`: manually initiated investigation not described by a more
  specific core activity;
- `automated_scanning`: automated detection or vulnerability checking against a
  web or network service;
- `fuzzing`: automated transmission of generated or mutated inputs; and
- `credential_testing`: testing only with researcher-controlled or explicitly
  provided test accounts; it excludes credential stuffing, password spraying,
  and use of third-party credentials.

An extension activity identifier MUST be an absolute URI.  An unknown
unqualified token is structurally invalid.  Activity identifiers, including
extension URI identifiers, are compared as exact, case-sensitive strings.

<!-- requirements: TEST-003; disposition: normative -->

A rule's `state` is `permitted` or `prohibited`.  A `permitted` rule MUST contain
at least one `target_id`.  A `prohibited` rule without `target_ids` applies to
every web Target in Reporting Scope.  Every `target_id` MUST reference an
existing web entry whose state is `in`; references to products, `out` entries,
or missing IDs are invalid.

<!-- requirements: TEST-004 TEST-005 TEST-006; disposition: normative -->

For one activity and Target, every applicable rule is collected.  Any matching
`prohibited` rule MUST override every matching `permitted` rule.  No matching
rule means no established Testing Permission.

A `prohibited` rule MUST NOT contain `conditions`; a prohibition is
unconditional once the rule applies.

<!-- requirements: TEST-007 TEST-008; disposition: normative -->

### Conditions

Version 1 defines these condition members:

- `max_requests_per_second`: a positive number;
- `max_concurrent_requests`: a positive integer;
- `required_user_agent_token`: a non-empty visible-ASCII string matched
  case-sensitively as a complete substring of the planned User-Agent; and
- `test_accounts_only`: the literal JSON value `true`.

A conditions object MUST contain at least one member.  Unknown members in
`conditions` MUST make the policy structurally invalid.

<!-- requirements: COND-001; disposition: normative -->

A `permitted` `automated_scanning` or `fuzzing` rule MUST contain both rate and
concurrency limits.  A `permitted` `credential_testing` rule MUST contain those
two limits and `test_accounts_only: true`.

<!-- requirements: COND-002 COND-003; disposition: normative -->

A condition is satisfied only if every value required from the planned activity
is present and compliant.  A missing planned value MUST be treated as
unsatisfied.  A client MUST NOT ignore an unknown condition.  Planned rate and
concurrency MUST be no greater than their limits, the planned User-Agent MUST
contain the required token, and controlled or explicitly provided test accounts
MUST be affirmatively confirmed when required.

<!-- requirements: COND-004; disposition: normative -->

## Reporting Preferences

`reporting.requested_fields` is a unique array containing zero or more of:
`affected_asset`, `vulnerability_type`, `description`, `reproduction_steps`,
`impact`, `environment`, `evidence`, `researcher_contact`, and
`disclosure_preference`.

Requested fields are preferences.  A missing requested field MUST NOT by itself
cause a report to be rejected.

<!-- requirements: REP-001; disposition: normative -->

`reporting.proof_of_exploitation` is `not_requested`, `requested_if_safe`, or
`prohibited`.  `requested_if_safe` MUST NOT be interpreted as a request for
access to third-party data, persistence, exfiltration, lateral movement, damage,
availability impairment, or further exploitation.

<!-- requirements: REP-002; disposition: normative -->

This document does not define report transmission, an intake endpoint, or an
attachment protocol.

The optional declaration in {{csaf-reporting}} identifies contact channels for
a structured report format. It adds no members to the `reporting` object and
does not change the meaning of its preferences.

## Response Targets

`response_targets` is optional and contains one or more positive integer values:
`acknowledgement_days`, `initial_assessment_days`, and `update_interval_days`.
Acknowledgement and initial-assessment periods start when the publisher
receives the initial report.  Each update interval starts when the preceding
substantive update is sent.  They are publisher targets, not guarantees,
deadlines imposed on a reporter, or permission to test.

## Disclosure Preferences

`disclosure.approach` is required when `disclosure` is present and is one of
`coordinated`, `case_by_case`, or `no_preference`.  The optional
`default_days` is a positive integer whose period starts when the publisher
receives the initial report.  The optional `statement` is explanatory text.  These members express publisher preferences and do not override a
Testing Rule, a condition, or applicable law.

## Extensions

Extension identifiers are absolute RFC 3986 URIs compared as exact,
case-sensitive strings.  Extension data appears only as values of same-named
members in the `extensions` object.  `critical_extensions` is an
array of unique extension identifiers.  Every identifier in
`critical_extensions` MUST have a same-named member in `extensions`.

<!-- requirements: EXT-001; disposition: normative -->

An unknown critical extension MUST produce `unsupported-policy` during
permission evaluation.  An unknown non-critical extension MAY be ignored as
metadata but MUST NOT weaken any core prohibition or condition.  An extension
that changes permission, prohibition, or conditions MUST be listed as critical.

<!-- requirements: EXT-002 EXT-003 EXT-004; disposition: normative -->

This revision creates no Activity or extension registry.  Such registries can
be considered in future work if interoperable extensions are deployed.

### CSAF Vulnerability Report Declaration {#csaf-reporting}

A contact URI identifies a way to reach the publisher. It does not state
whether that channel accepts a structured vulnerability report. This extension
lets the publisher make that additional statement for specific contact
channels.

CSAF is the only structured vulnerability-report format for which this
revision defines a declaration. The extension is optional. A CVD policy remains
a policy document, and core policy implementations are not required to
implement this extension or process CSAF reports.

The extension identifier is
`https://github.com/cvd-policy/spec/extensions/csaf-vulnerability-report-v1`.
This URI is an identifier defined by this document. Its use does not require a
resource to be published at that location.

#### Specification Binding {#csaf-reporting-binding}

This revision binds the declaration to Profile 9, Vulnerability Report, in
Section 4.9 of {{CSAF-2.1-CSD04}}. That reference identifies CSAF Version 2.1,
Committee Specification Draft 04, dated 21 October 2026. It is a work in
progress, not an OASIS Standard.

The one supported value of `specification` in this revision is
`https://docs.oasis-open.org/csaf/csaf/v2.1/csd04/csaf-v2.1-csd04.html`.
Implementations MUST compare it as an exact, case-sensitive string after JSON
string decoding. They MUST NOT substitute a latest-version URL, infer support
from a URI prefix, or silently treat another specification revision as this
binding.

<!-- requirements: CSR-001; disposition: normative -->

The bound CSAF document has `document.csaf_version` equal to `2.1` and
`document.category` equal to `csaf_vulnerability_report`. The policy's
`specification` value pins the specification revision; it does not alter either
CSAF field. Conformance of a report is governed by the referenced CSAF
specification, including its applicable schema, mandatory tests, and profile
requirements. Policy-declaration validation does not perform that report
validation.

The declaration introduces no new media type. The policy media type remains
`application/cvd-policy+json`. CSAF reports are separate JSON documents. This
declaration does not define report transport or media-type negotiation for that
transport.

#### Declaration Data {#csaf-reporting-data}

The extension value MUST be an object containing only the required member
`channels`. That member MUST be a non-empty array. Each array element MUST be an
object containing only the required string members `uri` and `specification`.
Missing or additional members and incorrect types make the declaration invalid.

<!-- requirements: CSR-002; disposition: normative -->

Each `uri` MUST exactly match one entry in `contact.channels` after JSON string
decoding and MUST use the `mailto` or `https` scheme. Matching is case-sensitive
and performs no URI normalization or redirect resolution. A `tel` channel
cannot be listed in this declaration. Each distinct `uri` MUST occur at most
once in the array.

<!-- requirements: CSR-003; disposition: normative -->

The declaration's array order has no meaning. The preference order continues
to be the order in `contact.channels`. A client selecting among declared
channels MUST preserve that preference order.

<!-- requirements: CSR-004; disposition: normative -->

Each `specification` MUST be an absolute URI as defined by {{RFC3986}}. A
different, syntactically valid URI is an unsupported specification, not a
structural error. The exact binding in {{csaf-reporting-binding}} is the only
one supported by this revision.

<!-- requirements: CSR-005; disposition: normative -->

Implementations MUST treat the extension identifier and specification URI as
identifiers. Assessing the declaration MUST NOT require or trigger a network
request to either URI.

<!-- requirements: CSR-006; disposition: normative -->

#### Declaration Assessment {#csaf-reporting-assessment}

Assessment of this extension is separate from Testing Permission evaluation.
The result names below describe declaration assessment only; they are not
additional policy members or Testing Permission statuses.

The policy first has to pass the text, format-version, core structural, and
core semantic checks in {{structural-and-semantic-validation}}. Those checks
retain their precedence. In particular, duplicate JSON member names anywhere
in the document remain a policy error, including duplicates inside this
extension.

For a policy that passes those checks, implementations that support this
extension MUST assess it in the following order:

1. If the exact extension identifier is absent from `extensions`, the result
   is `not-advertised`.
2. If any data rule in {{csaf-reporting-data}} fails, the result is `invalid`.
   Check all structural and contact-reference rules before deciding whether a
   specification is unsupported.
3. If the identifier is listed in `critical_extensions`, or any entry names a
   syntactically valid but unsupported specification URI, the result is
   `unsupported`.
4. Otherwise, the result is `advertised` for all listed channels.

Assessment is atomic. An implementation MUST NOT return usable CSAF channel
metadata for an `invalid`, `unsupported`, or `not-advertised` result, or retain
a successful subset of an invalid or unsupported declaration. Such a result
does not state that the publisher rejects CSAF reports.

<!-- requirements: CSR-007; disposition: normative -->

This extension MUST NOT be listed in `critical_extensions`. If it is listed
there, an implementation that recognizes the identifier MUST treat that use as
unsupported critical behavior at step 6 of {{testing-permission-evaluation}},
producing `unsupported-policy` unless an earlier step has already determined
the result. Recognition of this identifier does not permit the client to ignore
its critical use.

<!-- requirements: CSR-008; disposition: normative -->

When this extension is non-critical, declaration errors or an unsupported
specification MUST NOT change core policy validity, Reporting Scope,
conditions, prohibitions, or the Testing Permission result. Implementations
MUST keep these declaration errors separate from core structural and semantic
errors. The general parsing and extension rules still apply; this does not
excuse duplicate JSON names or invalid core members.

<!-- requirements: CSR-009; disposition: normative -->

Before using an `advertised` result as a current statement of a Discovery Host,
a client MUST establish valid Authority and policy-retrieval evidence under
{{policy-retrieval}} and {{authority-and-delegation}}, verify that the policy
and its `security.txt` have not expired, and reject unsupported critical policy
behavior. An offline declaration assessment alone does not establish those
facts. This use does not require a Target, a testing activity, or a positive
Testing Permission result. A `report_only` policy can advertise CSAF report
support.

<!-- requirements: CSR-010; disposition: normative -->

#### Meaning and Limits {#csaf-reporting-meaning}

A publisher MUST list only channels at which it offers to receive reports
conforming to the bound CSAF profile. The declaration is the publisher's
statement of that offer. A client MUST NOT present a valid declaration as proof
that a channel was tested, that a particular report conforms to CSAF, or that a
submitted finding was accepted or confirmed.

<!-- requirements: CSR-011; disposition: normative -->

The declaration does not specify report transmission, a request method, an
intake API, authentication, attachment handling, acknowledgements, or case
management. In particular, a client MUST NOT infer that a declared HTTPS
contact URI is a POST endpoint or that reading this declaration authorizes
report transmission. The privacy rule in {{privacy-considerations}} continues
to apply.

<!-- requirements: CSR-012; disposition: normative -->

A client MUST NOT interpret this declaration as requiring every report to use
CSAF or as an additional reason to reject a human-readable report. The reporting
preferences in {{reporting-preferences}} retain their meaning. Mandatory CSAF
fields determine whether a CSAF report conforms to that format; they do not
become additional core policy reporting requirements.

<!-- requirements: CSR-013; disposition: normative -->

A client MUST NOT infer a CSAF publisher identity, a product's affected status,
or a vulnerability from policy organization or scope data. Reporting Scope
records where reports are welcomed; it does not establish that those assets
are vulnerable. A policy publisher and the publisher of a CSAF report can be
different parties.

<!-- requirements: CSR-014; disposition: normative -->

The `CSAF` field in `security.txt`, described in Section 7.1.8 of
{{CSAF-2.1-CSD04}}, supports discovery of CSAF provider metadata for
distribution. It is not this report-reception declaration and does not identify
an intake endpoint. The extension mechanism in this policy format is also
separate from the extension mechanism inside CSAF documents.

# Structural and Semantic Validation

Policy text MUST be UTF-8 JSON conforming to {{RFC8259}}, with exactly one
top-level value, and that value MUST be an object.  Parsers MUST reject comments,
trailing commas, multiple JSON texts, non-JSON numbers, and duplicate member
names at every nesting level.  A parser MUST NOT silently normalize duplicate
names by retaining an earlier or later value.

Automatic discovery and evaluation MUST use a duplicate-aware text parser before
ordinary object validation.  Duplicate safety cannot be recovered from an
object that has already passed through a parser that discarded duplicate names.

<!-- requirements: DOC-003 DOC-004 DOC-005; disposition: normative -->

A validator MUST NOT insert defaults or coerce types.  Every core object MUST
reject unknown properties.  Extension data is permitted only under
`extensions`.

<!-- requirements: DOC-006 DOC-007; disposition: normative -->

Validation proceeds through four distinct layers:

1. text parsing and duplicate detection;
2. format-version selection and structural validation;
3. semantic and cross-reference validation; and
4. expiry, supported-extension, Authority, Target, scope, rule, and condition
   evaluation.

The JSON Schema Draft 2020-12 {{JSON-SCHEMA-2020-12}} schema published with the
implementation corpus is a supporting artifact.  The normative requirements in
this document govern interoperability.  An implementation cannot rely on
external access to that schema to understand this format.

Semantic validation includes timestamp ordering, valid URIs and language tags,
document-wide ID uniqueness, scope-host normalization, permitted-rule target
references, posture conflicts, required conditions, and critical-extension data
presence.

The separate assessment in {{csaf-reporting-assessment}} does not add the CSAF
declaration's data rules to core policy validation. In non-critical use, a
declaration can be invalid or unsupported while the core policy remains valid.

# Target Normalization and Scope Matching

A Target is an absolute HTTP or HTTPS URL without userinfo.  Product identifiers
and URIs with any other scheme are not evaluation Targets.  Query and fragment
components do not participate in scope matching.  The scheme and host are
normalized, an omitted port becomes 80 for HTTP or 443 for HTTPS, and the URL
pathname is used for path matching.

DNS names MUST be converted to lowercase ASCII A-label form as described by
{{RFC5890}} and {{RFC5891}}, and one trailing dot MUST be removed.  IPv4 and
IPv6 literals MUST be compared in canonical form; IPv6 text representation
SHOULD follow {{RFC5952}}.

<!-- requirements: SCOP-003; disposition: normative -->

A web scope entry matches only if all of the following hold:

1. the normalized hosts are equal, or `include_subdomains` is true and the
   Target is the named DNS host or a proper subdomain on a label boundary;
2. the normalized scheme appears in `schemes`;
3. the effective port is present in `ports`, or `ports` is absent and the
   effective port is the scheme's default; and
4. the normalized pathname matches `path_prefix`.

Scope `path_prefix` and Target paths MUST use the same normalization.  An empty
path becomes `/`; RFC 3986 dot-segments are removed; repeated slashes are
preserved; hexadecimal digits in percent-encoded triplets are converted to
uppercase; and no percent-encoded octet is decoded for matching.  A percent
sign not followed by exactly two hexadecimal digits is invalid.  An encoded
slash therefore remains distinct from `/`.

<!-- requirements: SCOP-010; disposition: normative -->

Path matching is case-sensitive.  `/` matches every path.  A prefix ending in `/` matches paths that
start with that prefix.  Any other prefix matches the exact path or that prefix
followed by `/`.  Therefore, `/api` matches `/api`, `/api/`, and `/api/v1`, but
not `/apix`.

Matching scope entries are collected without order-based priority.  If any
matching entry is `out`, the Target is excluded.  Otherwise, at least one
matching `in` web entry is required before rule evaluation.  Scope matching for
a subdomain does not establish Authority for that subdomain.

# Testing Permission Evaluation

An evaluator accepts policy text, a Target, one activity, the planned values
needed by conditions, the set of understood extensions, an evaluation time, and
Authority evidence.  Before policy evaluation, it MUST validate and normalize
the Target input.  Invalid Target input MUST produce a typed machine-readable
input-validation failure with no evaluation status; it MUST NOT produce
`not-covered` or any other status from this document.

After successful Target input validation, an evaluator MUST execute the
following order and return at the first terminal outcome:

1. Parse the policy with duplicate detection.  A failure returns
   `invalid-policy`.
2. Check `cvd_policy`.  A missing or non-integer value returns
   `invalid-policy`; an unknown integer version returns `unsupported-policy`.
3. Perform structural validation.  A failure returns `invalid-policy`.
4. Perform semantic and reference validation.  A failure returns
   `invalid-policy`.
5. Check policy expiry.  Expiry returns `invalid-policy`.
6. Check critical extensions and the requested extension activity.  Unsupported
   critical behavior returns `unsupported-policy`.
7. Require successfully established Authority evidence and Policy retrieval
   evidence bound to its advertised Policy URI.  Missing, invalid, or mismatched
   evidence returns `authority-not-established`.
8. Require exact normalized Target and Discovery Host equality.  A mismatch
   returns `authority-not-established`.
9. Collect matching Reporting Scope entries.
10. If any matching entry is `out`, return `not-covered`; otherwise, if no
    matching `in` web entry exists, return `not-covered`.
11. Apply Research Posture.  `report_only` or `prohibited` returns
    `publisher-stated-prohibited`.
12. Collect all rules for the requested activity that apply globally or refer to
    a matching `in` target ID.
13. If any collected rule is `prohibited`, return
    `publisher-stated-prohibited`.
14. If no collected `permitted` rule exists, return `not-covered`.  Otherwise,
    evaluate all conditions fail closed.  If no permitted rule is fully
    satisfied, return `conditions-not-satisfied`.
15. Return `publisher-stated-permitted` when one or more permitted rules are
    fully satisfied.  Implementations MAY report all satisfied rule IDs
    informatively.  Version 1 defines neither lexicographic rule selection nor
    one aggregated constraint object; each satisfied rule retains its own
    conditions.

<!-- requirements: EVAL-003 EVAL-005; disposition: normative -->

A positive status requires a valid unexpired policy, understood critical
behavior, established Authority, exact Target and Discovery Host equality, at
least one matching `in` web entry, no matching `out`, no applicable prohibition,
and at least one fully satisfied `permitted` rule.

<!-- requirements: EVAL-004; disposition: normative -->

The primary public result MUST NOT be a Boolean named `allowed`, `authorized`,
or `safe`.  Calling software MUST treat every status other than
`publisher-stated-permitted` as no established Testing Permission.  Even
`publisher-stated-permitted` reports only a publisher statement obtained by the
algorithm above; it is not a determination of legal authorization or safe
harbor.

<!-- requirements: EVAL-001 EVAL-002; disposition: normative -->

# Processing Errors and Result Statuses

The Testing Permission status is exactly one of:

- `publisher-stated-permitted`: every positive precondition is satisfied;
- `publisher-stated-prohibited`: posture or an applicable rule prohibits the
  activity;
- `not-covered`: a syntactically valid normalized Target has no matching `in`
  web scope, matches an `out` web scope, or has no matching testing rule;
- `authority-not-established`: required Authority evidence is absent, invalid,
  or bound to another host;
- `conditions-not-satisfied`: applicable permission statements exist, but none
  has all conditions satisfied;
- `invalid-policy`: parsing, structural, semantic, reference, or expiry
  validation failed; or
- `unsupported-policy`: the format version, critical extension, or requested
  extension activity is not understood.

The ordered algorithm in {{testing-permission-evaluation}} defines precedence.  Array order and
implementation iteration order MUST NOT alter the status.

Input-validation and policy-processing failures MUST be machine-readable and
identify affected locations when available.  Only failures that validate
evaluation-call input, such as an invalid Target URL, are structurally outside
status-bearing evaluation results.  Policy parsing, version dispatch,
structural, semantic, reference, and expiry failures remain normal
status-bearing results; in particular, `invalid-policy` is a normative status.  Localized prose MUST NOT be the
only interface contract.  Implementations are not required to emit identical
detailed diagnostic identifiers.  Such identifiers are informative and
implementation-specific.

<!-- requirements: ERR-001 ERR-002; disposition: normative -->

The declaration-assessment results in {{csaf-reporting-assessment}} belong to a
separate result domain. They neither add to nor replace the statuses above.

# Operational Considerations

Publishers should choose expiry periods that force regular review; approximately
one year is a useful operational starting point.  They should update
`last_updated` only for substantive changes and should preserve old policy
versions for incident records when practical.

Clients should record the policy representation, retrieval context, evaluation
time, status, diagnostic details, and satisfied rules used for a decision.  A policy can
change during an investigation; a later policy must not silently rewrite the
record of an earlier evaluation.  Clients should revalidate after cache
revalidation, redirects, media-type changes, or expiry.

Response and disclosure targets are publisher statements.  Operational tooling
must not present them as service guarantees or as conditions imposed on a
reporter.

# Implementation Status

**RFC Editor: remove this entire section and the informative reference to RFC
7942 before publication.**

This section records known implementation evidence as recommended by
{{RFC7942}}. Source availability and local tests do not establish independent
interoperability, deployed behavior, or IETF endorsement.

The specification repository at commit
`e8b26c05482c2cee9872adcc8fa2fd18b2e53214` contains the experimental Version 1
specification, schema, examples, and conformance corpus {{CVD-POLICY-SPEC}}.
The reference implementation repository at commit
`0221629e2bb6702ccc24ddb84fcaf5dc7df87c8d` contains the isolated
`@cvd-policy/core/v1` entry point and Version 1 CLI and website paths
{{CVD-POLICY-CORE}}. The legacy package interfaces remain separate. These
repository snapshots were inspected on 8 November 2026 and describe the existing
core policy implementation.

The CSAF declaration in {{csaf-reporting}} is new in this revision. No
implementation or independent interoperability evidence for that declaration
is recorded here. The existing core corpus is not evidence that CSAF report
processing or the new declaration is implemented. This section needs to be
updated with specific implementation revisions and test evidence as that work
becomes available.

# Security Considerations

Policies and `security.txt` files are untrusted input.  Implementations MUST fail
closed for every security-sensitive ambiguity in parsing, Authority, scope,
rule matching, conditions, and extensions.

<!-- requirements: SEC-001; disposition: normative -->

Duplicate member names can produce inconsistent interpretations between
parsers.  Clients need duplicate-aware parsing before ordinary object mapping,
must reject non-JSON syntax, and should bound input size, nesting depth, member
count, string length, and total validation errors.  Such limits mitigate memory,
CPU, stack, and denial-of-service attacks involving overly complex documents.

Automatic retrieval creates SSRF and redirect risks.  Clients should enforce
HTTPS at every hop, finite redirect and response limits, timeouts, address
filtering before every connection, DNS-rebinding defenses, and credential
isolation.  They should reject HTTPS downgrades and unexpected media types.

A compromised Policy URI host can alter or suppress a policy.  A compromised
Discovery Host can advertise a malicious policy for that exact host.  Authority
records what the Discovery Host published; it does not prove ownership,
organizational control, or legal permission.  High-risk decisions need
independent corroboration.

Claims about third-party targets are not permission.  Exact Discovery Host
binding prevents parent-domain, subdomain, CNAME, shared-address, shared-
certificate, and organization-name confusion from transferring Authority.
Clients should display normalized A-label hostnames and, when useful, their
Unicode presentation to reduce IDNA and Unicode confusion.

Caches can preserve withdrawn or stale statements.  Clients must honor both
policy and `security.txt` expiry and should retain the exact policy used during
an investigation.  Unknown conditions fail validation or remain unsatisfied;
unknown critical extensions produce `unsupported-policy`; and non-critical
extensions cannot weaken core prohibitions.

No status in this document determines that an activity is legally authorized.
`publisher-stated-permitted` is not guaranteed safe harbor and does not remove
the need to assess law, contracts, third-party rights, safety, or operational
risk.

The CSAF declaration is untrusted metadata. Its contact channels can be
operated by a third party, and valid Authority does not verify their technical
capability. The declaration adds no permission to test those channels.
Treating specification identifiers as automatic fetch targets or contact links
as implicit upload APIs would create additional network and data-disclosure
risks; the restrictions in {{csaf-reporting}} prevent those inferences.

# Privacy Considerations

Implementations MUST NOT transmit policy text, `security.txt` text, Target
details, or researcher plan data unless a user explicitly invokes a network
operation that requires the transmission.

<!-- requirements: PRIV-001; disposition: normative -->

A policy can reveal internal asset names, product identifiers, test systems, or
contact addresses.  This document does not require a publisher to disclose
confidential infrastructure.  Publishers should provide only information they
intend to make public and should consider role-based rather than personal
contact addresses.

Policy retrieval can be logged by the Discovery Host, Policy URI host,
intermediaries, and DNS operators.  Per-client URLs, tokens, query parameters,
or similar registration mechanisms can track researchers and should be avoided.
A client should disclose the destination of every network request and minimize
retention of retrieval and evaluation data.

Nothing in this document requires a researcher to publish or transmit identity
information.  `researcher_contact` is only a reporting preference, and omission
alone cannot justify rejecting a report.  Contact information in policies can
be personal data and should be processed with appropriate minimization and
retention controls.

A report-format declaration belongs in a public policy; the vulnerability
report itself does not. Publishers should not place findings, evidence, exploit
details, or reporter identities inside this extension. Discovering a contact
channel does not itself transmit or publish a report.

# IANA Considerations

This document requests the following registrations.  The field and media type
remain proposed until IANA completes the applicable actions.

The CSAF declaration uses the URI identifier defined in {{csaf-reporting}} and
requests no additional registration. It does not redefine the CSAF field in
`security.txt`.

## security.txt Field

IANA is requested to add this entry to the "security.txt Fields" registry:

Field Name:
: CVD-Policy

Description:
: Link to a machine-readable coordinated vulnerability disclosure policy

Multiple Appearances:
: No

Status:
: current

Change Controller:
: IETF

Reference:
: This document, {{discovery-using-securitytxt}}

## Media Type

IANA is requested to add this entry to the "Media Types" registry, using the
template defined by {{RFC6838}} and the structured-syntax suffix rules in
{{RFC6839}}:

Type name:
: application

Subtype name:
: cvd-policy+json

Required parameters:
: N/A

Optional parameters:
: N/A

Encoding considerations:
: binary; representations are UTF-8 JSON as required by this document and
  {{RFC8259}}

Security considerations:
: Policy representations are untrusted JSON and can influence decisions about
  active security testing.  Implementations need duplicate-aware parsing,
  strict schema and semantic validation, bounded resource use, expiry checks,
  exact Authority and Policy-URI binding, fail-closed rule processing, and
  rejection of unknown critical behavior.  Automatic retrieval introduces
  SSRF, redirect, credential-disclosure, DNS-rebinding, and stale-cache risks;
  clients are required to use HTTPS, avoid ambient credentials, and accept only
  complete `200 OK` representations; they are advised to enforce finite limits
  and filter unsafe network destinations.  No result establishes ownership, legal authorization,
  safe harbor, or operational safety.  See {{security-considerations}}.

Interoperability considerations:
: Interoperability requirements are specified throughout this document,
  including strict parsing, validation, Authority, scope matching, condition
  processing, and extension handling.

Published specification:
: This document.

Applications that use this media type:
: CVD policy publishers, validators, discovery clients, and policy evaluators.

Fragment identifier considerations:
: The syntax and semantics of fragment identifiers for this `+json` media type
  follow `application/json` as specified by {{RFC6839}}.  At the time of this
  registration, `application/json` defines no fragment identifier syntax; if
  such syntax is defined in the future, it applies to this media type unless a
  later specification states otherwise.  Independently, a Policy URI carried
  by `CVD-Policy` cannot contain a fragment.

Additional information:
: Deprecated alias names: none.  Magic number(s): none.  File extension(s):
  none.  Macintosh file type code(s): none.

Person and email address to contact for further information:
: Ben Luca Behring, behring@skalvar.de; Marco Berg, berg@skalvar.de.

Intended usage:
: COMMON

Restrictions on usage:
: none

Author:
: IETF

Change controller:
: IETF

Provisional registration:
: no

This document does not request registration of a well-known URI suffix. It also
does not create an Activity or extension registry in this revision.

# Examples

All policy examples in this section are complete documents. The original
Version 1 examples retain their core semantics, and named corpus vectors identify
the stated evaluation cases. Long lines in the CSAF example use the
single-backslash folding convention in {{RFC8792}}. Remove its two-line folding
header and unfold continued lines before parsing that example as JSON. Folding
changes presentation only.

## Minimal report-only Policy

<!-- policy-example: minimal-report-only -->

~~~ json
{
  "cvd_policy": 1,
  "last_updated": "2026-08-29T08:00:00Z",
  "expires": "2027-02-28T08:00:00Z",
  "organization": {
    "name": "Example Organization"
  },
  "contact": {
    "channels": [
      "mailto:security@example.com"
    ]
  },
  "research": {
    "posture": "report_only"
  },
  "reporting_scope": {
    "web": [
      {
        "id": "main-web",
        "state": "in",
        "host": "example.com",
        "schemes": [
          "https"
        ],
        "path_prefix": "/",
        "include_subdomains": false
      }
    ]
  },
  "reporting": {
    "requested_fields": [
      "affected_asset",
      "description"
    ],
    "proof_of_exploitation": "not_requested"
  }
}
~~~

This policy accepts reports but contains no Testing Permission.

## Limited automated Web testing

<!-- policy-example: limited-web-testing -->

~~~ json
{
  "cvd_policy": 1,
  "last_updated": "2026-08-29T08:00:00Z",
  "expires": "2027-02-28T08:00:00Z",
  "organization": {
    "name": "Example Organization",
    "uri": "https://example.com/"
  },
  "contact": {
    "channels": [
      "mailto:security@example.com",
      "https://example.com/security/contact"
    ],
    "preferred_languages": [
      "en",
      "de"
    ],
    "encryption": [
      "https://example.com/security/pgp-key.txt"
    ]
  },
  "research": {
    "posture": "limited",
    "statement": "Security research is welcome only under the rules below."
  },
  "reporting_scope": {
    "web": [
      {
        "id": "main-web",
        "state": "in",
        "host": "example.com",
        "schemes": [
          "https"
        ],
        "ports": [
          443
        ],
        "path_prefix": "/",
        "include_subdomains": false
      }
    ]
  },
  "testing": {
    "rules": [
      {
        "id": "automated-scan-main",
        "activity": "automated_scanning",
        "state": "permitted",
        "target_ids": [
          "main-web"
        ],
        "conditions": {
          "max_requests_per_second": 2,
          "max_concurrent_requests": 2,
          "required_user_agent_token": "security-research"
        }
      }
    ]
  },
  "reporting": {
    "requested_fields": [
      "affected_asset",
      "description",
      "reproduction_steps",
      "impact"
    ],
    "proof_of_exploitation": "not_requested"
  },
  "response_targets": {
    "acknowledgement_days": 2,
    "initial_assessment_days": 10,
    "update_interval_days": 14
  },
  "disclosure": {
    "approach": "coordinated",
    "default_days": 90
  },
  "critical_extensions": [],
  "extensions": {}
}
~~~

For the plan in corpus vector `conditions-rate-exceeded`, a planned rate of 3
requests per second exceeds the limit of 2.  The normative result is
`conditions-not-satisfied`.

<!-- evaluation-vector: conditions-rate-exceeded -->

## Externally hosted Policy

The minimal policy in {{minimal-report-only-policy}} can be hosted by a provider.  The
Discovery Host retains Authority because its own assessed `security.txt`
contains the reference:

~~~ text
Contact: mailto:security@example.com
Policy: https://example.com/security-policy
CVD-Policy: https://policies.provider.example/example.json
Expires: 2027-02-28T08:00:00Z
Canonical: https://example.com/.well-known/security.txt
~~~

The provider host does not gain Authority over `example.com`.

## Multiple hosts sharing one Policy

<!-- policy-example: shared-policy-multiple-hosts -->

~~~ json
{
  "cvd_policy": 1,
  "last_updated": "2026-08-29T08:00:00Z",
  "expires": "2027-02-28T08:00:00Z",
  "organization": {
    "name": "Example Organization"
  },
  "contact": {
    "channels": [
      "mailto:security@example.com"
    ]
  },
  "research": {
    "posture": "limited"
  },
  "reporting_scope": {
    "web": [
      {
        "id": "example",
        "state": "in",
        "host": "example.com",
        "schemes": [
          "https"
        ],
        "path_prefix": "/",
        "include_subdomains": true
      }
    ]
  },
  "testing": {
    "rules": [
      {
        "id": "manual",
        "activity": "manual_testing",
        "state": "permitted",
        "target_ids": [
          "example"
        ]
      }
    ]
  },
  "reporting": {
    "requested_fields": [
      "affected_asset",
      "description"
    ],
    "proof_of_exploitation": "not_requested"
  }
}
~~~

`example.com` and `api.example.com` each publish their own `security.txt` and
both point to `https://policies.provider.example/shared.json`.  Separate
Authority evidence is required for each exact Discovery Host.  The
`include_subdomains` member affects scope matching only.

## An out entry overriding an in entry

<!-- policy-example: scope-out-wins -->

~~~ json
{
  "cvd_policy": 1,
  "last_updated": "2026-08-29T08:00:00Z",
  "expires": "2027-02-28T08:00:00Z",
  "organization": {
    "name": "Example Organization",
    "uri": "https://example.com/"
  },
  "contact": {
    "channels": [
      "mailto:security@example.com",
      "https://example.com/security/contact"
    ],
    "preferred_languages": [
      "en",
      "de"
    ],
    "encryption": [
      "https://example.com/security/pgp-key.txt"
    ]
  },
  "research": {
    "posture": "limited",
    "statement": "Security research is welcome only under the rules below."
  },
  "reporting_scope": {
    "web": [
      {
        "id": "main-web",
        "state": "in",
        "host": "example.com",
        "schemes": [
          "https"
        ],
        "ports": [
          443
        ],
        "path_prefix": "/",
        "include_subdomains": false
      },
      {
        "id": "excluded",
        "state": "out",
        "host": "example.com",
        "schemes": [
          "https"
        ],
        "path_prefix": "/",
        "include_subdomains": false
      }
    ]
  },
  "testing": {
    "rules": [
      {
        "id": "automated-scan-main",
        "activity": "automated_scanning",
        "state": "permitted",
        "target_ids": [
          "main-web"
        ],
        "conditions": {
          "max_requests_per_second": 2,
          "max_concurrent_requests": 2,
          "required_user_agent_token": "security-research"
        }
      }
    ]
  },
  "reporting": {
    "requested_fields": [
      "affected_asset",
      "description",
      "reproduction_steps",
      "impact"
    ],
    "proof_of_exploitation": "not_requested"
  },
  "response_targets": {
    "acknowledgement_days": 2,
    "initial_assessment_days": 10,
    "update_interval_days": 14
  },
  "disclosure": {
    "approach": "coordinated",
    "default_days": 90
  },
  "critical_extensions": [],
  "extensions": {}
}
~~~

For `https://example.com/`, both entries match.  The `out` entry wins regardless
of array order, producing the normative status `not-covered` as specified by
corpus vector `scope-out-wins`.

<!-- evaluation-vector: scope-out-wins -->

## A report-only Policy with a CSAF Declaration {#csaf-reporting-example}

The publisher advertises CSAF reports at its email channel. Its HTTPS contact
remains an ordinary contact link; this policy does not claim that the link
accepts CSAF uploads.

<!-- policy-example: csaf-reporting -->

~~~ json
NOTE: '\' line wrapping per RFC 8792

{
  "cvd_policy": 1,
  "last_updated": "2026-11-08T00:00:00Z",
  "expires": "2027-05-07T00:00:00Z",
  "organization": {
    "name": "Example Organization"
  },
  "contact": {
    "channels": [
      "mailto:security@example.com",
      "https://example.com/security/contact"
    ]
  },
  "research": {
    "posture": "report_only"
  },
  "reporting_scope": {
    "web": [
      {
        "id": "main-web",
        "state": "in",
        "host": "example.com",
        "schemes": [
          "https"
        ],
        "path_prefix": "/",
        "include_subdomains": false
      }
    ]
  },
  "reporting": {
    "requested_fields": [
      "affected_asset",
      "description"
    ],
    "proof_of_exploitation": "not_requested"
  },
  "extensions": {
    "https://github.com/cvd-policy/spec/extensions/\
      csaf-vulnerability-report-v1": {
      "channels": [
        {
          "uri": "mailto:security@example.com",
          "specification": "https://docs.oasis-open.org/csaf/csaf/\
      v2.1/csd04/csaf-v2.1-csd04.html"
        }
      ]
    }
  }
}
~~~

The declaration-assessment result is `advertised` for
`mailto:security@example.com`. A client still needs the Authority, retrieval,
and freshness checks in {{csaf-reporting-assessment}} before using it as the
current statement of a Discovery Host. The `report_only` posture continues to
provide no Testing Permission.

If the declaration names `mailto:other@example.com` instead, its result is
`invalid` because that exact contact is absent. If it names an unrecognized but
absolute specification URI instead, its result is `unsupported`. Neither
non-critical change alters the core policy's Testing Permission result. Listing
this extension as critical invokes `unsupported-policy` at the existing
critical-extension step.

# Changes from -00 {#changes-from-00}

*RFC Editor: remove this appendix before publication.*

- Add an optional, non-critical CSAF Vulnerability Report declaration for
  explicitly named contact channels.
- Pin the one supported report-format binding to CSAF 2.1 CSD04 and identify its
  work-in-progress status.
- Define declaration data, atomic assessment, unsupported critical use, and the
  separation from core policy and Testing Permission results.
- Clarify the distinction between policy discovery, a declared receiving
  capability, report conformance, and actual channel behavior.
- Add a complete policy example and clarify that human-readable reports remain
  usable and that report transmission is outside scope.
- Update the Implementation Status to distinguish inspected core
  implementations from the new, unimplemented declaration.
- Keep the JSON format version at integer 1 and preserve the existing core
  object members, discovery rules, Authority model, scope matching, and ordered
  Testing Permission algorithm.

--- back
