# cvd-policy

Deterministischer Rust-Core zum Parsen, Validieren und lokalen Auswerten von CVD Policy Version 1. Dies ist eine eigenständige zweite Codeimplementierung, keine unabhängige Implementierung durch eine zweite Organisation. Sie ist kein neues öffentliches Repository und macht keine Registry-Verfügbarkeitszusage.

## Paket und Status

- Paket `cvd-policy` 0.1.0, Bibliotheksmodul `cvd_policy`
- Edition 2021, MSRV Rust 1.88 (geprüft)
- Lizenz des Rust-Codes: Apache-2.0; vendorte Spec-/Corpus-Quellen behalten ihre eigenen Lizenzen
- Keine Netzwerk- oder Dateisystem-I/O und kein Zugriff auf die Systemuhr im Core; Zeit kommt explizit vom Aufrufer

Manager-gemeldete Prüfungen: offline/locked und ohne Node/npm im PATH auf Rust 1.88.0 liefen 101 Unit-, 7 Conformance-Loop-, 1 Interop-Fixture-, 1 Provenienz- und 9 Doctests; 0 übersprungen, 0 Warnungen. Die Conformance-Loops umfassen 198 Baseline-Vektoren (10 valid, 47 invalid, 8 raw-invalid, 19 Security.txt, 55 Evaluation, 42 CSAF, 17 URI), hinzu kommen 14 native Interop-Extras. MSRV no-default-features Tests, MSRV all-target/all-feature Clippy `-Dwarnings` und MSRV rustdoc `-Dwarnings` bestanden. Stable `fmt` und all-target Clippy ebenfalls bestanden. `cargo +1.88 run --example integration` bestand: `report_only`, Permission `publisher-stated-prohibited`, CSAF `Advertised`, Host `usable=true`. Der 220-Fall-Replay mit identischen gespeicherten Inputs bestand; Request-SHA-256 `3d787d16bf28d51abaf7c446fe32c2dbf9f91f367255262f86a71b44e6d5cefd`, committierbarer Bericht [`tools/interop/artifacts/report.json`](tools/interop/artifacts/report.json), zusätzlicher Replaybericht `/tmp/opencode/cvd-rust-interop-replay/report.json`. Zwölf Verhaltensdeltas sind in [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) normativ eingeordnet. Offen bleiben verifizierter Packaging-Archivconsumer, Remote-CI und Produkt-Cutover; dies ist keine pauschale Drop-in-Freigabe.

## Quellen

NormDraft-01 und Fixtures sind unter `vendor/spec/`; Originalquelle Spec-Commit `955f01c67391c832c970661329c7da5fdbf011af`. Der Web-Core-Vergleich stammt von `2e63a73ac1a04d31fc9fca8dec6cc256ccf963b4`; die Tests gegen diese Referenz sind Entwicklungs-/Interop-Werkzeuge, nicht Build-Voraussetzung für die Library. Quellinventar und Lizenzzuordnung stehen in [`vendor/SOURCES.json`](vendor/SOURCES.json) und [`NOTICE.md`](NOTICE.md).

## Öffentliche API

Die Namen und Typen unten entsprechen den Root-Exports in [`src/lib.rs`](src/lib.rs). Sie sind Signaturskizzen, keine kopierbaren vollständigen Rust-Ausdrücke:

```text
Policy::parse(&[u8]) -> Result<Policy, PolicyError>
Policy::from_value(Value) -> Result<Policy, PolicyError>
Policy::value(&self) -> &Value
Policy::to_json(&self) -> Result<String, PolicyError>
Policy::validate_at(&self, now: &Timestamp) -> Result<(), PolicyError>

evaluate_policy(
    raw: &[u8],
    query: &EvaluationQuery,
    authority: Option<&AuthorityEvidence>,
    context: &EvaluationContext,
) -> Result<PermissionResult, InputError>

assess_security_txt(raw: &[u8], retrieval: &SecurityTxtRetrieval) -> AuthorityAssessment
assess_csaf(raw: &[u8]) -> Result<CsafAssessment, PolicyError>
assess_csaf_for_host(
    raw: &[u8],
    authority: Option<&AuthorityEvidence>,
    retrieval: Option<&PolicyRetrieval>,
    context: &EvaluationContext,
) -> CsafHostAssessment

generate_policy(input: Value) -> Result<Policy, PolicyError>
security_txt(policy: &Policy, options: &SecurityTxtOptions) -> Result<String, InputError>
merge_security_txt(raw: &str, policy_uri: &str) -> Result<String, InputError>
policy_retrieval_issues(...) -> Vec<Diagnostic>
```

`CsafAssessment` has a four-state `state` (`CsafState`), channels, and diagnostics. `CsafHostAssessment` has `usable`, `capability: Result<CsafAssessment, PolicyError>`, and diagnostics; its `&EvaluationContext` is required. Root exports also include `CsafChannel`, `CSAF_EXTENSION_ID`, `CSAF_SPECIFICATION`, `SecurityTxtOptions`, `NormalizedTarget`, `ParseLimits`, timestamps, query/retrieval/evaluation types, and error types. Number/URI helpers are internal, not a public toolkit module.

`Policy` validates static structure and semantics and is immutable; required `expires` remains part of its value. `validate_at(now)` must be called for every current use, and authority evidence expiry is also reevaluated against that current context. A `SecurityTxtRetrieval.retrieved_at` is historical retrieval evidence, not the current evaluation time. `EvaluationContext::new(now)` makes time explicit.

`to_json()` errors use diagnostic `policy_serialization_failed`. Since the Policy was already checked, this is an internal/product fault, never a permission decision. Handle it or deliberately `.expect(...)` only where the invariant is justified. Target `InputError` is separate from the seven permission-result statuses. `AuthorityEvidence` is only produced through assessment; `security_txt_uri()` intentionally reports the originally requested URI, not necessarily the final redirect URI. This is an allowed internal representation difference, not a normative failure or a byte-for-byte evidence mapping claim. No TLS or signature cryptographic verification is claimed.

## Parsing and exact values

Default limits: 1 MiB input, nesting depth 64, and 100,000 JSON nodes/member names; configured depth is clamped to a hard ceiling of 256. Number lexemes are limited to 4,096 bytes. Strings require Unicode scalar values; unpaired surrogate escapes are rejected as an implementation representation limit, not an added NormDraft MUST. Exact arbitrary-precision numbers are retained. URI parsing rejects illegal raw characters rather than repairing them and preserves percent-encoded octets.

Runtime dependencies are `fluent-uri` (URI syntax), `language-tags` (language validation), `num-bigint` (exact decimal comparison), `serde` (typed serialization), `serde_json` with mandatory `arbitrary_precision` (JSON and exact numbers), `time` (explicit timestamps), and `url` (host/URL parsing). `sha2` is a dev-dependency for provenance checks. Cargo feature unification means enabling `serde_json/arbitrary_precision` may affect consumer `Value`/`Number` behavior; integration must inspect JSON roundtrips rather than disable this required feature. The crate's custom raw parser is not equivalent to ordinary consumer `serde_json::Value` deserialization.

## Local use

Use the local path dependency only; no unpublished remote commit or registry package is implied:

```toml
[dependencies]
cvd-policy = { path = "/home/undef/Projects/skalvar/cvd/cvd_policy/rust", version = "0.1.0" }
```

[`examples/integration.rs`](examples/integration.rs) compiles under Rust 1.88 and exercises parsing, explicit-time validation, security.txt evidence, evaluation, and CSAF host assessment. Manager ran it successfully with `report_only`, Permission `publisher-stated-prohibited` (not positive), CSAF `Advertised`, and Host `usable=true`. [`tools/external-consumer`](tools/external-consumer/) is an additional local consumer.

## Boundaries and interoperability

The core does not discover/fetch, publish releases, submit CSAF reports, validate CSAF report documents, or assert that advertised channels actually receive reports. Those remain product/adapter/transport/publisher responsibilities. See the concrete endpoint mapping and cutover obligations in [`docs/INTEGRATION.md#produktquellen-und-snapshot-belege`](docs/INTEGRATION.md#produktquellen-und-snapshot-belege) and the 85-requirement evidence matrix in [`docs/requirements.md`](docs/requirements.md).

The recorded 220-case replay passed using identical saved inputs (198 baseline + 22 extras), with request SHA-256 `3d787d16bf28d51abaf7c446fe32c2dbf9f91f367255262f86a71b44e6d5cefd`; see `tools/interop/artifacts/report.json`. It is not blanket equivalence. Twelve deltas are classified against NormDraft/RFC in [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md): original-requested versus final security.txt URI getter is allowed representation; other differences include RFC 9116 whitespace, integer version rounding/overflow, URI fragment rejection, sub-millisecond expiry precision, and exact decimal-rate evaluation. No normative fixtures were changed to hide differences. Packaging archive-consumer verification, Remote-CI, and product cutover remain open; do not add automatic Node fallback on errors, panic, or timeout.
