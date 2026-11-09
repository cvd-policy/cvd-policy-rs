# Integrationsübergabe

Diese Übergabe gilt für Crate-Revision `dfa1d5347a23938e5b8ef9b68f5128dc4c6e3ba9` auf lokalem Branch `task/rust-v1` (kein Remote): Paket `cvd-policy` `0.1.0`, crate root `cvd_policy`, Edition 2021, MSRV 1.88; Crate-Pfad `/home/undef/Projects/skalvar/cvd/cvd_policy/rust`. Version/Pfad begründen keine Registry-Verfügbarkeit.

## Lokaler Build und Beispiele

Consumer verwenden während dieser Integration ausschließlich den lokalen Path-Dependency:

```toml
[dependencies]
cvd-policy = { path = "/home/undef/Projects/skalvar/cvd/cvd_policy/rust", version = "0.1.0" }
```

Das Beispiel [`examples/integration.rs`](../examples/integration.rs) wurde mit `cargo +1.88 run --example integration` ausgeführt. Der eigenständige Consumer unter [`tools/external-consumer`](../tools/external-consumer/) wurde gegen den verifizierten entpackten Crate als eigenes Cargo-Workspace-Paket ausgeführt: `report_only`, `publisher-stated-prohibited`, CSAF `Advertised`, Host `usable=true`.

`Policy::to_json()` liefert `Result<String, PolicyError>`. `policy_serialization_failed` ist ein interner Produkt-/Implementierungsfehler bei bereits geprüfter Policy und darf nicht als Permission-Status interpretiert werden. Target-`InputError` ist eine getrennte Fehlergrenze; Core-Policy-Ergebnisse sind die sieben Permission-Statusdomänen. Kein automatischer Node-Fallback bei Rust-Fehler, Panic oder Timeout.

## Produktquellen und Snapshot-Belege

Pfade sind relativ zu `/tmp/opencode/cvd-rust-aeskal-O5FHEZ`. Hashes stehen in dessen `SHA256SUMS`; sie identifizieren Snapshot-Dateien, nicht Rust-Integrationserfolg. Der Snapshot hat `SOURCE_HEAD=6f2024534d2e6c6866601ea14d9c42f38bf867a5` und einen Dirty-Status mit fremden Änderungen.

| Produktdatei | Relevante Bereiche | SHA-256 |
|---|---|---|
| `api/backend/crates/management/src/lib.rs` | `PolicyCoreClient` 1364–1395; `render_release` 1438–1486; `generate_policy` 1488–1538 | `d688ed52c0932ab2a26a9e5fa40a97bc55c9bf34bce027c685e79bf1b1f77927` |
| `api/backend/crates/management/src/deployment.rs` | Policy/Security.txt 173–208; Kontaktprüfung 326–329; Checker 306–341, 490–609 | `eb33e8aec1eea00c3870f4da27c15f2d2fb3c27a1b14f27e73f5712c6f77efcf` |
| `api/backend/crates/management/src/policy_publish.rs` | Publisher-Aufrufer 585, 1017 | `e929d2d1fcd079f29348f1013f98972a735a8a3cfce40bf9e40c2612e4cb3ca8` |
| `api/backend/crates/management/src/policy_migration.rs` | Migration-Aufrufer 221, 248 | `c340af05f4c7a84e01b49980abafda5148ce2b2c8036415d39bfc27f565dd339` |
| `api/backend/crates/management/src/csaf.rs` | separates CSAF-Reportvalidieren 198–200 | `fbf5f6a13672c6c49e7c8f453b3d1cd2cd13cfeb6874b0c395a3932aa5818b02` |
| `policy-core/src/server.js` | Wrapper/endpoints; `assessPolicyWithCsaf` 331–347; `/v1/assess-policy` response 534–535; `assess-csaf-policy` route without dedicated Rust caller; `new Date(input.security_txt.retrieved_at)` 346 | `a4cb0f3fe79b89f05f8e6085381e7daf5b834703fa9981b6a095cab35cd02492` |
| `policy-core/src/csaf-policy.js` | `policyWithCsafChannels` 24–52 | `58d716a4c2fa4f7450cb5ec916ad05a5c307786fa3deeced20fc1d78a7597f8d` |

## Endpoint mapping and ownership

| Existing endpoint / wrapper | Rust mapping | Product-owned behavior and compatibility notes |
|---|---|---|
| `generate-policy` | `generate_policy` → `Policy::validate_at(now)` → `Policy::to_json()` | Preserve product reason/facts, HTTP response shape, and publisher orchestration. Serialization failure is internal/product fault, not a permission decision. |
| `render-release` | `generate_policy`/parse → `validate_at(now)` → `to_json`, plus `security_txt`, `merge_security_txt`, `assess_security_txt` | Contact preference, encryption, human Policy fields/comparisons, and expiry equality are Aeskal adapter/release rules, not new NormDraft requirements. Preserve product response and facts. |
| `assess-security-txt` | `assess_security_txt(raw, &SecurityTxtRetrieval)` | Product still compares `text`, `expected_text`, required contacts and expected URI; drift/reason/facts remain adapter-owned. |
| `assess-security-txt-contacts` | Product contact validation | No native Core endpoint/helper; preserve product contact rules and response. |
| `assess-policy` | `Policy::parse` → `validate_at(current_now)` → `policy_retrieval_issues` → `assess_csaf_for_host` + product comparison | Node `assessPolicyWithCsaf` at 331–347 returns `.csaf_host` at 534–535. Rust `PolicyAssessment` (`deployment.rs` 173–183) lacks that field and serde ignores it; map the response explicitly. Product reason/facts/comparison remain adapter-owned. |
| `assess-csaf-policy` | `assess_csaf_for_host(raw, authority, retrieval, &context)` | No dedicated Rust caller identified, but CSAF is already consumed indirectly by `assess-policy`. |
| `validate-csaf` | No replacement in this crate | Separate CSAF report validator; remains outside this Policy Core. |

In `policyWithCsafChannels` (`policy-core/src/csaf-policy.js` lines 24–52) and `declaredCsafChannels` (lines 17–21), undefined preserves the existing policy; an empty list removes only the CSAF extension (and empty extension container); non-empty writes exact channels with fixed specification, without adding `critical_extensions`. Rust can clone `Policy::value()`, edit that extension with the same shape, preserve unrelated extensions, validate via `Policy::from_value`, then call `assess_csaf`; no new Core helper is needed. The separate report validator is unaffected.

## Fresh time versus historical retrieval

The Node wrapper derives `new Date(input.security_txt.retrieved_at)` at the cited callsite. Do not port that historical timestamp as `now` when reusing evidence. Preserve original `SecurityTxtRetrieval::retrieved_at`; obtain a fresh current `EvaluationContext::now` from the caller. Policy expiry and authority expiry are reevaluated against current context. Compare outputs using the same saved inputs, without duplicate discovery/fetch, send, or store operations.

Discovery, HTTP retrieval, TLS/credential checks, redirects as observed by transport, response/status adaptation, product reason/facts, contact checks, expected-document drift, and publication remain adapter/transport/publisher responsibilities. No claim that these have been ported or verified. The external consumer's `report_only`/advertised-host demonstration is evidence of that example consumer behavior only, not full Node interoperability.

## `serde_json` feature-unification risk

This crate enables `serde_json` `arbitrary_precision` to preserve exact numbers. Cargo unifies dependency features in a consumer workspace, potentially changing `serde_json::Value`/`Number` behavior. Snapshot `api/backend/crates/management/Cargo.toml` line 33 and `api/backend/crates/intake/Cargo.toml` line 15 declare `serde_json = "1"`. Agent2 must inspect affected consumer JSON callsites and roundtrips; do not delete dependencies or disable the feature as a shortcut. The native raw parser constructs objects itself and preserves literal `$serde_json::private::Number` keys; ordinary consumer `Value` deserialization is not the same parser.

## Cutover safeguards

Only after adapter mapping and output comparison are demonstrated should Agent2 remove superseded wrappers and their now-unused Node dependencies; retain unrelated Node dependencies. There is no automatic Node fallback for invalid/unsupported input, internal error, panic, or timeout. Rollback is controlled and uses identical saved inputs; no duplicate fetch, send, or store. No silent legacy 0.x migration.

## Remaining final gates

The source commit listed above is the reviewed implementation revision, not a self-referential documentation commit. Remaining obligations: Agent2 product endpoint/response mapping and cutover, consumer `serde_json/arbitrary_precision` feature-unification review of JSON roundtrips, and any final revalidation after documentation commit. Do not automatically fall back to Node on Rust errors/panics/timeouts; after proven cutover remove only superseded wrappers/dependencies, not unrelated Node dependencies.
