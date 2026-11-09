# Integrationsübergabe

Diese Übergabe beschreibt konkrete Crate-Schnittstellen und Produktverantwortungen. Paketstand `cvd-policy` `0.1.0`, crate root `cvd_policy`; lokaler Crate-Pfad: `/home/undef/Projects/skalvar/cvd/cvd_policy/rust`. Ein Source-Commit-Hash ist noch nicht zugewiesen. Keine Abhängigkeit auf einen ungepushten Remote-Commit und keine Registry-Verfügbarkeit von `0.1.0` voraussetzen.

## Lokaler Build und Beispiele

Consumer verwenden während dieser Integration ausschließlich den lokalen Path-Dependency:

```toml
[dependencies]
cvd-policy = { path = "/home/undef/Projects/skalvar/cvd/cvd_policy/rust", version = "0.1.0" }
```

Das kompilierende Beispiel [`examples/integration.rs`](../examples/integration.rs) zeigt Policy-Parsing und `validate_at`, geprüfte Security.txt-Evidenz, Retrieval-Metadaten, Evaluation und CSAF-Hostbewertung. Der separate Consumer unter [`tools/external-consumer`](../tools/external-consumer/) demonstriert Path-Dependency-Verbrauch. Diese lokalen Artefakte ersetzen weder die konkrete Adapterportierung noch deren Produktvergleich.

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
| `policy-core/src/server.js` | Wrapper/endpoints; `assessPolicyWithCsaf` 331–347; `/v1/assess-policy` response 534–535; `assess-csaf-policy` route without Rust caller; `new Date(input.security_txt.retrieved_at)` 346 | `a4cb0f3fe79b89f05f8e6085381e7daf5b834703fa9981b6a095cab35cd02492` |
| `policy-core/src/csaf-policy.js` | `policyWithCsafChannels` 24–52 | `58d716a4c2fa4f7450cb5ec916ad05a5c307786fa3deeced20fc1d78a7597f8d` |

## Endpoint mapping and ownership

| Existing endpoint / wrapper | Rust mapping | Product-owned behavior and compatibility notes |
|---|---|---|
| `generate-policy` | `generate_policy` → validate current policy with `validate_at(now)` → `Policy::to_json()` | Preserve product reason/facts, HTTP response shape, and publisher orchestration. Serialization failure is internal/product fault, not a permission decision. |
| `render-release` | policy validation/serialization as above, plus `security_txt` and `merge_security_txt` where applicable | Release orchestration remains product-owned. Equality of Security.txt expiry and policy expiry is a product release rule, not a general NormDraft rule. Preserve existing response and facts. |
| `assess-security-txt` | `assess_security_txt(raw, &SecurityTxtRetrieval)` | `text`, `expected_text`, `required_contacts`, `drift`, `reason`, and `facts` remain product wrapper responsibilities. Core returns assessment/evidence, not the product response. |
| `assess-policy` | `Policy::parse` → `validate_at(current_now)` → `policy_retrieval_issues` and `assess_csaf_for_host` as applicable; map policy decision to product result | Existing Node wrapper calls `assessPolicyWithCsaf`; `/v1/assess-policy` returns `.csaf_host`. Rust `PolicyAssessment` in `deployment.rs` has no `csaf_host` field and serde ignores that extra field. Agent2 must add/map this product response explicitly; do not silently claim direct response parity. Product comparison/reason/facts remain adapter-owned. |
| `contacts` | Product field validation; no dedicated native Core contacts endpoint | Keep existing product contact checks and response behavior in the adapter. |
| `assess-csaf-policy` | `assess_csaf_for_host` | The dedicated route has no Rust caller identified, but CSAF is already used indirectly through `assess-policy`; do not omit that path. |
| `validate-csaf` | No replacement in this crate | Separate CSAF report validator; remains outside this Policy Core. |

In `policyWithCsafChannels`, an undefined value preserves existing policy data; an empty channel list removes only the CSAF extension; a non-empty list writes the exact fixed-specification object. Rust can clone `Policy::value()`, edit only that extension, preserve other extensions, pass the result through `Policy::from_value`, then call `assess_csaf`; no new crate helper is required. Do not mark a new extension critical. The separate report validator is unaffected.

## Fresh time versus historical retrieval

The Node wrapper derives `new Date(input.security_txt.retrieved_at)` at the cited callsite. On reuse, the integrator must pass a fresh current `EvaluationContext::now` separately from historical `SecurityTxtRetrieval::retrieved_at`. The library checks policy and authority freshness against the current context; retrieval timestamp remains historical evidence. Compare old and new outputs using the same saved inputs, without duplicate network fetch, send, or store operations.

Discovery, HTTP retrieval, TLS/credential checks, redirects as observed by transport, response/status adaptation, product reason/facts, contact checks, expected-document drift, and publication remain adapter/transport/publisher responsibilities. No claim that these have been ported or verified. The external consumer's `report_only`/advertised-host demonstration is evidence of that example consumer behavior only, not full Node interoperability.

## `serde_json` feature-unification risk

This crate enables `serde_json` `arbitrary_precision` to preserve exact numbers. Cargo unifies dependency features in a consumer workspace, potentially changing `serde_json::Value`/`Number` behavior. Snapshot `api/backend/crates/management/Cargo.toml` line 33 and `api/backend/crates/intake/Cargo.toml` line 15 declare `serde_json = "1"`. Agent2 must inspect affected consumer JSON callsites and roundtrips; do not delete dependencies or disable the feature as a shortcut. The native raw parser constructs objects itself and preserves literal `$serde_json::private::Number` keys; ordinary consumer `Value` deserialization is not the same parser.

## Cutover safeguards

Only after adapter mapping and output comparison are demonstrated should Agent2 remove superseded wrappers and their now-unused Node dependencies; retain unrelated Node dependencies. There is no automatic Node fallback for invalid/unsupported input, internal error, panic, or timeout. Rollback is controlled and uses identical saved inputs; no duplicate fetch, send, or store. No silent legacy 0.x migration.

## Remaining final gates

No source commit hash is claimed yet. Manager's native tests are reported separately; final commit hash and remaining integration/package/CI gates are still to be supplied. Do not state those gates passed before their execution.
