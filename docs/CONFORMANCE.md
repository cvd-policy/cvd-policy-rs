# Normkonformität und Prüfnachweise

## Maßgebliche Basis

Maßgeblich ist [`../vendor/spec/draft/draft-behring-cvd-policy.md`](../vendor/spec/draft/draft-behring-cvd-policy.md); die IDs stammen aus [`../vendor/spec/v1/requirements.json`](../vendor/spec/v1/requirements.json) und Baseline-Zuordnung aus [`../vendor/spec/draft/REQUIREMENTS-MAPPING.md`](../vendor/spec/draft/REQUIREMENTS-MAPPING.md). Alle drei Dateien wurden laut Manager byteweise gegen Spec-Commit `955f01c67391c832c970661329c7da5fdbf011af` geprüft. Die Web-Quelle ist nur Vergleichsbasis. Die per Requirement aufgeschlüsselte Rust-Prüfzuordnung steht in [`requirements.md`](requirements.md).

Die Implementierung ist eine zweite Codeimplementierung, jedoch keine unabhängige Implementierung durch eine zweite Organisation. Conformance ist nicht allein dadurch erwiesen, dass Rust und Web dieselben Fixtures verwenden; erforderlich sind die normative Zuordnung, ausführbare Rust-Prüfungen und Interop-Nachweise für Ablösung.

## Conformance-Umfang

Der Library-Core ist für lokale Policy-Validierung und -Auswertung, security.txt-Evidenzbeurteilung anhand übergebener Retrieval-Fakten sowie CSAF-2.1/CSD-04-Policy-Assessment vorgesehen. Release-Publishing, Discovery und Netzwerktransport, TLS-/Signaturprüfung, Produktstatus-/Reason-Transformation, CSAF-Reportvalidierung und Submission sind nicht Teil der Library-Conformance. Sie müssen als Adapter-/Publisher-/Transportverantwortung separat geprüft werden.

Vertrag: geprüfte statische Struktur und Semantik, verpflichtendes `expires` mit `Policy::validate_at(now)` bei jeder aktuellen Nutzung; unbekannte Erweiterungen bleiben im unveränderlichen Value; RFC-3339-Zeit-Parsing und explizite Evaluation-Zeit; `serde_json::Number` mit Arbitrary Precision für numerische Planfelder; sieben Permission-Statuswerte; Target-`InputError` separat; geprüfte, nicht frei konstruierbare `AuthorityEvidence`. `Policy::to_json()` liefert `Result<String, PolicyError>`; `policy_serialization_failed` signalisiert nach validierter Konstruktion ein Implementierungs-/Produktproblem und darf nie in eine Permission-Entscheidung umgedeutet werden. `evaluate_policy` trennt Target-`InputError` von regulären Core-Policy-Ergebnissen.

CSAF-Verhalten ist auf die festgelegte exakte Norm-ID sowie 2.1/CSD-04-Profil und -Kategorien begrenzt. Lokales Assessment führt keinen URI-Fetch aus. Report-only kann eine Capability aussagen, aber keine Zielaktivität auslösen. Keine Aussage über Reportvalidierung, menschliche Annahme oder Intake-Protokoll.

## Baseline vs. Rust-Prüfungen

Die Requirements-Matrix verknüpft normative Baseline-Fixtures/Check-IDs mit tatsächlichen Rust-Testfunktionen und ihren Loop-Assertions. Eine vorhandene Testfunktion darf mehrere Requirements abdecken, wenn für jede Zeile die konkreten Fixture-IDs und geprüften Assertions benannt sind. Publisher-/Transportpflichten sind als externe Verantwortlichkeit ausgewiesen und nicht als Core-Runtime-Proof gezählt. Vorherige Node-Assertions sind keine Rust-Nachweise.

Die Ablösung erfordert zusätzlich Interop-Vergleich mit identischen, gespeicherten Eingaben und tatsächlichen Wrapper-Mappings. Unit-Conformance allein beweist keine Drop-in-Kompatibilität. Bei relevanter Abweichung ist Ablösung blockiert; kein automatischer Fallback auf Node.

## Provenienz und Arbeitsstand

Manager-gemeldete lokale Gates: Node-frei und offline/locked auf Rust 1.88.0: 101 Unit-Tests, 7 Conformance-Loops (198 Baseline-Vektoren), 1 Interop-Fixture (14 native Extras), 1 Provenienztest und 9 Doctests bestanden; 0 übersprungen, 0 Warnungen. MSRV no-default-features Tests vollständig; MSRV all-target/all-feature Clippy mit `-Dwarnings` und rustdoc mit `-Dwarnings` bestanden. Stable `fmt` und all-target Clippy bestanden. `cargo +1.88 run --example integration` bestand und meldete `report_only`, `publisher-stated-prohibited`, CSAF `Advertised`, `usable=true`. Diese Ergebnisse wurden in dieser Dokumentationsarbeit nicht erneut ausgeführt.

Der Manager meldet einen bestandenen 220-Fall-Replay mit identischen gespeicherten Inputs (198 Baseline + 22 Extras), gegen neu gebauten gepinnten TS-Core. Request-Datei-SHA-256: `3d787d16bf28d51abaf7c446fe32c2dbf9f91f367255262f86a71b44e6d5cefd`; primärer Artefaktbericht [`../tools/interop/artifacts/report.json`](../tools/interop/artifacts/report.json), zusätzlicher Replaybericht `/tmp/opencode/cvd-rust-interop-replay/report.json`. Das belegt den beschriebenen Fallvergleich, nicht vollständige Produkt-Interop oder Drop-in-Kompatibilität.

### Eingeordnete Verhaltensdeltas aus dem Replay

Die zwölf abweichenden Zeilen umfassen zwei zulässige interne Authority-Getter-Repräsentationen und zehn TypeScript-Verhaltensabweichungen in Zahlen, URI, Zeit und RFC 9116. Im geprüften Fallbestand ist keine ungeklärte Rust-Abweichung bekannt; dies ist keine pauschale Produkt-Drop-in-Freigabe. Normative Fixtures/Erwartungen wurden nicht verändert.

| Gruppe / Fallreferenz | Beobachtung | Normative Einordnung |
|---|---|---|
| Security.txt URI getter (zwei AuthorityEvidence-Fälle) | Rust-Getter liefert ursprüngliche angefragte URI, TypeScript finale URI | Zulässige interne Evidenzdarstellung; Normbindung bleibt gleich, kein byteweises Mappingversprechen. |
| `security-rfc9116-space-after-colon` | Rust akzeptiert RFC 9116 `:` gefolgt von SP strenger als TS | Norm: RFC 9116 Feldsyntax verlangt Colon-SP; TS-Toleranz ist kein Normmaßstab. |
| Zwei Integer version rounding/overflow-Fälle (numeric-URI regressions) | TS-Zahlrepräsentation rundet bzw. läuft bei Integerfällen über, Rust prüft exakt | Norm verlangt mathematischen JSON-Integer und Version 1; Rust-Verhalten ist maßgeblich. |
| Fünf URI-Fragmentfälle (organization, contact channel, encryption, product identifier, extension identifier; numeric-URI regressions) | TS lässt Fragmente an absoluten URI-Feldern durch, Rust weist zurück | Norm bindet an absolute URI nach RFC 3986 §4.3; Fragment ist ausgeschlossen. |
| Sub-millisecond expiry (`time-probe`) | TS `Date` vergleicht Millisekunden, Rust bewahrt RFC-3339-Submillisekunden | Norm vergleicht Zeitpunkte als RFC-3339-Instants; Rust-Präzision entspricht der Norm. |
| `numeric-permission-exact-decimal-condition` | TS rundet nahe Dezimalwerte und meldet permitted; Rust vergleicht exakt und meldet conditions-not-satisfied | Norm-Ratenvergleich ist mathematisch; exakte Dezimalentscheidung ist maßgeblich. |

Der Replaybericht enthält die konkreten Case-IDs und Begründungen. Die Spec-Quelle ist Draft-01; URI-Fragmente werden insbesondere durch RFC 3986 §4.3, Zeit durch RFC 3339, security.txt durch RFC 9116 ABNF und Zahlen durch JSON-Schema-/Normsemantik beurteilt.

## Prüfprotokoll (auszufüllen)

| Prüfung | Kommando/Umgebung | Ergebnis | Revision/Artefakt | Status |
|---|---|---|---|---|
| Native Rust-Prüfungen | Rust 1.88 offline/locked, ohne Node/npm im PATH | 101 unit + 7 loops/198 Baseline + 1 interop fixture/14 extras + 1 provenance + 9 doctest; alle bestanden | Managerbericht | Gemeldet bestanden |
| MSRV Clippy / rustdoc | Rust 1.88 all-target/all-feature Clippy `-Dwarnings`; rustdoc `-Dwarnings` | Beide bestanden | Managerbericht | Gemeldet bestanden |
| Stable Gates | stable `fmt`, all-target Clippy | Bestanden | Managerbericht | Gemeldet bestanden |
| Kompilierendes Beispiel | `cargo +1.88 run --example integration` | `report_only`, `publisher-stated-prohibited`, CSAF `Advertised`, `usable=true` | Managerbericht | Gemeldet bestanden |
| 220-Fall-Replay | Identische gespeicherte Inputs; gepinnter TS-Core | Bestanden; Request SHA-256 `3d787d16bf28d51abaf7c446fe32c2dbf9f91f367255262f86a71b44e6d5cefd` | `tools/interop/artifacts/report.json` | Gemeldet bestanden; keine Produkt-Cutover-Freigabe |
| Packaging-Archivconsumer | `cargo +stable package --list --offline --locked` und `cargo +stable package --offline --locked`; 124 Dateien, anschließender entpackter eigenständiger Consumer unter MSRV | Paket 1.8 MiB / 213 KiB komprimiert; Archivconsumer-Tests vollständig bestanden | `.cargo_vcs_info` SHA-1 `dfa1d5347a23938e5b8ef9b68f5128dc4c6e3ba9`; Managerbericht | Gemeldet bestanden |
| Remote-CI | Workflow nicht remote ausgeführt | Nicht ausgeführt | — | Offen |
| Produkt-Cutover | Agent2 Endpoint-Mapping, Response und `serde_json/arbitrary_precision` Feature-Unification | Nicht freigegeben | — | Offen |
