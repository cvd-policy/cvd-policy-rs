# CVD-Policy-Format: Kandidat für Version 1

**Status:** Experimenteller Pre-Standard-Kandidat  
**Formatversion:** `1`  
**Datum:** 2026-09-01
**Lizenz:** CC0-1.0  
**Maßgebliche Fassung:** [English](SPEC.md)

Diese vollständige deutsche Übersetzung ist informativ. Bei Widersprüchen gilt ausschließlich die englische Fassung. Der Kandidat soll einen möglichen ersten Internet-Draft vorbereiten und kann sich vor oder während einer IETF-Prüfung ändern. Er ist kein RFC und stellt keinen IETF-Konsens dar.

## 1. Konventionen und Begriffe

Die Schlüsselwörter **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT** und **MAY** sind ausschließlich in der englischen maßgeblichen Fassung gemäß BCP 14 (RFC 2119 und RFC 8174) auszulegen.

Jede normative Anforderung besitzt eine stabile Kennung in eckigen Klammern. `v1/requirements.json` ordnet jede Kennung ausführbaren Tests zu.

- **Publisher:** Partei, die eine Policy veröffentlicht.
- **Discovery Host:** normalisierter Host, über den `security.txt` ursprünglich vor Redirects abgerufen wurde.
- **Policy-URI:** URI im vorgeschlagenen Feld `CVD-Policy`.
- **Target:** absolute HTTP(S)-URL, die für eine Aktivität ausgewertet wird.
- **Authority Evidence:** Ergebnis einer erfolgreichen `security.txt`-Bewertung; kein Eigentumsnachweis.
- **Reporting Scope:** Assets und Produkte, für die Berichte angenommen werden.
- **Testing Permission:** ausdrückliche Publisher-Aussage in einer passenden Testing-Regel.

## 2. Status und Nichtziele

[DOC-001] Ein Version-1-Dokument muss die JSON-Zahl `1` in `cvd_policy` enthalten; Strings und 0.x-Werte sind nicht Version 1.

[DOC-017] Ein fehlender oder nicht ganzzahliger `cvd_policy`-Member muss `invalid-policy` ergeben. Eine unbekannte ganzzahlige Version muss `unsupported-policy` ergeben.

[DOC-002] Implementierungen müssen Paketversionen und Dokumentformatversion getrennt behandeln.

`CVD-Policy` und `application/cvd-policy+json` sind vorgeschlagen und nicht bei IANA registriert. Version 1 ist ein Pre-Standard-Kandidat, kein stabiler oder veröffentlichter Standard.

Dieses Format:

- beweist kein Eigentum und keine Kontrolle über ein Asset;
- bietet keine Rechtsberatung, rechtliche Autorisierung oder garantierten Safe Harbor;
- veranlasst keine Software zur Durchführung von Tests;
- definiert keine Übermittlung von Schwachstellenberichten, Authentisierung, Retries, Anhänge oder Transporte;
- ersetzt nicht das menschenlesbare Feld `Policy` aus RFC 9116;
- definiert keine Syntax für Produktversionsbereiche.

Ein strukturiertes Protokoll zur Berichtsübermittlung kann später separat standardisiert werden. Eine Kontakt-URI darf auf ein vorhandenes Formular zeigen, ohne dieses Formular zum Bestandteil des Formats zu machen.

## 3. JSON-Verarbeitung und Validierungsebenen

[DOC-003] Policy-Text muss UTF-8-JSON nach RFC 8259 sein und genau einen Top-Level-Wert enthalten, der ein Objekt ist.

[DOC-004] Ein Parser muss Kommentare, nachgestellte Kommata, mehrere JSON-Texte, Nicht-JSON-Zahlen und doppelte Member-Namen auf jeder Ebene ablehnen.

[DOC-005] Automatische Discovery und Auswertung müssen vor normaler Objektvalidierung einen duplicate-aware Textparser verwenden.

Ein nach `JSON.parse` übergebenes JavaScript-Objekt kann nicht nachträglich auf doppelte Member geprüft werden. Objektvalidierung kann Schema- und Semantikprüfungen durchführen, aber keine Duplicate-Sicherheit behaupten.

Validierung besitzt vier getrennte Ebenen:

1. Textparsing und Duplicate-Erkennung;
2. Auswahl der Formatversion und JSON-Schema-Validierung;
3. semantische Validierung;
4. Ablauf-, Extension-, Authority-, Target-, Scope-, Regel- und Bedingungsauswertung.

[DOC-006] Ein Validator darf während der Validierung weder Defaults einfügen noch Typen konvertieren.

[DOC-007] Jedes Core-Objekt muss unbekannte Eigenschaften ablehnen; Extension-Daten sind ausschließlich unter `extensions` zulässig.

## 4. Dokumentmodell

Erforderliche Top-Level-Member:

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

Optionale Member:

```text
testing
response_targets
disclosure
critical_extensions
extensions
```

[DOC-008] Fehlende optionale Member dürfen keine Testing Permission erzeugen. Insbesondere bedeutet fehlendes `testing`, dass keine Testing Permission vorliegt.

[DOC-019] Die Core-Objekte enthalten ausschließlich die in der englischen normativen Member-Tabelle aufgeführten erforderlichen und optionalen Member. Insbesondere besitzt `reporting` die erforderlichen Member `requested_fields` und `proof_of_exploitation`; `response_targets` darf nur `acknowledgement_days`, `initial_assessment_days` und `update_interval_days` enthalten; `disclosure` erfordert `approach` und erlaubt `default_days` sowie `statement`. Als nichtleer definierte Arrays müssen mindestens einen Eintrag enthalten; `reporting.requested_fields`, `contact.preferred_languages`, `contact.encryption` und `critical_extensions` dürfen leer sein.

### 4.1 Zeit

`last_updated` und `expires` sind RFC-3339-Date-Time-Strings.

[DOC-009] `expires` muss einen Zeitpunkt strikt nach `last_updated` darstellen.

[DOC-010] Eine abgelaufene Policy muss den normativen Status `invalid-policy` ergeben und darf keine Testing Permission erzeugen. Eine detaillierte Ablaufdiagnose ist informativ und implementierungsspezifisch.

Die Auswertung akzeptiert ein injiziertes `now`. Eine Laufzeit von ungefähr einem Jahr ist nur eine nichtnormative Empfehlung.

### 4.2 Organisation

```json
{
  "name": "Example Organization",
  "uri": "https://example.com/"
}
```

[DOC-011] `organization.name` muss ein nichtleerer String sein.

[DOC-012] Falls vorhanden, muss `organization.uri` eine absolute HTTPS-URI ohne Userinfo sein.

Organisationsmetadaten begründen keine Authority.

### 4.3 Kontakt

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

[DOC-013] `contact.channels` darf nicht leer sein. Jeder Eintrag muss eine absolute URI sein und ausschließlich das Scheme `mailto`, `tel` oder `https` verwenden; das Array darf kein identisches Duplikat enthalten.

[DOC-014] HTTPS-Kontakt-URIs dürfen weder Userinfo noch ein Fragment enthalten.

Kanalreihenfolge drückt Präferenz aus. Sprachreihenfolge nicht.

[DOC-015] Jeder Wert in `preferred_languages` muss ein gültiger BCP-47-Sprach-Tag sein.

[DOC-016] `encryption`-Werte müssen absolute URIs sein und auf Schlüssel verweisen, statt Schlüsselmaterial einzubetten.

### 4.4 Research Posture

`research.posture` ist einer der folgenden Werte:

- `open`: Forschung ist grundsätzlich willkommen; nur passende ausdrückliche Regeln sagen Testing Permission aus;
- `limited`: Forschung ist nur unter ausdrücklichen Regeln willkommen;
- `report_only`: Berichte werden angenommen; aktive Tests sind unter dieser Policy nicht gestattet;
- `prohibited`: der Publisher erklärt aktive Tests als untersagt.

[TEST-001] `open` darf ohne passende `permitted`-Regel keine Permission implizieren.

[TEST-002] Eine `report_only`- oder `prohibited`-Policy darf keine `permitted`-Regel enthalten.

`research.statement` ist erklärender Text ohne Auswertungswirkung.

### 4.5 Reporting Scope

`reporting_scope` beschreibt berichtbare Assets und Produkte. Er sagt für sich keine Testing Permission aus.

[SCOP-001] Jede Scope- und Testing-Regel-ID muss dokumentweit eindeutig sein.

[DOC-018] Jede Scope- und Regel-ID muss 1 bis 128 ASCII-Zeichen lang sein, mit ASCII-Buchstabe oder Ziffer beginnen und danach nur ASCII-Buchstaben, Ziffern, `.`, `_` oder `-` enthalten. IDs und Referenzen werden als exakte case-sensitive Strings verglichen.

#### 4.5.1 Web-Einträge

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

[SCOP-002] `host` muss ein normalisierter DNS-Name, ein IPv4- oder IPv6-Literal ohne Scheme, Port, Pfad, Userinfo, Wildcard, Query oder Fragment sein.

[SCOP-003] DNS-Namen müssen zum Vergleich in kleingeschriebene ASCII-A-Labels überführt und um genau einen abschließenden Punkt gekürzt werden.

[SCOP-004] IPv4- und IPv6-Literale müssen kanonisch verglichen werden; IP-Einträge müssen `include_subdomains: false` setzen.

[SCOP-005] `schemes` muss mindestens `http` oder `https` enthalten und darf kein anderes Scheme enthalten.

Ohne `ports` gilt nur der Standardport des passenden Schemes: 80 für HTTP und 443 für HTTPS. Nichtstandardports müssen ausdrücklich aufgeführt sein.

[SCOP-006] `path_prefix` muss mit `/` beginnen und darf keine Query- oder Fragmentsyntax enthalten.

[SCOP-010] Scope-`path_prefix` und Target-Pfad müssen identisch normalisiert werden: leerer Pfad wird `/`; RFC-3986-Dot-Segmente werden entfernt; wiederholte Slashes bleiben erhalten; Hex-Ziffern in Prozenttriplets werden großgeschrieben; Prozentkodierung wird für Matching nicht dekodiert. Ungültige Prozentkodierung ist abzulehnen; encoded slash und `/` bleiben verschieden.

Pfadmatching verwendet den normalisierten URL-Pfad ohne Query oder Fragment und beachtet Groß-/Kleinschreibung. `/` passt auf alle Pfade. Ein mit `/` endendes Präfix passt auf Pfade, die damit beginnen. Jedes andere Präfix passt exakt oder mit anschließendem `/`. Daher passt `/api` auf `/api`, `/api/` und `/api/v1`, aber nicht `/apix`.

`include_subdomains: true` passt auf echte DNS-Subdomains an Labelgrenzen und auf den genannten Host. Dadurch entsteht keine Authority; jeder Target-Host benötigt eigene Discovery Evidence.

[SCOP-007] Ein passender `out`-Eintrag muss jeden passenden `in`-Eintrag unabhängig von der Array-Reihenfolge überschreiben.

[SCOP-008] Die Reihenfolge von Scope- und Regelarrays darf ein Ergebnis nicht verändern.

#### 4.5.2 Produkt-Einträge

```json
{
  "id": "example-product",
  "state": "in",
  "name": "Example Product",
  "identifiers": ["pkg:npm/example-product"]
}
```

[SCOP-009] Produkt-Einträge müssen ausschließlich als Reporting-Metadaten behandelt werden und dürfen keine automatische Testing Permission erzeugen.

Produktidentifikatoren müssen absolute RFC-3986-URIs sein und werden ohne scheme-spezifische Äquivalenz als exakte case-sensitive Strings verglichen. Versionsbereichssyntax liegt außerhalb von Version 1.

### 4.6 Testing-Regeln

Core-Aktivitäten:

- `manual_testing`: manuell initiierte Untersuchung, soweit keine spezifischere Core-Aktivität greift;
- `automated_scanning`: automatisierte Erkennung oder Schwachstellenprüfung gegen Web- oder Netzwerkdienste;
- `fuzzing`: automatisierte Übermittlung erzeugter oder mutierter Eingaben;
- `credential_testing`: Prüfung nur mit eigenen oder ausdrücklich bereitgestellten Testkonten; Credential Stuffing, Password Spraying und fremde Zugangsdaten sind ausgeschlossen.

[TEST-003] Eine Extension-Aktivität muss eine absolute URI sein; ein unbekannter unqualifizierter Wert wie `automated_scaning` ist ungültig. Aktivitäts-Identifier einschließlich Extension-URIs werden als exakte case-sensitive Strings verglichen.

Regeln verwenden `state: permitted` oder `state: prohibited`. Version 1 definiert weder `allowed` noch `testing.default` oder `explicit_order`.

[TEST-004] Eine `permitted`-Regel muss mindestens eine `target_id` enthalten.

[TEST-005] Eine `prohibited`-Regel ohne `target_ids` muss für alle Web-Targets im Reporting Scope gelten.

[TEST-006] Jede `target_id` muss einen existierenden `in`-Web-Eintrag referenzieren; Produkt- und `out`-Referenzen sind ungültig.

[TEST-007] Eine passende `prohibited`-Regel muss jede passende `permitted`-Regel überschreiben.

[TEST-008] Eine `prohibited`-Regel darf keine `conditions` enthalten; ein anwendbares Verbot ist bedingungslos.

Keine passende Regel bedeutet keine Testing Permission.

#### 4.6.1 Bedingungen

Version 1 definiert nur:

- `max_requests_per_second`: positive Zahl;
- `max_concurrent_requests`: positive Ganzzahl;
- `required_user_agent_token`: nichtleerer sichtbarer ASCII-String, der als vollständiger case-sensitiver Teilstring im geplanten User-Agent vorkommen muss;
- `test_accounts_only`: der Literalwert `true`.

[COND-001] Unbekannte Eigenschaften in `conditions` müssen die Policy strukturell ungültig machen.

[COND-002] Eine erlaubende `automated_scanning`- oder `fuzzing`-Regel muss Rate und Parallelität begrenzen.

[COND-003] Eine erlaubende `credential_testing`-Regel muss beide Limits und `test_accounts_only: true` enthalten.

[COND-004] Ein Client muss einen fehlenden erforderlichen Planwert als nicht erfüllt behandeln und darf unbekannte Bedingungen nicht ignorieren.

Eine Bedingung ist nur erfüllt, wenn geplante Rate und Parallelität vorhanden und nicht größer als ihre Limits sind, der User-Agent den erforderlichen Token enthält und die ausschließliche Verwendung kontrollierter oder bereitgestellter Testkonten ausdrücklich bestätigt wurde.

### 4.7 Reporting Preferences

`reporting.requested_fields` enthält beliebige Werte aus:

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

[REP-001] Angefragte Felder müssen als Präferenzen interpretiert werden; ein fehlendes Feld darf allein keine Zurückweisung eines Berichts bewirken.

`proof_of_exploitation` ist `not_requested`, `requested_if_safe` oder `prohibited`.

[REP-002] `requested_if_safe` darf nicht als Aufforderung zu Zugriff auf fremde Daten, Persistenz, Exfiltration, lateraler Bewegung, Schädigung, Verfügbarkeitsbeeinträchtigung oder weitergehender Ausnutzung interpretiert werden.

### 4.8 Response Targets und Disclosure

`response_targets` darf nur positive ganze `acknowledgement_days`, `initial_assessment_days` und `update_interval_days` enthalten. Acknowledgement und Initial Assessment beginnen beim Eingang des initialen Berichts; jedes Update-Intervall beginnt mit dem vorherigen substanziellen Update. Diese Werte sind keine technischen oder rechtlichen Garantien und beeinflussen die Testing-Auswertung nicht.

`disclosure.approach` ist `coordinated`, `case_by_case` oder `no_preference`. Positive `default_days` beginnen beim Eingang des initialen Berichts und sind eine Koordinationspräferenz, keine automatische Offenlegungsfreigabe. `statement` ist erklärend.

### 4.9 Erweiterungen

Extension-IDs sind absolute RFC-3986-URIs und werden als exakte case-sensitive Strings verglichen. Extension-Daten stehen nur als Werte unter `extensions`; `critical_extensions` ist eine Liste eindeutiger IDs.

[EXT-001] Jede ID in `critical_extensions` muss einen gleichnamigen Member in `extensions` besitzen.

[EXT-002] Eine unbekannte kritische Extension muss bei Permission-Auswertung `unsupported-policy` ergeben.

[EXT-003] Eine unbekannte nichtkritische Extension darf als Metadatum ignoriert werden und darf kein Core-Verbot oder keine Core-Bedingung abschwächen.

[EXT-004] Eine Extension, die Permission, Verbot oder Bedingungen verändert, muss als kritisch markiert sein.

#### CSAF Vulnerability Report-Deklaration

Diese optionale, nichtkritische Deklaration benennt vorhandene Kontaktkanäle, an denen ein Publisher nach eigener Aussage Berichte gemäß dem CSAF Vulnerability Report Profile annimmt. Sie definiert weder Berichtsübermittlung noch eine Submission-API oder CSAF-Berichtsvalidierung. Core-Implementierungen müssen sie nicht verarbeiten.

Die Extension-ID lautet `https://github.com/cvd-policy/spec/extensions/csaf-vulnerability-report-v1`. Die unterstützte Spezifikations-URI ist `https://docs.oasis-open.org/csaf/csaf/v2.1/csd04/csaf-v2.1-csd04.html`. Sie bindet die Deklaration an Profile 9, Vulnerability Report, Abschnitt 4.9 von CSAF Version 2.1 Committee Specification Draft 04 (21. Oktober 2026, Arbeitsfassung). Implementierungen vergleichen die URI nach JSON-Dekodierung exakt und case-sensitive. Der zugehörige CSAF-Bericht hat `document.csaf_version` `2.1` und `document.category` `csaf_vulnerability_report`.

Der Extensionwert enthält ausschließlich ein nichtleeres `channels`-Array. Jedes Element enthält ausschließlich die String-Member `uri` und `specification`. Eine URI muss nach JSON-Dekodierung exakt einem Wert in `contact.channels` entsprechen, `mailto` oder `https` verwenden und darf höchstens einmal vorkommen. Es gibt keine URI-Normalisierung oder Redirect-Auflösung. `tel` ist unzulässig. Die Reihenfolge des Extension-Arrays ist bedeutungslos; bei der Auswahl gilt die Reihenfolge von `contact.channels`. Jede Spezifikation ist eine absolute RFC-3986-URI. Eine andere syntaktisch gültige URI ist unsupported, nicht strukturell ungültig. Extension-ID und Spezifikation werden nicht abgerufen.

[CSR-001] Der einzige unterstützte Wert von `specification` MUSS exakt der oben angegebene CSAF-2.1-CSD04-URI entsprechen.

[CSR-002] Das Extension-Objekt MUSS ausschließlich das erforderliche nichtleere `channels`-Array mit Objekten besitzen, die exakt die erforderlichen String-Member `uri` und `specification` enthalten.

[CSR-003] Jede `uri` MUSS nach JSON-Dekodierung exakt einem Kontaktkanal entsprechen, `mailto` oder `https` verwenden und höchstens einmal vorkommen; URI-Normalisierung und Redirect-Auflösung sind ausgeschlossen.

[CSR-004] Die Reihenfolge der Extension-Kanäle ist bedeutungslos; bei einer Auswahl MÜSSEN Clients die Präferenzreihenfolge aus `contact.channels` einhalten.

[CSR-005] Jede `specification` MUSS eine absolute RFC-3986-URI sein; eine syntaktisch gültige URI außerhalb der exakten unterstützten Bindung ist unsupported.

[CSR-006] Die Bewertung DARF weder die Extension-ID noch die `specification`-URI abrufen.

Die Bewertung ist von Core-Validierung und Testing Permission getrennt. Doppelte Member-Namen bleiben globale Policyfehler. Nach erfolgreichem Textparsing, Versionswahl sowie Core-Struktur- und Semantikprüfung gilt folgende Reihenfolge:

1. Fehlende Extension-Daten ergeben `not-advertised`.
2. Struktur-, URI-, Eindeutigkeits- oder Kontaktreferenzfehler ergeben `invalid`. Diese Fehler werden vor einer Einstufung unsupported geprüft.
3. Eine kritische Deklaration oder eine syntaktisch gültige nicht unterstützte Spezifikation ergibt `unsupported`.
4. Sonst lautet das Ergebnis für alle Kanäle `advertised`.

Die Ergebnisse sind atomar. Für `not-advertised`, `invalid` und `unsupported` sind keine Kanäle verwendbar; Teilerfolge sind unzulässig. Diese Zustände behaupten nicht, dass CSAF-Berichte abgelehnt werden.

[CSR-007] Die Bewertung MUSS die genannte Reihenfolge und Atomarität einhalten.

[CSR-008] Diese Extension DARF NICHT in `critical_extensions` stehen. Ist sie dort enthalten, MUSS eine sie erkennende Implementierung die Verwendung in Permission-Schritt 6 als unsupported kritisches Verhalten behandeln, sofern kein früherer Schritt das Ergebnis bestimmt.

[CSR-009] Fehler einer nichtkritischen Deklaration DÜRFEN Core-Gültigkeit oder Testing Permission NICHT ändern. Die Deklarationsbewertung bleibt von Core-Struktur- und Semantikvalidierung getrennt; globale Regeln zu doppelten Schlüsseln und Core-Membern gelten weiter.

[CSR-010] Vor Verwendung eines `advertised`-Ergebnisses als aktuelle Aussage eines Discovery Hosts MUSS ein Client gültige Authority und gebundenen Policy-Abruf, Aktualität von Policy und `security.txt` sowie unterstütztes kritisches Verhalten prüfen. Target, Aktivität oder positive Testing Permission sind dafür nicht erforderlich. Auch eine `report_only`-Policy kann CSAF-Annahme deklarieren.

[CSR-011] Ein Publisher MUSS nur Kanäle aufführen, an denen er Berichte gemäß dem gebundenen CSAF-Profil annimmt. Die Deklaration ist seine Aussage über dieses Angebot. Ein Client DARF eine gültige Deklaration NICHT als Nachweis darstellen, dass ein Kanal getestet wurde, ein Bericht CSAF-konform ist oder ein Finding angenommen oder bestätigt wurde.

[CSR-012] Die Deklaration spezifiziert weder Berichtsübermittlung, Request-Methode, Intake-API, Authentisierung, Anhänge, Bestätigungen noch Fallverwaltung. Insbesondere DARF ein Client NICHT ableiten, dass ein deklarierter HTTPS-Kontakt ein POST-Endpunkt ist oder dass das Lesen der Deklaration eine Berichtsübermittlung autorisiert.

[CSR-013] Die Deklaration DARF CSAF nicht für alle Berichte verlangen oder die Ablehnung menschenlesbarer Berichte begründen. Core-Reporting-Präferenzen bleiben unverändert; CSAF-Anforderungen bestimmen nur CSAF-Konformität.

[CSR-014] Ein Client DARF aus Policy-Organisation oder Scope keine CSAF-Publisher-Identität, Betroffenheit oder Schwachstelle ableiten. Reporting Scope belegt keine Verwundbarkeit. Das `CSAF`-Feld in `security.txt` dient der Discovery von Provider-Metadaten für Verteilung, nicht der Berichtsannahme oder einem Intake-Endpunkt; Policy-Extensions sind von CSAF-Extensions getrennt.

## 5. Discovery über security.txt

Vorgeschlagenes Feld:

```text
CVD-Policy: https://example.com/cvd-policy.json
```

[DISC-001] Ein `CVD-Policy`-Wert muss genau eine absolute HTTPS-URI ohne Userinfo oder Fragment sein.

[DISC-002] Feldnamen müssen case-insensitive geparst werden; automatische Verarbeitung muss mehrere `CVD-Policy`-Felder ablehnen, statt eines auszuwählen.

[DISC-003] Ein Consumer darf bei fehlendem Feld weder `/.well-known/cvd.json` noch einen anderen Policy-Pfad raten.

Policy-Host und Discovery Host dürfen verschieden sein. Dateiname und Erweiterung besitzen keine normative Bedeutung. Bestehende `Policy`-Felder bleiben Links zu Human Policies; Reihenfolge und Mehrfachvorkommen bleiben erhalten.

`CVD-Policy` ist vorgeschlagen und unregistriert. Ein lokaler Generator darf `https://example.com/cvd-policy.json` vorschlagen; dies ist kein Discovery-Default.

### 5.1 Bewertung von security.txt

Kontexteingabe:

```ts
interface SecurityTxtRetrievalContext {
  requestedUri: string;
  finalUri: string;
  redirectChain: string[];
  retrievedAt: Date;
}
```

[DISC-004] Authority Evidence darf nur entstehen, wenn die Datei parsebar ist, mindestens einen gültigen `Contact`, genau ein syntaktisch gültiges `Expires` mit einem Zeitpunkt nach `retrievedAt` und genau ein gültiges `CVD-Policy` enthält. Ein syntaktisch ungültiges `Expires` und ein gültiges, aber abgelaufenes `Expires` sind verschiedene Diagnosefälle; beide begründen keine Authority.

[DISC-005] Kontext-URIs und jeder Redirect-Hop müssen HTTPS verwenden; Redirect-Verarbeitung muss den ursprünglichen Discovery Host erhalten.

Weicht der finale Redirect-Host vom angeforderten Host ab, muss mindestens ein gültiges `Canonical` exakt der ursprünglich angeforderten security.txt-URI entsprechen.

[DISC-006] Ein Cross-Host-Redirect ohne diesen exakten ursprünglichen `Canonical`-Wert darf keine Authority begründen. Eine detaillierte Canonical-Mismatch-Diagnose ist informativ und implementierungsspezifisch.

[DISC-008] Sobald mindestens ein `Canonical` vorhanden ist, muss vor Authority mindestens ein Wert exakt der ursprünglich angeforderten security.txt-URI entsprechen. Dies gilt ohne Redirect und bei Same-Host-Redirects.

OpenPGP-Cleartext-Signaturen werden an ihrem RFC-9116-Frame erkannt. Core-Software muss sie nicht verifizieren.

[DISC-007] Software, die eine signierte security.txt nicht echt neu signieren kann, darf sie nicht automatisch umschreiben.

## 6. Authority-Modell

[AUTH-001] Automatische Permission-Auswertung muss ein von erfolgreicher security.txt-Bewertung erzeugtes `AuthorityEvidence` verlangen; ein vom Aufrufer übergebener Host-String reicht nicht.

```ts
interface AuthorityEvidence {
  established: true;
  discoveryHost: string;
  securityTxtUri: string;
  cvdPolicyUri: string;
  securityTxtExpires: string;
}
```

[AUTH-002] Discovery Host muss unabhängig von security.txt-Redirects, Policy-Hosting oder Policy-Redirects der Host der ursprünglich angeforderten security.txt-URI bleiben.

[AUTH-003] Normalisierter Target Host und normalisierter Discovery Host müssen vor einem positiven Permission-Status exakt übereinstimmen.

[AUTH-004] Parent-Domains, Subdomains, CNAME-Ziele, gemeinsame Adressen, Zertifikate, Organisationsbehauptungen, Scope-Wildcards, Policy-Ort, Dateinamen und Redirects dürfen Authority weder erzeugen noch übertragen.

[AUTH-005] Authority Evidence muss an ihre beworbene `cvdPolicyUri` gebunden sein. Die ausgewertete Repräsentation muss von genau dieser URI oder der finalen URI ihrer aufgezeichneten reinen HTTPS-Redirect-Kette stammen. Beliebiges Policy-JSON darf nicht mit Authority Evidence einer anderen Policy-URI kombiniert werden.

Ein anderer Port desselben exakten Hosts kann bei passendem Scope erfasst sein. Zwei Discovery Hosts können unabhängig auf dieselbe zentrale Policy zeigen; jede Auswertung nutzt die Evidence des eigenen Hosts.

## 7. Abruf der Policy-Repräsentation

Der vorgeschlagene, unregistrierte Medientyp ist `application/cvd-policy+json`.

[FETCH-001] Netzwerkclients müssen `application/cvd-policy+json` akzeptieren. Ein separat aktivierter Kompatibilitätsmodus darf `application/json` mit Hinweis akzeptieren, aber keine weiteren Medientypen. HTML, Plain Text und andere unerwartete Repräsentationen sind abzulehnen.

[FETCH-002] Ein Netzwerkclient muss die Policy-URI per HTTPS `GET` gemäß RFC 9110 abrufen, in `Accept` `application/cvd-policy+json` bevorzugen und nur bei aktivem Kompatibilitätsmodus `application/json` aufführen. Nur `200 OK` ist eine vollständige Policy-Repräsentation; insbesondere `204` und `206` sind es nicht. Jeder Redirect-Hop muss HTTPS verwenden. Ambient Credentials, Cookies, `Authorization` und `Proxy-Authorization` dürfen weder automatisch gesendet noch über Redirects weitergereicht werden.

Lokale Dateien besitzen keinen HTTP-Medientyp. Endliche Redirect-, Zeit- und Größenlimits, Adressfilterung und Credential-Isolation gehören in Clients oder Adapter. Der deterministische Core prüft übergebene Retrieval Evidence und führt keine Netzwerkrequests aus.

## 8. Auswertung

### 8.1 Query und Result

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

`target` akzeptiert ausschließlich eine absolute HTTP- oder HTTPS-URL ohne Userinfo. Product-Identifier und alle anderen URI-Schemes sind keine Evaluation-Targets. Scheme und Host werden durch den URL-Parser normalisiert; fehlende Ports werden zu 80 oder 443; Query und Fragment beeinflussen Scope nicht.

Die Target-Syntax wird vor der Policy-Auswertung validiert. Ungültige Target-Eingaben erzeugen einen typisierten Eingabevalidierungsfehler mit maschinenlesbaren Issues und ohne Evaluation-Status. Sie dürfen weder `not-covered` noch einen anderen normativen Evaluation-Status erzeugen.

Eine abgeschlossene Policy-Auswertung erzeugt genau einen dieser sieben normativen Statuswerte:

```text
publisher-stated-permitted
publisher-stated-prohibited
not-covered
authority-not-established
conditions-not-satisfied
invalid-policy
unsupported-policy
```

[EVAL-001] Das primäre öffentliche Ergebnis darf kein Boolean namens `allowed`, `authorized` oder `safe` sein.

[EVAL-002] Aufrufende Software muss jeden anderen Status als `publisher-stated-permitted` als nicht belegte Testing Permission behandeln.

`publisher-stated-permitted` bedeutet nur, dass die über belegte Discovery veröffentlichte Policy eine passende Erlaubnisaussage enthält, deren maschinenprüfbare Bedingungen erfüllt sind. Es ist keine Rechtsberatung, kein Eigentumsnachweis, keine Autorisierung durch Software und kein garantierter Safe Harbor.

Ein statustragendes Ergebnis kann sortierte passende Regel- und Target-IDs, Validierungsprobleme und implementierungsspezifische Diagnosen enthalten. Detaillierte Diagnose-Identifier sind nicht Teil des normativen Interoperabilitätsvertrags.

[EVAL-005] Sobald mindestens eine anwendbare `permitted`-Regel vollständig erfüllt ist, muss das Ergebnis `publisher-stated-permitted` sein. Alle erfüllten Regel-IDs dürfen informativ ausgegeben werden. Draft 00 definiert weder lexikografische Regelauswahl noch ein aggregiertes Constraint-Objekt; jede erfüllte Regel behält ihre eigenen Bedingungen.

### 8.2 Verbindliche Reihenfolge

[EVAL-003] Nach erfolgreicher Validierung und Normalisierung der Target-Eingabe muss ein Evaluator diese Schritte in Reihenfolge ausführen:

1. duplicate-aware JSON-Parsen;
2. Formatversionsprüfung;
3. JSON-Schema-Validierung;
4. semantische Validierung;
5. Ablaufprüfung;
6. Prüfung unbekannter kritischer Extensions;
7. Authority-Evidence- und Policy-Retrieval-Bindungsprüfung;
8. exakter Target-/Discovery-Hostvergleich;
9. Reporting-Scope-Matching;
10. `out`-Ausschluss;
11. Research-Posture-Prüfung;
12. Sammlung passender Regeln;
13. Verbotspräzedenz;
14. Bedingungsprüfung aller erlaubenden Regeln;
15. stabile Konstruktion eines statustragenden Ergebnisses.

### 8.3 Statuspräzedenz

Das erste anwendbare Ergebnis in Auswertungsreihenfolge gewinnt:

- `invalid-policy`: Parse-, Duplicate-, Schema-, Semantik-, Referenz-, Posture-, andere target-unabhängige Policy- oder Ablauffehler;
- `unsupported-policy`: unbekannte Formatversion, kritische Extension oder angefragte Extension-Aktivität;
- `authority-not-established`: fehlende/ungültige Evidence oder Host-Mismatch;
- `not-covered`: ein syntaktisch gültiges normalisiertes Target hat keinen passenden `in`-Web-Scope, passt auf einen `out`-Web-Scope oder hat keine passende Testing-Regel;
- `publisher-stated-prohibited`: `report_only`, `prohibited` oder passende Verbotsregel;
- `conditions-not-satisfied`: passende Erlaubnisregeln, aber keine erfüllt alle Bedingungen;
- `publisher-stated-permitted`: mindestens eine vollständig erfüllte Erlaubnisregel und kein früheres Ergebnis.

[EVAL-004] Ein positiver Status muss eine gültige nicht abgelaufene Policy, unterstütztes kritisches Verhalten, belegte Authority, exakte Target-/Discovery-Hostgleichheit, passenden `in`-Scope, kein `out`, kein passendes Verbot und eine vollständig erfüllte Erlaubnisregel voraussetzen.

## 9. Maschinenlesbare Fehler und informative Diagnosen

[ERR-001] Eingabevalidierungs- und Policy-Verarbeitungsfehler müssen maschinenlesbar sein und, soweit verfügbar, betroffene Stellen identifizieren. Lokalisierte Prosa darf nicht der einzige API-Vertrag sein. Implementierungen müssen nicht dieselben detaillierten Diagnose-Identifier verwenden.

[ERR-002] Nur Fehler der Evaluation-Call-Eingabevalidierung, etwa eine ungültige Target-URL, liegen strukturell außerhalb statustragender Ergebnisse. Policy-Parsing, Version Dispatch, Schema-, Semantik-, Referenz- und Ablauffehler bleiben normale statustragende Ergebnisse; `invalid-policy` ist insbesondere ein normativer Evaluation-Status.

Die folgenden Identifier sind informative Diagnosen der Referenzimplementierung. Sie bilden kein normatives Register; Konformität verlangt nicht, dass andere Implementierungen sie emittieren:

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

`target_url_invalid` gehört zu einem typisierten Eingabevalidierungsfehler und trägt niemals einen normativen Evaluation-Status. `policy_condition_invalid` entfällt, weil Version 1 keinen separaten Cross-Field-Condition-Fehler neben Schema-Validierung und den vorhandenen spezifischen semantischen Diagnosen definiert.

## 10. Sicherheitsbetrachtungen

[SEC-001] Jede sicherheitsrelevante Mehrdeutigkeit in Parsing, Authority, Scope, Regeln, Bedingungen oder Extensions muss fail-closed behandelt werden.

Ein kompromittierter Host kann irreführende Daten veröffentlichen. Authority Evidence dokumentiert die Veröffentlichung über diesen Host; sie beweist kein Eigentum, keine Organisationskontrolle und keine rechtliche Permission. Riskante Entscheidungen sollten unabhängig bestätigt werden.

Policies und security.txt sind nicht vertrauenswürdige Eingaben. Netzwerkclients sollten HTTPS, Redirect- und Body-Limits, Timeouts, Medientypen, fehlendes Credential-Forwarding sowie standardmäßige Sperren für Loopback, Link-local, private, reservierte und Metadata-Adressen durchsetzen.

Rate und Parallelität beschreiben Publisher-Aussagen; dieses Projekt führt keine Scans aus. Parser sollten Größe, Verschachtelung und Ressourcenverbrauch begrenzen.

## 11. Datenschutzbetrachtungen

[PRIV-001] Implementierungen dürfen Policy-Text, security.txt-Text, Target-Details oder Researcher-Planwerte nicht übertragen, außer der Nutzer startet ausdrücklich einen erforderlichen Netzwerkvorgang.

Kontakt- und Researcher-Daten können personenbezogen sein. Oberflächen sollten Speicherung minimieren, Analytics und Tracking vermeiden und Netzwerkziele erklären. `requested_if_safe` rechtfertigt nie das Sammeln fremder Daten oder weitergehende Ausnutzung.

## 12. IANA-Erwägungen

Dieser Kandidat beantragt keine Registrierung. Ein späterer Internet-Draft kann die Registrierung des vorgeschlagenen security.txt-Feldes `CVD-Policy` und des Medientyps `application/cvd-policy+json` beantragen. Version 1 definiert keinen Well-Known-Policy-Pfad.
