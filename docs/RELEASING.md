# Release und Veröffentlichung

Dieses Dokument beschreibt den vorgesehenen Release-Ablauf für `cvd-policy` im Repository [cvd-policy/cvd-policy-rs](https://github.com/cvd-policy/cvd-policy-rs). Es behauptet nicht, dass CI- oder Release-Workflows bereits ausgeführt oder verifiziert sind. Das öffentliche GitHub-Repository ist angelegt; es wurde noch kein Push, Tag oder crates.io-Publish durchgeführt. `cvd-policy` `0.1.0` ist derzeit nicht auf crates.io verfügbar.

## Geplanter Release-Gate

Der Release-Workflow soll nur Tags der Form `v*` akzeptieren und den Tag-Inhalt exakt mit der Cargo-Paketversion abgleichen. Der zu veröffentlichende Commit muss von `main` abstammen und das CI-Gate bestanden haben. Das Gate umfasst MSRV 1.88 und Stable. Vor der Veröffentlichung muss das gepackte Crate verifiziert sein; veröffentlichter Inhalt und Prüfsummen müssen an denselben freigegebenen Commit gebunden sein.

Nach erfolgreichem Gate soll der Workflow über OpenID Connect (OIDC) veröffentlichen und ein GitHub Release mit dem `.crate`-Archiv und dessen SHA-256-Prüfsumme bereitstellen. Nutzer können diese Artefakte samt Prüfsumme manuell prüfen. Diese Beschreibung ist eine Anforderung an die geplanten Workflows, kein Nachweis eines konkreten Workflow-Laufs oder Release-Artefakts.

## Trusted Publishing und Bootstrap

Die geplante crates.io-Authentifizierung verwendet [Trusted Publishing](https://crates.io/docs/trusted-publishing) mit `rust-lang/crates-io-auth-action@v1`, kurzlebigem OIDC-Token und `id-token: write` für den GitHub-Job. Die crates.io-Umgebung muss exakt `crates-io` heißen. Trusted Publisher muss auf crates.io für das Repository `cvd-policy/cvd-policy-rs` und Workflow `release.yml` registriert sein.

**Erstveröffentlichung ist ein separater, einmaliger Bootstrap-Schritt.** Ein Trusted Publisher kann nicht die Erstveröffentlichung eines noch nicht existierenden Crates ausführen. Eine berechtigte Person mit crates.io-Konto und verifizierter E-Mail-Adresse muss die erste Veröffentlichung mit einem API-Credential außerhalb dieses Chats vornehmen und danach in den Crate-Einstellungen den Trusted Publisher registrieren. Das Credential gehört weder in Chat noch Repository. Es ist kein persistenter API-Token-Fallback für den Workflow vorgesehen.

Vor diesem Bootstrap muss die Release-Metadatenquelle, insbesondere der Git-Commit für `0.1.0`, lokal geprüft und auf das Repository gepusht sein. Daher darf kein Tag `v0.1.0` den OIDC-Publish versuchen, bevor das Paket existiert und die Trusted-Publisher-Konfiguration abgeschlossen ist. Der einmalige Bootstrap-Publish von `0.1.0` erfolgt durch die berechtigte Person; nach erfolgreicher Einrichtung können spätere Versionen, etwa `0.1.1`, den vorgesehenen Tag-Workflow durchlaufen.

Die GitHub-Umgebung `crates-io` ist eingerichtet: Sie ist für `v*`-Tags zugelassen, Actions sind aktiviert und `bxn-dev` ist als erforderlicher Reviewer eingetragen. Selbstfreigabe ist erlaubt (`preventSelfReview: false`), damit der einzelne Maintainer nicht blockiert wird. Das belegt nur die Environment-Konfiguration, nicht einen Workflow-Lauf. Schlägt Authentifizierung oder Publish fehl, muss der Job als fehlgeschlagen enden; er darf keinen Erfolg vortäuschen und kein GitHub Release als erfolgreich publiziert melden.

## Maintainer-Checkliste

1. Workflows und Branchschutz im Ziel-Repository prüfen; `main`-CI erfolgreich abwarten.
2. Sicherstellen, dass gepushter Commit und gepackter Crate-Inhalt dem geprüften Stand entsprechen.
3. Die berechtigte crates.io-Kontoinhaberin oder der Kontoinhaber veröffentlicht einmalig `0.1.0` und registriert danach Trusted Publisher mit den oben genannten exakten Werten. Die konkreten Bootstrap-Schritte sind einem separaten Follow-up vorbehalten.
4. GitHub Environment `crates-io` ist bereits konfiguriert (siehe oben).
5. Erst nach abgeschlossenem Bootstrap reguläre Versions-Tags setzen; Tag-Version muss mit `Cargo.toml` übereinstimmen und auf `main` liegen.
6. Workflow-Ergebnis und Release-Artefakte prüfen. `.crate` und SHA-256-Prüfsumme müssen zum publizierten Paket gehören.

Es gibt derzeit keine bestätigten Run-IDs, erfolgreichen Remote-CI-Läufe, Tag-Releases, crates.io-Veröffentlichungen oder verifizierten Release-Prüfsummen. Die GitHub-Environment-Konfiguration ist erfolgt; übrige Remote-Ausführung und der crates.io-Bootstrap bleiben offen.
