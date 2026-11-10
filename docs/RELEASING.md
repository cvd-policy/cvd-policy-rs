# Release und Veröffentlichung

Dieses Dokument beschreibt den Release-Ablauf für `cvd-policy` im Repository [cvd-policy/cvd-policy-rs](https://github.com/cvd-policy/cvd-policy-rs). Commit `81dbc104e68efc1ea07a22a63bfba061e862f570` ist auf `origin/main` gepusht. Die Remote-Main-CI ist für MSRV 1.88.0 und Stable erfolgreich (Run [42795131111](https://github.com/cvd-policy/cvd-policy-rs/actions/runs/42795131111)). Version `0.1.0` ist auf [crates.io](https://crates.io/crates/cvd-policy) veröffentlicht (SHA-256: `4d145b55b7f56bdf58c45804f9aac3241ceefb84c8cbe5ce502015ee95ac8414`). Der Bootstrap und die Trusted-Publisher-Konfiguration sind abgeschlossen; der automatische Tag-/OIDC-Releasepfad wird mit `0.1.1` erprobt und ist noch nicht erfolgreich ausgeführt.

## Release-Gate

Der Release-Workflow akzeptiert nur Tags der Form `v*` und gleicht den Tag-Inhalt exakt mit der Cargo-Paketversion ab. Der zu veröffentlichende Commit muss von `main` abstammen und das CI-Gate bestanden haben. Das Gate umfasst MSRV 1.88 und Stable. Vor der Veröffentlichung muss das gepackte Crate verifiziert sein; veröffentlichter Inhalt und Prüfsummen müssen an denselben freigegebenen Commit gebunden sein. Die Workflow-Guards wurden lokal getestet.

Nach erfolgreichem Gate veröffentlicht der Workflow über OpenID Connect (OIDC) und stellt ein GitHub Release mit dem `.crate`-Archiv und dessen SHA-256-Prüfsumme bereit. Nutzer können diese Artefakte samt Prüfsumme manuell prüfen. Diese Release-End-to-End-Strecke und der Artefakttransfer wurden noch nicht ausgeführt; ein erfolgreicher Main-CI-Lauf belegt sie nicht.

## Trusted Publishing und Bootstrap

Die crates.io-Authentifizierung verwendet [Trusted Publishing](https://crates.io/docs/trusted-publishing) mit `rust-lang/crates-io-auth-action@v1`, kurzlebigem OIDC-Token und `id-token: write` für den GitHub-Job. Die crates.io-Umgebung muss exakt `crates-io` heißen. Trusted Publisher muss auf crates.io für das Repository `cvd-policy/cvd-policy-rs` und Workflow `release.yml` registriert sein.

**Erstveröffentlichung ist ein separater, einmaliger Bootstrap-Schritt.** Ein Trusted Publisher kann nicht die Erstveröffentlichung eines noch nicht existierenden Crates ausführen. Eine berechtigte Person mit crates.io-Konto und verifizierter E-Mail-Adresse muss die erste Veröffentlichung mit einem API-Credential außerhalb dieses Chats vornehmen und danach in den Crate-Einstellungen den Trusted Publisher registrieren. Das Credential gehört weder in Chat noch Repository. Es ist kein persistenter API-Token-Fallback für den Workflow vorgesehen.

Für den Bootstrap mussten Release-Metadatenquelle und Git-Commit für `0.1.0` lokal geprüft und gepusht werden. Ein `v0.1.0`-Tag durfte nicht OIDC-Publishes versuchen, bevor das Paket existierte und Trusted Publishing konfiguriert war. Die berechtigte Person hat `0.1.0` manuell veröffentlicht und Trusted Publisher eingerichtet. Der automatische Tag-Workflow soll erstmals für `0.1.1` erprobt werden; ein erfolgreicher Lauf ist noch nicht bestätigt.

Die GitHub-Umgebung `crates-io` ist eingerichtet und für `v*`-Tags zugelassen; Actions sind aktiviert. Es ist derzeit kein erforderlicher Reviewer konfiguriert, daher blockiert keine manuelle Environment-Freigabe den Tag-Job. Schlägt Authentifizierung oder Publish fehl, muss der Job als fehlgeschlagen enden; er darf keinen Erfolg vortäuschen und kein GitHub Release als erfolgreich publiziert melden.

## Maintainer-Checkliste

1. Workflows und Branchschutz im Ziel-Repository prüfen; `main`-CI erfolgreich abwarten.
2. Sicherstellen, dass gepushter Commit und gepackter Crate-Inhalt dem geprüften Stand entsprechen.
3. Erstveröffentlichung `0.1.0` und Trusted-Publisher-Registrierung sind abgeschlossen.
4. GitHub Environment `crates-io` ist eingerichtet (siehe oben).
5. Für reguläre Releases Tag-Version exakt mit `Cargo.toml` abgleichen und sicherstellen, dass der Commit auf `main` liegt.
6. Workflow-Ergebnis und Release-Artefakte prüfen. `.crate` und SHA-256-Prüfsumme müssen zum publizierten Paket gehören.

Remote-Main-CI und lokal getestete Workflow-Guards sind bestätigt; Run [42795131111](https://github.com/cvd-policy/cvd-policy-rs/actions/runs/42795131111). Die manuelle crates.io-Erstveröffentlichung `0.1.0` ist abgeschlossen; der veröffentlichte Crate-Checksum ist oben dokumentiert. Ein erfolgreicher automatisierter Tag-/OIDC-Lauf, das zugehörige GitHub Release und der Artefakttransfer sind noch nicht nachgewiesen. Der erste automatisierte Releaseversuch für `0.1.1` steht aus.
