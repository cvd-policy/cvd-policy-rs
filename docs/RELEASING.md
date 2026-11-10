# Release und Veröffentlichung

Dieses Dokument beschreibt den Release-Ablauf für `cvd-policy` im Repository [cvd-policy/cvd-policy-rs](https://github.com/cvd-policy/cvd-policy-rs). `0.1.0` wurde manuell veröffentlicht (SHA-256 `4d145b55b7f56bdf58c45804f9aac3241ceefb84c8cbe5ce502015ee95ac8414`); der einmalige Bootstrap und die Trusted-Publisher-Konfiguration sind abgeschlossen. Tag `v0.1.1` verweist auf Source-Commit `7f52cdd94cb914ba894427a7e2999f97f2f75192`; dessen Main-CI lief für Rust 1.88 und Stable erfolgreich (Run [42803873595](https://github.com/cvd-policy/cvd-policy-rs/actions/runs/42803873595)). Der automatisierte Tag-Release lief erfolgreich (Run [42804207280](https://github.com/cvd-policy/cvd-policy-rs/actions/runs/42804207280)): validierte Gates, verifiziertes Paket und Artefakttransfer, OIDC-Publish sowie Nachvergleich der Paketbytes und GitHub Release. Die crates.io-Version [`0.1.1`](https://crates.io/crates/cvd-policy/0.1.1) ist veröffentlicht (SHA-256 `d69900e225f2b59830baa0c19d69ce9122b47d1806c781346819374d85841655`), nicht yanked. Der Registry-Download und das GitHub-Release-Artefakt sind bytegleich mit dem lokal verifizierten `.crate`-Archiv; dessen VCS-Metadaten nennen `7f52cdd94cb914ba894427a7e2999f97f2f75192`, und alle 13 Rust-Quelldateien stimmen mit diesem Commit überein.

## Release-Gate

Der Release-Workflow akzeptiert nur Tags der Form `v*` und gleicht den Tag-Inhalt exakt mit der Cargo-Paketversion ab. Der zu veröffentlichende Commit muss von `main` abstammen und das CI-Gate bestanden haben. Das Gate umfasst MSRV 1.88 und Stable. Vor der Veröffentlichung muss das gepackte Crate verifiziert sein; veröffentlichter Inhalt und Prüfsummen müssen an denselben freigegebenen Commit gebunden sein. Die Workflow-Guards wurden lokal getestet.

Nach erfolgreichem Gate veröffentlicht der Workflow über OpenID Connect (OIDC) und stellt ein GitHub Release mit dem `.crate`-Archiv und dessen SHA-256-Prüfsumme bereit. Für `v0.1.1` wurden Paketbytes vor und nach Veröffentlichung verglichen; GitHub Release und Artefakte wurden erfolgreich erstellt und übertragen (Run [42804207280](https://github.com/cvd-policy/cvd-policy-rs/actions/runs/42804207280)).

## Trusted Publishing und Bootstrap

Die crates.io-Authentifizierung verwendet [Trusted Publishing](https://crates.io/docs/trusted-publishing) mit `rust-lang/crates-io-auth-action@v1`, kurzlebigem OIDC-Token und `id-token: write` für den GitHub-Job. Die crates.io-Umgebung muss exakt `crates-io` heißen. Trusted Publisher muss auf crates.io für das Repository `cvd-policy/cvd-policy-rs` und Workflow `release.yml` registriert sein.

**Erstveröffentlichung ist ein separater, einmaliger Bootstrap-Schritt.** Ein Trusted Publisher kann nicht die Erstveröffentlichung eines noch nicht existierenden Crates ausführen. Eine berechtigte Person mit crates.io-Konto und verifizierter E-Mail-Adresse muss die erste Veröffentlichung mit einem API-Credential außerhalb dieses Chats vornehmen und danach in den Crate-Einstellungen den Trusted Publisher registrieren. Das Credential gehört weder in Chat noch Repository. Es ist kein persistenter API-Token-Fallback für den Workflow vorgesehen.

Für den einmaligen Bootstrap wurden Release-Metadatenquelle und Git-Commit für `0.1.0` lokal geprüft und gepusht. Eine berechtigte Person hat `0.1.0` manuell veröffentlicht und Trusted Publisher eingerichtet. Der automatische Tag-/OIDC-Release für `v0.1.1` wurde erfolgreich ausgeführt; Run [42804207280](https://github.com/cvd-policy/cvd-policy-rs/actions/runs/42804207280).

Die GitHub-Umgebung `crates-io` ist eingerichtet und für `v*`-Tags zugelassen; Actions sind aktiviert. Es ist derzeit kein erforderlicher Reviewer konfiguriert, daher blockiert keine manuelle Environment-Freigabe den Tag-Job. Schlägt Authentifizierung oder Publish fehl, muss der Job als fehlgeschlagen enden; er darf keinen Erfolg vortäuschen und kein GitHub Release als erfolgreich publiziert melden.

## Zukünftige Releases

1. Paketversion aktualisieren und beide Lockfiles über Cargo aktualisieren; relevante Änderungen committen und auf `main` pushen.
2. Erfolgreiche Main-CI abwarten.
3. Den exakten passenden Tag `vX.Y.Z` auf den geprüften `main`-Commit setzen und pushen.
4. Automatischen Release-Workflow und veröffentlichtes crates.io-Paket samt GitHub-Artefakten prüfen.

Für reguläre Tags sind weder ein manueller API-Token noch eine Environment-Reviewerfreigabe erforderlich. Veröffentlichte Versionen sind unveränderlich: niemals eine veröffentlichte Version überschreiben oder einen bestehenden Tag verschieben.

Verifizierte Release-Nachweise: Main-CI Run [42803873595](https://github.com/cvd-policy/cvd-policy-rs/actions/runs/42803873595), Release Run [42804207280](https://github.com/cvd-policy/cvd-policy-rs/actions/runs/42804207280), Tag [`v0.1.1`](https://github.com/cvd-policy/cvd-policy-rs/releases/tag/v0.1.1) und veröffentlichter Crate-Checksum oben. Ein separater Rust-1.88-Consumer lud `0.1.1` nachweislich aus crates.io, baute und führte ihn ohne Node/npm aus; Registry-Download, GitHub-Release-Artefakt und vor dem Tag erstelltes Paket stimmten byteweise überein. Keine manuellen API-Tokens oder Reviewerfreigaben wurden für diesen OIDC-Release verwendet.
