# cvd-policy

[![CI](https://github.com/cvd-policy/cvd-policy-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/cvd-policy/cvd-policy-rs/actions/workflows/ci.yml)

A Rust library for parsing, validating, and locally evaluating the experimental CVD Policy Format Version 1 (Draft-01). It also assesses `security.txt` authority evidence and CSAF 2.1 CSD04 Vulnerability Report (Profile 9) declarations.

## Features

- Duplicate-safe UTF-8 JSON parsing with exact numeric values.
- Immutable, statically validated policies; current validity is checked explicitly with `validate_at(now)`.
- Permission evaluation with seven policy-result statuses, separate from target-input errors.
- `security.txt` evidence assessment and local CSAF assessment (four declaration states and host-usability assessment).
- No runtime Node.js/process dependency, network or DNS access, or system-clock reads. Callers provide retrieval facts and evaluation time.

This is a local policy core, not a complete intake or reporting client. It does not fetch policies, validate CSAF report documents, submit reports, or send reports automatically. A declaration or capability assessment does not itself establish live host behavior; use the full evidence and current-time gates for host assessment.

## Install

Install the published crate from crates.io:

```toml
[dependencies]
cvd-policy = "0.1"
```

The Cargo package is `cvd-policy`; its Rust library module is `cvd_policy`. The minimum supported Rust version is 1.88. Version 0.1.0 is published on [crates.io](https://crates.io/crates/cvd-policy). A reviewed source commit is also available from Git:

```toml
[dependencies]
cvd-policy = { git = "https://github.com/cvd-policy/cvd-policy-rs.git", rev = "8800a50fca690d75b72e35d897588dbf83b875dc" }
```

The first publication and Trusted Publisher setup are complete. The tagged automated release path has not yet been run; see [Release and publishing](docs/RELEASING.md).

## Example

Parse a policy and check its expiry against an explicit time:

```rust
use cvd_policy::{Policy, Timestamp};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw = br#"{
      "cvd_policy": 1,
      "last_updated": "2026-08-29T08:00:00Z",
      "expires": "2027-02-28T08:00:00Z",
      "organization": { "name": "Example Organization" },
      "contact": { "channels": ["mailto:security@example.com"] },
      "research": { "posture": "report_only" },
      "reporting_scope": { "web": [{
        "id": "main-web", "state": "in", "host": "example.com",
        "schemes": ["https"], "path_prefix": "/", "include_subdomains": false
      }] },
      "reporting": {
        "requested_fields": ["affected_asset", "description"],
        "proof_of_exploitation": "not_requested"
      }
    }"#;

    let policy = Policy::parse(raw)?;
    let now = Timestamp::parse("2026-11-08T12:00:00Z")?;
    policy.validate_at(&now)?;
    println!("policy parsed and valid at {now}");
    Ok(())
}
```

Static parsing and validation do not replace `validate_at` for each current use. The timestamp above is only an example: applications must provide the current evaluation time on every use, not a historical retrieval timestamp. This example makes no claim about a retrieved or live host. For the complete retrieval-evidence and host-assessment flow, see [`examples/integration.rs`](examples/integration.rs).

## Checks and scope

The GitHub Actions CI workflow checks Rust 1.88 and stable. The native conformance suite covers 198 normative baseline vectors; the 220-case Rust/TypeScript comparison is documented in [Conformance and evidence](docs/CONFORMANCE.md). Known comparison differences are documented; this is not a claim of universal interoperability.

Run the local checks with:

```sh
cargo test --locked
cargo run --locked --example integration
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --no-deps
```

For API usage and integration considerations, see [`docs/INTEGRATION.md`](docs/INTEGRATION.md). The normative Draft-01 source is [`vendor/spec/draft/draft-behring-cvd-policy.md`](vendor/spec/draft/draft-behring-cvd-policy.md); source and license provenance is recorded in [`vendor/SOURCES.json`](vendor/SOURCES.json) and [`NOTICE.md`](NOTICE.md).

## Integration note

The crate enables `serde_json/arbitrary_precision`; Cargo feature unification can affect consumers' `serde_json::Value`/`Number` behavior. Check consumer JSON roundtrips before integration. Default parser limits are 1 MiB input, nesting depth 64, 100,000 JSON nodes/member names, and 4,096 bytes per number lexeme; see the API and conformance documentation for details.
