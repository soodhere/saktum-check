# Security policy

## Reporting a vulnerability
Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab of this repository).
Do not open a public issue. We acknowledge reports within 3 business days, keep you informed, and credit you in the
release notes unless you prefer otherwise. Please give us 90 days before public disclosure.

## Scope
Saktum Check (the `saktum` command, its contracts and the GitHub Action). Third-party MCP servers tested with Saktum
are out of scope: report those to their maintainers.

## How Saktum protects you (summary)
- **Runs in your environment.** Nothing is sent to Saktum; there is no Saktum service in the path.
- **Passive by default.** Checks never call a server's tools unless you pass `--active`, for servers you own.
- **Secrets stay yours.** Your environment is not passed to servers under test; configured secrets are never printed;
  receipts store argument digests, not values; headers given to the bridge are never logged.
- **Signed evidence.** Results, attestations, mandates, approvals, agreements and receipts are signed with Ed25519
  (did:key); receipts are hash-chained, so any change or removal is detected.
- **Protected keys.** Keys can come from an environment variable (`env:VAR`) or the operating system's keychain
  (`keychain:NAME`: macOS Keychain, Linux Secret Service, Windows DPAPI); key files are written owner-only.
- **Supply chain.** Releases are published with npm provenance and a CycloneDX SBOM; dependencies are audited in CI.

Details: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md), [docs/DATA-FLOW.md](docs/DATA-FLOW.md),
[docs/VENDOR-QUESTIONNAIRE.md](docs/VENDOR-QUESTIONNAIRE.md).
