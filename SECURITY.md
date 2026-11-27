# Security policy

## Reporting a vulnerability
Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab of this repository).
Do not open a public issue. We acknowledge reports within 3 business days, keep you informed, and credit you in the
release notes unless you prefer otherwise. Please give us 90 days before public disclosure.

## Safe harbour
We will not pursue legal action against good-faith research that follows this policy: test only against your own
installations of Saktum, avoid privacy violations and service disruption, and give us time to fix issues before
disclosure. Researchers who report valid issues are credited in the hall of fame below (with permission).

## Hall of fame
Thank you to everyone who has helped make Saktum safer. (Your name could be first.)

## Verify Saktum itself
- `npm audit signatures` checks npm provenance for the installed package.
- Each release publishes `saktum.mjs`, its SHA-256 checksum, a CycloneDX SBOM and a Sigstore bundle
  (`saktum.mjs.sigstore.json`). `npx saktum self-verify` compares your copy and prints the `cosign verify-blob` command.
- Every GitHub Action in our workflows is pinned to an exact commit; CodeQL, Dependabot and the OpenSSF Scorecard run
  on the repository.

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
