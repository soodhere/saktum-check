# Vendor security questionnaire (answers)

Common questions from security reviews, answered for Saktum Check (open source, self-hosted).

| Question | Answer |
| --- | --- |
| Is Saktum a hosted service? | No. Saktum Check runs entirely in your environment (laptops, servers, CI). There is no Saktum-operated service in the data path. |
| What customer data do you process or store? | None. Saktum does not receive customer data. Evidence files stay where you write them. |
| Where is data stored? Data residency? | On your systems, in folders you choose. Residency is yours to decide. |
| Encryption | Evidence is signed (Ed25519) and receipts are hash-chained for integrity; confidentiality at rest follows your storage. Keys can be held in the OS keychain or provided via environment variables. |
| Authentication and access control | Local files under your OS permissions; the approvals page listens on localhost by default and requires a one-time token. SSO and role-based access arrive with the hosted gateway. |
| Logging and audit | Every governed agent call produces a signed receipt with its decision and reason; exportable as OpenTelemetry. |
| Secure development | Open source; automated tests on Windows, macOS and Linux; dependency audit in CI; releases with npm provenance and an SBOM. |
| Vulnerability management | Private reporting via GitHub security advisories; acknowledgement within 3 business days; 90-day coordinated disclosure (SECURITY.md). |
| Penetration testing / certifications | No external penetration test or certification yet (planned after funding). The code is open for your own review. |
| Subprocessors | None. |
| Business continuity | Open source under Apache-2.0: everything you set up keeps working without Saktum. |
| AI usage | No language model decides access. Decisions are deterministic and reproducible. |
