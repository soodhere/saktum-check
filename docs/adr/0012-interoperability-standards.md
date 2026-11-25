# 0012 Interoperability: Saktum's evidence in the standards enterprises already run

**Status:** accepted (26 Nov 2026).

**Decision.** Saktum does not ask enterprises to adopt a new stack. Its evidence is exported into standards their
existing tools accept: receipts as **OpenTelemetry** traces (GenAI semantic conventions for tool execution, plus
`saktum.*` attributes) for observability and security tools; attestations as **W3C Verifiable Credentials** (Data Model
2.0, secured as a JWS with `typ: vc+jwt`, EdDSA, issued by the signer's `did:key`) for identity and procurement systems;
findings as **SARIF** for code scanning; releases with a **CycloneDX** SBOM; sign-in checks against **OAuth** (RFC 9728,
RFC 8414); and, in the gateway, decisions through the **OpenID AuthZEN** API. Allowlists stay in a neutral format, with
adapters for specific firewalls and gateways once their formats are documented.

**Why.** Enterprises run several platforms (Microsoft, Google, Salesforce, AWS, ServiceNow) and their agents cross them.
Each vendor governs only its own estate and will not certify competitors. Neutral, portable evidence in accepted
standards is what lets any platform and any counterparty verify the same facts, and it lowers sales friction.

**Consequences.** Exports must round-trip in tests (credentials verify; spans are valid OTLP/JSON); semantic-convention
names are revisited when the conventions stabilise; no export may carry raw arguments or secrets (digests only).
