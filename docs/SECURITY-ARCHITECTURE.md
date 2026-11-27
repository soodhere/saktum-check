# Security architecture

**Principle:** deterministic decisions, signed evidence, least privilege, fail-closed, and nothing to trust that cannot
be verified.

1. **Identity.** Ed25519 keys (did:key) for organisations, people, agents and publishers. Organisations prove control of
   their domain (DNS TXT or a well-known file). Credentials form chains (organisation → person → agent), verified
   link by link. Keys come from the OS keychain, environment variables or an external signer; rotations and revocations
   are recorded in the public ledger.
2. **Authority.** Mandates signed by the principal and countersigned by the operator: purpose, autonomy per action class,
   rules on domain fields, preferences, substitution and upsell policies, approval triggers, data sharing, limits.
   Agreements between providers and invokers are signed by both.
3. **Enforcement.** The proxy decides every call before it reaches the tool: revocation (local, chain and remote), tool
   pinning, the mandate, the agreement and credit, approvals. Any error refuses the call.
4. **Human approval.** Approvals cover exactly one action (mandate, tool and arguments), expire, are single use (file and
   receipt chain), arrive by per-request links, and can require a passkey.
5. **Evidence.** Signed, hash-chained receipts with reasons and keyed argument digests; signed checkpoints detect
   deletion; signed, chained wallets; the public ledger with checkpoints and witnesses; canonical JSON compatible with
   RFC 8785; exports to OpenTelemetry and W3C Verifiable Credentials.
6. **Supply chain.** Open source; pinned actions; CodeQL, Dependabot, Scorecard; npm provenance; SBOM; Sigstore-signed
   bundles; `saktum self-verify`.

See [THREAT-MODEL.md](THREAT-MODEL.md), [HARDENING.md](HARDENING.md) and [DATA-FLOW.md](DATA-FLOW.md).
