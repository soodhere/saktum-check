# Threat model v2 (Saktum Check v0.12)

**System:** the `saktum` command on a customer's machines or CI; the proxy between agents and MCP servers (local, or
remote through `saktum bridge`); local files for keys, mandates, approvals, revocations, receipts and wallets; the public
ledger and census. **Untrusted inputs:** agents (they may be manipulated), MCP servers (tool definitions and outputs),
the network, and any file an agent's OS user can write.

| # | Threat | Mitigation in v0.12 | Residual risk |
| --- | --- | --- | --- |
| S1 | A compromised agent deletes its own revocation | Revocations signed by the owner or operator; once a revocation is seen it is recorded in the append-only receipt chain and enforced from then on; optional remote revocation list (`--revocations-url`) the agent cannot edit | Run the proxy under a separate OS user so the agent cannot touch its files |
| S2 | Wallet balances edited | Wallet entries chained and signed; `chargeCall` refuses to spend from a wallet that fails verification; `wallet verify` | The provider keeps its own authoritative record |
| S3 | Newest receipts deleted (truncation) | Signed checkpoints (`--checkpoint-every`, `receipts checkpoint`); `ledger check --receipts` detects deletion and rewriting | Keep checkpoints off the agent's machine |
| S4 | Guessable argument values recovered from digests | Keyed digests (`--digest-key env:VAR`) | Protect the digest key like any secret |
| S5 | Bridge credentials visible in the process list | `--header-env Name=VAR` | Environment variables are visible to the same OS user |
| S6 | Organisation claims a domain it does not control | `org verify-domain`: DNS TXT `_saktum.<domain>` or `/.well-known/saktum.json`, re-checkable by anyone | DNS or web compromise of the domain itself |
| S7 | A single ledger operator rewrites history | Signed ledger checkpoints, independent witnesses (`ledger witness`), mirrors; anyone can verify the full chain | Needs witnesses to participate |
| S8 | A leaked approval link approves later requests | Per-request, single-use links (`--approval-secret`); approvals expire and are used once | A leaked link can approve only its own pending request until it expires |
| S9 | Implementations disagree on what was signed | Canonical JSON proven compatible with RFC 8785 by its test vectors | — |
| S10 | Errors open the gate | Fail-closed: any error during a decision refuses the call (`error-fail-closed`) | — |
| S11 | A server silently changes its tools (rug pull) | Tool pinning (`--pin sha256:...`): calls refused if the fingerprint differs (`tools-changed`); `watch` alerts | Pins must be updated after an intended change |
| S12 | An approval replayed by editing the used-list | Single use also enforced through the signed receipt chain | — |
| S13 | The agent reads its key and forges receipts | Keys from the OS keychain, environment or an external signer (`exec:`, for cloud key services and hardware modules); proxy under its own OS user | An attacker with the proxy's OS account |
| S14 | Supply-chain compromise of CI or the ledger bot | Actions pinned to commits; bots pinned to an exact version; CodeQL, Dependabot, Scorecard; npm provenance; Sigstore-signed bundles | Upstream compromise of a pinned commit before review |
| S15 | Website injection or framing | Content-security and permissions policies, no framing, nosniff | Static site with inline scripts |

**Out of scope:** detecting prompt injection inside models; agents inside SaaS platforms (gateway phase); an external
penetration test and SOC 2 (planned after funding, before enterprise general availability).
