# 0004 Signing with Node's built-in Ed25519
**Decision:** RFC 8785 canonical JSON, detached JWS (RFC 7515) with EdDSA, keys identified as did:key; implemented with `node:crypto` rather than a third-party JOSE library (a change from the plan's `jose`, to reduce supply-chain surface).
**Why:** public-key signatures let anyone verify a result without a shared secret; this is the same evidence model as gateway receipts.
**Consequences:** local results are self-signed and must say so; hosted results (later) use a Saktum key held in an HSM.
