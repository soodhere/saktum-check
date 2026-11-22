# 0010 Interoperability: AuthZEN, Shared Signals, SD-JWT VC, SCITT
**Decision (2027-2028):** Saktum's policy engine exposes an OpenID AuthZEN-compatible decision API so cloud gateways and orchestrators can call it; revocation and emergency stops propagate as OpenID Shared Signals (SSF, CAEP, RISC) events; agent credentials are SD-JWT VCs issued via OpenID4VCI with W3C VC 2.0 compatibility; the transparency log for receipts, results and certifications follows the IETF SCITT architecture with RFC 3161 timestamps.
**Why:** standards let platforms use Saktum instead of replacing it, and let any party verify evidence.
**Consequences:** avoid proprietary formats where a standard exists; verify draft status (SCITT, transaction tokens, OAuth 2.1) before implementation.
