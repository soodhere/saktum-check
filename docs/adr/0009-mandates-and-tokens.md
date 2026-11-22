# 0009 Mandates as RFC 9396, audience-bound and sender-constrained tokens
**Decision (gateway, 2027):** mandates are expressed as RFC 9396 `authorization_details` (amounts, purposes, limits); per-task tokens are audience-bound (RFC 8707), short-lived, and sender-constrained with DPoP (RFC 9449) for high-risk actions; delegation uses token exchange (RFC 8693). Policies are verified with Cedar's analysis before activation.
**Why:** banks and payment systems already understand RAR (used by FAPI); audience binding and sender constraint defeat token theft and passthrough.
**Consequences:** the call envelope's mandate fields map one-to-one to `authorization_details`.
