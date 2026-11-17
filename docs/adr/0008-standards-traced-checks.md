# 0008 Standards-traced checks and the Agent Security Profile
**Decision:** every check carries `normative` references (source, version, clause, MUST/SHOULD/MAY/best-practice). Sign-in checks trace to the MCP authorization specification and RFC 9728, 8414, 7636, 7591 and 9700, plus a token-passthrough and audience check (RFC 8707). The Saktum Agent Security Profile (Baseline, Advanced), modelled on FAPI 2.0, is a set of these checks with a pass rule.
**Why:** conformance that cites the standard is defensible, reviewable and portable; this is what OpenID Foundation and GSMA conformance programmes do.
**Consequences:** the traceability matrix and the specification are generated from packs, never hand-written; specification changes are reviewed monthly and flag affected checks.
