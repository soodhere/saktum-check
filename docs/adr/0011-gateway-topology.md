# 0011 Gateway topology: central control, distributed enforcement, federation between companies

**Status:** accepted (23 Nov 2026). Applies to the Saktum gateway (build from mid-May 2027).

**Decision.** A centralised control plane holds policies, identities, mandates, ratings, allowlists and passports, and
pushes signed policy bundles. A distributed data plane of gateways, close to agents and tools, decides every call
locally (Cedar, sub-millisecond) with no round trip on the hot path. Receipts stay in-region; only hashes reach the
shared transparency log. The centre carries trust and configuration, never traffic.

- **Orchestration and choreography.** Orchestrators orchestrate inside a company; the gateway is the checkpoint on every
  call and works with either style. Between companies: choreography. The caller's egress gateway and the provider's
  ingress gateway both sign the receipt; federation uses open standards (DIDs, AuthZEN, Shared Signals), not a hub.
- **Discovery.** Decentralised: providers advertise gateway endpoint and trust passport at well-known addresses;
  registries and Saktum Index are the trust overlay, not routers.
- **Deployment modes.** Saktum-hosted regional (Canada and US, India, EU); customer-run container; later sidecar or SDK.
- **Profiles.** One gateway, many configurations: Observe, Standard, Regulated BFSI, Payments, Health, Sandbox.
  Behaviour varies per call by capability class and risk tier; layered policies (platform, company, team, person).
- **Sovereignty, latency, resilience.** Region-pinned gateways and stores, customer-held keys; local decisions and cached
  bundles; gateways keep working on their last signed bundle, with low-risk calls continuing and high-risk calls failing
  closed if the control plane is unreachable.

**Why.** No party is trusted by every company, so trust between companies must be choreographed and verifiable; a
central traffic hub would add latency, a single point of failure and data-residency problems.

**Phasing.** 2027 MVP: single-company gateways (hosted in one or two regions, or customer-run), observe mode first.
Later 2027: domain profiles, more regions, AuthZEN API. 2028: federation between companies, sidecar or SDK, passport discovery.
