# Saktum Check for enterprises

Agents across your organisation are connecting to MCP servers. Saktum Check tells you **which servers are in use, whether
they meet your rules, and gives you evidence** for security reviews and AI governance, using tools that run entirely in
your environment.

## What your security team will ask about Saktum itself

| Question | Answer |
| --- | --- |
| Does data leave our environment? | No. Saktum runs on your machines and in your CI. Nothing is sent to Saktum; there is no telemetry. |
| What does it touch? | Passive checks connect to a server as any MCP client would and never call its tools. `--active` calls tools and is only for servers you own. |
| Secrets? | Your environment is never passed to servers under test. `scan-config` never prints configured secrets; command lines in reports are redacted (key and token flags, long random strings, URL credentials and queries). |
| Supply chain? | Published to npm with provenance from GitHub Actions; each release ships a single-file bundle with its SHA-256 and a CycloneDX SBOM; Apache-2.0. |
| Air-gapped use? | Download `saktum.mjs` from a GitHub release, verify its SHA-256, and run it with Node.js 20 or later; no network access needed for local servers. |
| Can results be trusted? | Every result is signed and verifiable (`saktum verify`); self-tested results are labelled L1. |

## 1. Inventory: which MCP servers is the organisation using?

Run on engineering machines (for example through your device-management tool), then merge:

```
npx -y saktum@0.4.0 scan-config --yes --machine "$HOSTNAME" --out setup.json   # per machine
npx -y saktum@0.4.0 fleet setups/*.json --policy saktum-policy.yaml --html inventory.html --out inventory.json
```

`scan-config --yes` starts each configured server with the settings already in that machine's configuration and checks it
passively; announce the rollout to staff as you would any endpoint inventory.

## 2. Policy as code: your rules, enforced everywhere

`saktum-policy.yaml` (see [examples/saktum-policy.yaml](../examples/saktum-policy.yaml); format
[contracts/policy.schema.json](../contracts/policy.schema.json)): minimum trust and agent-readiness grades, forbidden
capabilities (for example moving money or running code), no failed checks above a severity, a maximum context cost, an
optional allowlist, and **exceptions with a reason, an approver and an expiry date**. Expired exceptions stop applying.

```
npx saktum check --policy saktum-policy.yaml -- <server>        # exit 1 on a violation
npx saktum scan-config --policy saktum-policy.yaml              # per developer
```

In CI, the GitHub Action takes `policy: saktum-policy.yaml` (plus `sarif: "true"` for code scanning).

## 3. Evidence for governance, procurement and firewalls

- `saktum allowlist` turns approved results into an allowlist pinned to each server's tool fingerprint, for MCP
  firewalls and gateways: any tool change drops the server until it is re-checked.
- `saktum packet` produces a printable security packet for vendor and procurement reviews.
- `saktum attest` produces compact signed attestations; providers can publish them to the public **Saktum trust
  ledger** (append-only, hash-chained, verifiable by anyone), and `saktum allowlist --from-ledger --trusted-signers`
  builds your allowlist from it, accepting only signers you trust.
- The census report and the maturity model give an external benchmark.

## Fits your existing tools

Continuous monitoring of approved servers (`saktum watch`, as a daily workflow); agent receipts as **OpenTelemetry**
traces for your observability and security tools; attestations as **W3C Verifiable Credentials** for identity and
procurement systems; findings as **SARIF**; an SBOM with every release. See decision record 0012.

## 4. Agent identity and receipts (preview)

Each agent gets its own identity (`saktum agent create`) and a mandate signed by its owner: allowed servers and tools,
whether destructive actions are allowed, and an expiry date. `saktum proxy` sits between the agent and a local MCP server,
observes or enforces the mandate, and writes a signed, hash-chained receipt for every tool call, so the path an agent
took (including retries and blocked attempts) is on record, not reconstructed in a compliance review months later.

## 5. The MCP Trust Pilot

A 4 to 6 week paid pilot with your security, AI governance or platform team (playbook, proposal and letter of intent:
[docs/PILOT.md](PILOT.md); the executive report comes from `saktum assess`):

1. **Inventory:** every MCP server in use across a chosen group of teams, with grades, capabilities and context cost.
2. **Policy:** a first organisation policy agreed with your security team, enforced in CI on your MCP repositories.
3. **Evidence:** an allowlist for your MCP firewall or gateway, security packets for approved servers, and a findings and
   remediation report for AI governance.
4. **Agent receipts:** mandates and the receipt proxy on one or two agent workflows, so the team sees every call's path.
5. **Next:** a design partnership for the Saktum gateway (decisions and signed receipts on every agent call), starting
   in observe mode.

Contact: through the form at https://saktum.vercel.app (choose "Gateway design partner" or "Verified certification").
Security issues in Saktum itself: see [SECURITY.md](../SECURITY.md).
