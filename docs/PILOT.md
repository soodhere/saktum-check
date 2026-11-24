# The MCP Trust Pilot: playbook and templates

A 4 to 6 week paid pilot with a security, AI-governance or platform team. Everything runs in the customer's
environment; nothing is sent to Saktum.

## Success criteria (agree these in week 0, in writing)
1. A complete inventory of MCP servers used by the pilot teams, with grades and capabilities.
2. A first organisation policy, agreed with security and enforced in CI on at least one MCP repository.
3. An allowlist deployed to (or ready for) the customer's MCP firewall or gateway.
4. Agent mandates and receipts on one or two agent workflows, with the path of every call on record.
5. An executive assessment the sponsor can present internally.

## Week by week
| Week | Work | Saktum commands | Customer provides |
| --- | --- | --- | --- |
| 0 | Kick-off: scope, teams, success criteria, data handling | — | Sponsor, a security contact, pilot teams |
| 1 | Inventory: run on pilot machines, merge | `scan-config --yes --out setup.json`; `fleet` | A way to run one command on machines (device management or the engineers) |
| 2 | Policy: draft with security; first exceptions with owners and expiry | `--policy saktum-policy.yaml`; `fleet --policy` | Security's rules and risk appetite |
| 3 | Enforce: CI gate on MCP repositories; allowlist | GitHub Action with `policy`, `sarif`; `allowlist` | Repository access for the team |
| 4 | Agents: mandates and receipts on one or two workflows | `agent create`; `proxy --enforce`; `receipts summary` | An agent workflow and its owner |
| 5 | Report: executive assessment and recommendations | `assess --fleet inventory.json --receipts …` | Sponsor review |
| 6 | Decision: production rollout and gateway design partnership | — | Go or no-go |

## Pilot proposal (one page, fill the brackets)
> **MCP Trust Pilot for [Organisation]**
> **Goal:** know which MCP servers your people and agents use, enforce your own rules, and keep evidence of every agent action.
> **Scope:** [N] teams, [N] machines, [N] MCP repositories, [1–2] agent workflows. **Duration:** [4–6] weeks.
> **Deliverables:** inventory; organisation policy enforced in CI; allowlist for your MCP firewall or gateway; agent mandates and receipts; executive assessment with recommendations.
> **Data:** everything runs in your environment; nothing is sent to Saktum.
> **Fee:** [fixed fee], credited in full against the first year of the Saktum gateway if you continue.
> **Next:** design partnership for the Saktum gateway (decisions and signed receipts on every agent call).

## Letter of intent (short, non-binding)
> [Organisation] intends to run an MCP Trust Pilot with Saktum starting [date], for [scope], with the success criteria
> above, at [fee] (credited against a first gateway year). This letter is non-binding and does not create an obligation
> to purchase. Signed: [name, role, date].

## Questions to ask in discovery (about past behaviour, not about Saktum)
1. The last time an AI agent or tool did something unexpected: what happened next?
2. How do you decide today which MCP servers or AI tools are allowed, and who decides?
3. What evidence did audit or compliance ask for about AI, and how did you produce it?
4. What have you tried or bought for this, and what was missing?
5. Whose budget would pay for solving it?
6. (Providers) Would you pay for independent people to try to break your server? (bounty interest)
