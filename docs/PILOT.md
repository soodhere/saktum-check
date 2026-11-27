# The MCP Trust Assessment: design-partner pilot runbook

**What it is:** a 4-week pilot that runs entirely in your environment. Nothing is sent to Saktum.
**First pilots are free design partnerships** (feedback, an approved quote, a reference); paid pilots ($15-30k,
credited against the first year) start after incorporation, from Q2 2027.
**Effort:** about 2 hours a week of your team's time; 2-3 hours a week from Saktum (one 30-minute call, async help).

## What you get (all available today)
1. An inventory of every MCP server your people use, with grades, risk tiers and costs.
2. Your policy, enforced as code; an allowlist for your MCP firewall or gateway; daily monitoring for silent changes.
3. One agent workflow governed (coding agents are ideal): mandates, approvals by link, signed receipts.
4. A board-ready assessment with a business case and evidence mapped to the EU AI Act, NIST AI RMF and ISO 42001.

## Week by week
| Week | You run | Saktum helps with | Output |
| --- | --- | --- | --- |
| 1 | `scripts/pilot/scan-config-*.{ps1,sh}` on pilot machines; `saktum fleet` | Kick-off; success criteria | Inventory |
| 2 | `saktum fleet --policy saktum-policy.yaml`; `saktum allowlist`; `examples/saktum-watch.yml` | Writing the policy; exceptions | Policy and monitoring |
| 3 | `saktum agent create --intent ...`; `saktum proxy ... -- saktum bridge https://...` for remote tools; `saktum approvals serve` | Mandates, bindings overrides, approvals | One governed workflow |
| 4 | `saktum agents scan --out agents.json`; `saktum receipts view`; `saktum assess --fleet inventory.json --agents-inventory agents.json` | Read-out to your sponsor | Assessment |

## Before you start
A design-partner agreement and mutual NDA (templates in `templates/`); a shared folder for inventory files; Node.js 20+
on pilot machines; one agent workflow to govern; your security review can use `SECURITY.md` and `docs/`.

## Honest scope
Saktum governs MCP tool calls of agents you run (local tools, and remote tools through the bridge). It does not yet
govern agents inside SaaS platforms (planned with the hosted gateway), offer SSO or a hosted console, or detect prompt
injection inside models (it contains a manipulated agent through its mandate).
