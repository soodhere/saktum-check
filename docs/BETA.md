# Private beta kit (stealth, Nov–Dec 2026)

## Invite message (personal, not public)
Hi [name], I'm building a small private tool that tests MCP servers: conformance, sign-in, security (mapped to the OWASP MCP Top 10) and how much context they cost an agent. It runs locally in about a minute and gives a grade, plain-language findings and fixes. It's early and private, so I'm asking a few people I respect. Would you try it on one of your servers and give me 20 minutes of feedback? Happy to walk you through it.

## Beta note (one page; have a lawyer glance at it)
- Early private software, provided as is, with no warranty.
- Runs locally; nothing is sent to us unless you choose to share your signed report.
- Please keep the tool and its findings confidential until our public launch.
- Your results are yours; we will never publish anything about your server without your written consent.
- Feedback is welcome and may shape the product; there is no obligation.

## Onboarding (20 minutes)
1. Install: download `saktum.mjs` from the private release (Node 20+).
2. Run: `node saktum.mjs check -- <command that starts your server>` or `node saktum.mjs check https://your-server/mcp`.
3. Read the grade and summary together; pick one finding to fix.
4. Re-run after fixing; send the signed `saktum-report.json` if you're happy to.

## Feedback questions
1. Which finding surprised you, and which would you fix first?
2. Was anything wrong (false positive) or missing?
3. Would you run this in CI? What would stop you?
4. Who else in your organisation would care about these results?
5. (Design partners) What would you need before putting a server behind a gateway?

## Metrics (every number verifiable)
| Metric | How we know |
| --- | --- |
| Developers who ran it | Onboarding call or shared signed report |
| Servers checked | Distinct tool fingerprints in shared reports |
| Findings fixed | A later shared report for the same server with the finding passing |
| Quotes | Written permission to quote |
