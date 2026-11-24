# Saktum Check — quickstart

Test an MCP server in about a minute. Needs Node.js 20 or later. Nothing is uploaded.

```
npx saktum check -- npx -y @your/mcp-server                    # a local server (passive: no tool is called)
npx saktum check --active -- node ./build/index.js              # your own server: also call read-only tools and measure load
npx saktum test -- node ./build/index.js                        # run your saktum.tests.yaml (see docs/TESTS.md)
npx saktum check https://your-server.example/mcp                # a remote server: sign-in checks
npx saktum check --header "Authorization: Bearer <token>" https://your-server.example/mcp   # and its tools
npx saktum checks                                               # every check, with the standard behind it
npx saktum fix -- node ./build/index.js                         # annotation code to paste (--format py for Python)
npx saktum snapshot -- node ./build/index.js                    # lock your tools; then in CI:
npx saktum diff saktum.lock.json -- node ./build/index.js       # breaking and silent changes, and the version bump
npx saktum docs -- npx -y your-package                          # tools table and client configuration
npx saktum packet saktum-report.json                            # a security packet for customers' reviews
npx saktum scan-config                                          # your agent set-up: total cost, duplicates, unvetted servers
npx saktum check --sarif saktum.sarif --baseline b.json -- ...  # CI: GitHub code scanning; fail only on new findings
npx saktum attest saktum-report.json --publish                  # signed attestation, badge, and a link to the public trust ledger
npx saktum ledger verify                                        # verify the public trust ledger
npx saktum agent create --name "My agent" --allow-tool get_order  # agent identity and a mandate you sign (preview)
npx saktum proxy --mandate agent-mandate.json --enforce -- npx -y some-server   # signed receipts for every call
npx saktum receipts summary                                     # the path: tools, order, retries, denials
npx saktum passport -- npx -y some-server                       # a visual MCP Server Passport
npx saktum passport --agent agent-mandate.json --receipts r.jsonl   # an Agent Passport with the call timeline
npx saktum assess --fleet inventory.json --org "Acme"           # executive MCP Trust Assessment (pilots)
npx saktum mcp                                                  # run Saktum as an MCP server for your coding agent
npx saktum init my-server --lang ts                             # new server, trustworthy by default (or --lang py)
npx saktum lint                                                 # static checks on tool definitions in your source
npx saktum call get_order --args '{"id":"1"}' --save-test order-1 -- node build/index.js   # save a call as a test
npx saktum check --watch -- node build/index.js                 # re-run on every change
```

The report starts with **trust**, **agent readiness** and **functional** status, then a **trust card** (security,
conformance, sign-in, functional, performance, agent readiness, capabilities), the problems with fixes, the tools called,
your test cases, the **scope of the run**, and OWASP MCP Top 10 coverage. A signed result is saved to
`saktum-report.json` (check it with `npx saktum verify saktum-report.json`). Add `--badge badge.svg` for your README and
`--ignore check.id="reason"` for a check you deliberately do not follow (shown in the report, not scored).

Will not start or connect? `npx saktum doctor -- <same target>` explains why.

**Feedback shapes the next release:** https://github.com/soodhere/saktum-check/discussions
