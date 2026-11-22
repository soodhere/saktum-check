# Saktum Check — quickstart

Test an MCP server in about a minute. Needs Node.js 20 or later. Nothing is uploaded.

```
npx saktum check -- npx -y @your/mcp-server                    # a local server (passive: no tool is called)
npx saktum check --active -- node ./build/index.js              # your own server: also call read-only tools and measure load
npx saktum test -- node ./build/index.js                        # run your saktum.tests.yaml (see docs/TESTS.md)
npx saktum check https://your-server.example/mcp                # a remote server: sign-in checks
npx saktum check --header "Authorization: Bearer <token>" https://your-server.example/mcp   # and its tools
npx saktum checks                                               # every check, with the standard behind it
```

The report starts with **trust**, **agent readiness** and **functional** status, then a **trust card** (security,
conformance, sign-in, functional, performance, agent readiness, capabilities), the problems with fixes, the tools called,
your test cases, the **scope of the run**, and OWASP MCP Top 10 coverage. A signed result is saved to
`saktum-report.json` (check it with `npx saktum verify saktum-report.json`). Add `--badge badge.svg` for your README and
`--ignore check.id="reason"` for a check you deliberately do not follow (shown in the report, not scored).

Will not start or connect? `npx saktum doctor -- <same target>` explains why.

**Feedback shapes the next release:** https://github.com/soodhere/saktum-check/discussions
