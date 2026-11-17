# Saktum Check — quickstart

Test an MCP server in about a minute. Needs Node.js 20 or later. Nothing is uploaded.

```
npx saktum check -- npx -y @your/mcp-server                    # a local server
npx saktum check --env API_KEY=... -- node ./build/index.js     # give it what it needs to start
npx saktum check https://your-server.example/mcp                # a remote server: sign-in checks
npx saktum check --header "Authorization: Bearer <token>" https://your-server.example/mcp   # and its tools
```

The report starts with a grade (A to F) and three plain sentences, then the problems with fixes, then OWASP MCP Top 10
coverage. A signed result is saved to `saktum-report.json` (check it with `npx saktum verify saktum-report.json`).

Will not start or connect? `npx saktum doctor -- <same target>` explains why.

Without npm: download `saktum.mjs` from the release and run `node saktum.mjs check ...`.

**Feedback shapes v0.2:** https://github.com/OWNER/saktum-check/discussions
