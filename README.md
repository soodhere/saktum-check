# Saktum Check

**Test your MCP server in one command:** conformance, sign-in, security mapped to the **OWASP MCP Top 10**, agent
experience, what your tools cost an agent in context, and performance. Two grades (**trust** and **agent readiness**),
plain findings, a fix for each, and a signed result anyone can verify.

```
npx saktum check -- npx -y @your/mcp-server          # a local server
npx saktum check https://your-server.example/mcp     # a remote server (sign-in checks run without a token)
```

Runs on your machine. Nothing is uploaded. Your own environment variables are never passed to the server.

## What you get

```
  GRADE F  (trust score 49, capped: a critical check failed)
  Grade F: 2 problems found (1 critical, 1 medium); 11 checks passed.
  Fix first (critical): found what looks like an AWS access key in tool upload_report.
  Agents spend about 142 tokens reading these tools on every turn, about $0.43 per 1,000 turns.

  agent-experience   100
  conformance        100
  security            61

✗ FAIL CRITICAL sec.secrets.exposed  No secrets in tool definitions or responses
    Found what looks like an AWS access key in tool upload_report. Anyone who can list tools or trigger an error can read it.
    Evidence: ess_key_id":{"type":"string","default":"AKIA…[redacted 16 chars]"}},"required":["nam
    Fix: Remove keys, tokens and passwords from descriptions, schemas, defaults, examples and error messages; load them from a secret store at runtime.
✗ FAIL MEDIUM sec.errors.leakage  Errors do not expose internals
    The error for an unknown tool exposes a JavaScript stack trace, which helps attackers map your internals.
    Evidence:     at handleCall (/home/deploy/acme-mcp/src/handlers.js:42:11)
```

**Two grades.** *Trust* covers conformance, sign-in and security; *agent readiness* covers whether agents can choose and
use your tools safely and cheaply (danger annotations, descriptions, context cost). Readiness never changes the trust
grade. Every report ends with **OWASP MCP Top 10 coverage**: which categories this run tested and which come later.

## What it checks (v0.1: 24 checks)

| Area | Checks |
| --- | --- |
| Conformance | Handshake, tool list, valid input schemas (draft-07, 2019-09, 2020-12), tool names, unknown-tool handling |
| Sign-in (remote servers) | HTTPS; 401 with a Bearer challenge pointing to resource metadata (RFC 9728); protected resource metadata; authorization server metadata with PKCE S256 (RFC 8414, RFC 7636); invalid tokens rejected (RFC 6750) |
| Security | Hidden instructions to the agent, invisible and bidirectional characters, terminal escape sequences, secrets in tools or errors (always redacted), stack traces and source paths in errors |
| Agent experience | Danger annotations, description quality, context cost in tokens and dollars |
| Performance (never scored) | Start-up, latency, memory of the whole process tree, and a rate-limit burst test with `--active` |

Validated on 31 public MCP servers before release. Each check cites the specification clause or OWASP item it verifies.

## Options

| Option | Use |
| --- | --- |
| `--env NAME=VALUE` | Give a local server what it needs to start (repeatable) |
| `--header "Authorization: Bearer <token>"` | Test a remote server's tools, not just its sign-in |
| `--html report.html` | Also write an HTML report |
| `--fail-on high` | Exit code for CI: fail on findings at or above this severity |
| `--price-per-mtok 3` | Your model's input price, for the cost estimate |
| `--active` | Extra checks that send more traffic. **Only against servers you own.** |

`npx saktum doctor -- <same target>` explains why a server will not start or connect.
`npx saktum verify saktum-report.json` checks a signed result.

## Feedback wanted

This is an early release, and **feedback shapes v0.2**. In two minutes:

- **Something looked wrong?** [Report a false positive](../../issues/new?template=false-positive.yml)
- **Something missing?** [Suggest a check](../../issues/new?template=missing-check.yml)
- **What should v0.2 do?** [Vote and comment](../../discussions)

Planned next: active checks for servers you own, sign-in registration and redirect checks, a lock file that catches
silent tool changes, a sandbox for untrusted servers, then CI (GitHub Action, SARIF) in January.

## Honest limits

Results are self-tested (assurance level L1): the signature proves the report was not changed after the run, not that it
was run independently. Findings describe the server at the time of the run and are not a guarantee of security. Static
checks can miss cleverly disguised attacks; a pass is evidence, not proof.

## Licence

Apache-2.0. Security issues: see [SECURITY.md](SECURITY.md).
