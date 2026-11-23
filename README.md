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

## Functional testing, performance and your own test cases

- **`--active`** (only against servers you own): Saktum calls your **read-only** tools with arguments generated from
  their schemas, validates results against any declared `outputSchema`, checks invalid arguments are rejected gracefully,
  confirms the server survives, and measures latency percentiles and behaviour at 1, 5 and 20 concurrent callers.
  Destructive tools are never called automatically; name others with `--call <tool>`.
- **Your test cases** (`saktum.tests.yaml`, guide in [docs/TESTS.md](docs/TESTS.md)): what your tools should actually
  return, run with `npx saktum test` locally and in CI.
- **Capability profile:** what your tools can do (run code, reach the network, touch files, change data, send messages,
  move money), declared or conservatively inferred, with a warning when private data, untrusted content and an outbound
  channel combine.
- **Trust card and scope:** every report says, dimension by dimension, what was tested, what was not, and why.
  `npx saktum checks` lists every check with the standard behind it ([docs/CHECKS.md](docs/CHECKS.md)).
- **Control:** `--ignore check.id="reason"` (shown in the report, not scored) and `--badge badge.svg` for your README.

## The provider toolkit

| Command | What it does |
| --- | --- |
| `saktum fix -- <server>` | Suggests danger annotations for every tool, as code to paste (`--format ts` or `py`), and flags annotations that contradict a tool's name |
| `saktum snapshot -- <server>` | Writes `saktum.lock.json`, a lock file of your tools |
| `saktum diff saktum.lock.json -- <server>` | Breaking changes (removed tools, new required fields, changed types), changes to review (descriptions, annotations: silent tool changes), additions, and the version bump they need; fails CI on breaking or risky changes |
| `saktum docs -- <server>` | A Markdown tools table and ready-to-paste configuration for Claude Desktop, Cursor and VS Code |
| `saktum packet saktum-report.json` | A printable **security packet** for customers' security reviews, built from a verified signed result, with a section for your own statements (clearly marked as not verified) |

## In CI (GitHub Action)

```yaml
- uses: actions/checkout@v4
- uses: soodhere/saktum-check@v0.3.0
  with:
    target: "-- node build/index.js"     # or an https URL
    args: "--active --tests saktum.tests.yaml"   # optional; --active only for your own server
    fail-on: high
```

The report appears in the job summary; the signed result, HTML report and badge are saved as an artifact.

## Test vectors for the MCP community

[`test-vectors/`](test-vectors/) holds known-good and known-bad servers with the expected verdict for every check, so any
MCP testing tool can validate itself against the same cases. Contributions welcome.

## What it checks

| Area | Checks |
| --- | --- |
| Conformance | Handshake, tool list, valid input schemas (draft-07, 2019-09, 2020-12), tool names, unknown-tool handling |
| Sign-in (remote servers) | HTTPS; 401 with a Bearer challenge pointing to resource metadata (RFC 9728); protected resource metadata; authorization server metadata with PKCE S256 (RFC 8414, RFC 7636); invalid tokens rejected (RFC 6750) |
| Security | Hidden instructions to the agent, invisible and bidirectional characters, terminal escape sequences, secrets in tools or errors (always redacted), stack traces and source paths in errors, Origin validation for local HTTP servers (DNS rebinding) |
| Agent experience | Danger annotations, description quality, context cost in tokens and dollars |
| Functional (`--active` or test cases) | Tools respond to valid arguments; results well-formed and matching their `outputSchema`; invalid arguments rejected gracefully; the server survives |
| Performance (never scored) | Start-up, latency percentiles, behaviour at 1, 5 and 20 concurrent callers, memory of the whole process tree |

Validated on real public MCP servers before every release ([docs/VALIDATION.md](docs/VALIDATION.md)), including active
runs, with no false failures. Each check cites the specification clause or OWASP item it verifies.

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
