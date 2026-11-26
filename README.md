# Saktum Check

**Test your MCP server in one command:** conformance, sign-in, security mapped to the **OWASP MCP Top 10**, agent
experience, what your tools cost an agent in context, and performance. Two grades (**trust** and **agent readiness**),
plain findings, a fix for each, and a signed result anyone can verify.

```
npx saktum check -- npx -y @your/mcp-server          # a local server
npx saktum check https://your-server.example/mcp     # a remote server (sign-in checks run without a token)
```

Runs on your machine. Nothing is uploaded. Your own environment variables are never passed to the server.

## From trust to a marketplace (v0.8)

Every agent traceable to a person and an organisation (**identity chains**, with orphan detection); publishers sign
**manifests** and agents find tools **by intent** in a catalogue; providers and invokers sign **agreements** from a
default template plus specific terms; every call is **metered in prepaid tokens** (double-entry, no money handled), and
calls stop when credit runs out; **usage statements** and **KPIs** come from the signed receipts. Guide:
[docs/MARKETPLACE.md](docs/MARKETPLACE.md). Try: `npx saktum demo --story marketplace`.

## Agents that follow instructions (v0.7)

Mandates now carry **intent**: purpose, autonomy per action, rules, ranked preferences, substitution and upsell
policies, approval triggers, allowed counterparties and data sharing, written in domain terms (commerce, travel) and
enforced on any server through **semantic bindings**. Every receipt explains the decision: the rules checked, the
preferences matched or missed, and flags such as a sponsored option. Personal data goes only where the mandate allows;
confidential data only to the recipients named for its class; high-risk actions wait for the owner's signed approval
of exactly that action (`saktum agent approve`); the operator countersigns; `saktum agent revoke` stops an agent at
once; and every passport carries a track record.
Even if an agent is tricked by a hidden instruction, the mandate holds. Guide: [docs/MANDATES.md](docs/MANDATES.md).

## See it in 60 seconds

```
npx saktum demo
```

A grocery agent and a travel agent follow their owners' instructions: the usual brand matched; at most 2 of each item;
a substitute within 10% allowed but never for baby food; upgrades and fees ask first; a sponsored option flagged; a
two-stop or non-refundable fare blocked; a hidden instruction to buy gift cards and pay a stranger stopped; a passport
kept from a hotel partner; a confidential forecast kept from a partner agency; a $12,000 invoice paid only after your
signed approval of exactly that payment; and the stop button honoured. Every decision has a signed receipt with its reason, and each agent gets a
passport with its instructions in plain words. Also: `npx saktum demo --story autonomy` (notify, propose, act).

## Start here

| I want to… | Run |
| --- | --- |
| **Test an MCP server** | `npx saktum check -- npx -y some-mcp-server` (or `npx saktum check https://your-server/mcp`) |
| **Start a new MCP server** that earns top grades from the first commit | `npx saktum init my-server --lang ts` (or `--lang py`) |
| **Let my coding agent test and fix servers** | Claude Code: `claude mcp add saktum -- npx -y saktum mcp` · Cursor and VS Code: one-click buttons at [saktum.vercel.app](https://saktum.vercel.app) |
| **Check my whole agent set-up** (cost, duplicate tools, unvetted servers) | `npx saktum scan-config` |

| **Govern MCP use across my organisation** (inventory, policy as code, evidence) | See [docs/ENTERPRISE.md](docs/ENTERPRISE.md): `saktum fleet`, `--policy`, allowlists, security packets |

Everything else (CI, test cases, lint, diff, allowlists, attestations, security packets) is below.

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

## Permissions and risk (v0.6.1)

Grades say how well a server is built; the **risk tier** says how much care it needs: **R0** reads public information,
**R1** reads private data, **R2** changes data, **R3** irreversible actions or external messages, **R4** moves money or
runs code. Every report and passport shows both ("Trust A · Risk R4"), and policies can require evidence proportionate
to the tier (`maxRiskTier`).

Mandates carry real permissions, enforced by the proxy before each call: `--autonomy notify|propose|act`,
`--max checkout.amount=50`, `--allow-value checkout.currency=CAD`, `--approve-above amount=25`, `--daily-calls 20`,
`--daily-total amount=200`, disclosures (`--operator`, `--incentives`, `--data-use`), and no sub-delegation unless
`--allow-delegation`. Tools that move money are denied unless explicitly granted. Every receipt carries a reason code
(`ok-action`, `notify-only`, `approval-needed`, `over-cap`, `value-not-allowed`, `daily-limit`, `money-not-granted`).

## Govern what agents do: identity, mandates, signed receipts (preview)

Testing servers is half the story; the other half is **what agents actually do with them**. Give an agent its own
identity and a mandate you sign, put Saktum between the agent and a local MCP server, and every tool call gets a
**signed, hash-chained receipt**: which tools, how often, in what order, what was blocked.

```
npx saktum agent create --name "Billing assistant" --allow-tool get_invoice --allow-tool list_invoices   # did:key + signed mandate
npx saktum proxy --mandate agent-mandate.json --enforce -- npx -y billing-mcp-server                     # use in place of the server command
npx saktum receipts summary          # the path, not the answer: tools, order, retry storms, denials, destructive actions
npx saktum receipts verify           # every signature and the chain
```

Observe by default; `--enforce` blocks calls outside the mandate (including tools declared destructive, unless allowed),
with an honest error to the agent. Receipts follow Saktum's receipt contract and store arguments only as a digest.
Preview limits: local (stdio) servers; receipts are signed by the agent side (bilateral receipts, co-signed by the
server side, come with the Saktum gateway).

## Plugs into what you run, and pays for itself (v0.6)

| Command | What it does |
| --- | --- |
| `saktum watch saktum-allowlist.json` | Continuous monitoring: re-checks approved servers and alerts on changed tools, grade drops or unreachable servers (daily GitHub workflow: `examples/saktum-watch.yml`) |
| `saktum receipts export --otel receipts.otlp.json [--endpoint http://collector:4318]` | Agent receipts as OpenTelemetry traces, into your observability and security tools |
| `saktum attest saktum-report.json --vc` · `saktum vc verify file.vc.jwt` | Attestations as W3C Verifiable Credentials, issued by your did:key |
| `saktum roi --tokens-per-turn 32833 --agents 10` | What tool definitions cost a year and what fixes and passports save (assumptions shown); `assess` includes the business case |

## Passports: trust you can see

```
npx saktum passport -- npx -y your-mcp-server                                  # MCP Server Passport: identity, tools, trust, maturity
npx saktum passport --agent agent-mandate.json --receipts receipts.jsonl      # Agent Passport: mandate and the path of its calls
```

Every server recorded in the trust ledger gets a public passport page and a place in the
[passport gallery](https://soodhere.github.io/saktum-index/passports/).

## The trust ledger: Certificate Transparency for AI agent tools

Providers publish signed attestations to a **public, append-only, hash-chained ledger**; anyone can verify every
signature and the whole chain; firewalls, gateways and enterprises build allowlists from it.

```
npx saktum attest saktum-report.json --publish        # publish yours (opens a pre-filled issue; a bot verifies and records it)
npx saktum ledger verify                               # verify the public ledger: signatures and chain
npx saktum ledger find my-server                       # look a server up
npx saktum allowlist --from-ledger --trusted-signers signers.txt   # an allowlist for your MCP firewall
```

Entries are signed claims with their assurance level stated (L1 = self-tested); independent re-checks come later.

## Start right, and test while you build (shift left)

| Command | What it does |
| --- | --- |
| `saktum init my-server --lang ts` (or `py`) | A new MCP server that is trustworthy by default: an annotated example tool with an output schema, test cases, CI with Saktum Check and code scanning, and `AGENTS.md` rules for coding agents. Both templates earn trust A and agent readiness A out of the box |
| `saktum lint` | Static checks on tool registrations in your source (TypeScript and Python SDKs): missing annotations, weak descriptions, names model providers reject, with file and line (`--sarif` for editors and GitHub) |
| `saktum call <tool> --args '{...}' --save-test <id> -- <server>` | Call a tool, see the result, and save it as a test case in `saktum.tests.yaml` |
| `saktum check --watch -- <server>` | Re-run on every file change while you develop |

**For coding agents:** `skills/saktum-mcp-builder/` is a Claude Code skill (copy it into `~/.claude/skills/`), and
`agents/` holds an `AGENTS.md` section and Cursor rules, so the agents writing MCP servers follow the same practices.

## Use it from your coding agent (Saktum as an MCP server)

Add Saktum to Claude Desktop, Claude Code, Cursor or VS Code, and ask your agent to test and fix MCP servers:

```json
{ "mcpServers": { "saktum": { "command": "npx", "args": ["-y", "saktum", "mcp"] } } }
```

Try: *"Check the MCP server started by `node build/index.js` and fix anything below A."* ·
*"Suggest annotations for my server's tools in Python."* · *"Did my changes break anything compared with saktum.lock.json?"*

Tools: `check_server`, `suggest_annotations`, `diff_against_lock`, `generate_docs`, `explain_check`, `list_checks`.
Passive by default; local targets start on your machine; `active` only for servers you own. Saktum's own server earns
trust A and agent readiness A under its own checks.

## Check your whole agent set-up

`npx saktum scan-config` finds the MCP servers in Claude Desktop, Claude Code, Cursor and VS Code, asks before starting
them, and reports what they cost together every turn (and per month), duplicate and look-alike tools across servers,
servers not on your allowlist, and the weakest grades. Configured secrets are never printed.

## The provider toolkit

| Command | What it does |
| --- | --- |
| `saktum fix -- <server>` | Suggests danger annotations for every tool, as code to paste (`--format ts` or `py`), and flags annotations that contradict a tool's name |
| `saktum snapshot -- <server>` | Writes `saktum.lock.json`, a lock file of your tools |
| `saktum diff saktum.lock.json -- <server>` | Breaking changes (removed tools, new required fields, changed types), changes to review (descriptions, annotations: silent tool changes), additions, and the version bump they need; fails CI on breaking or risky changes |
| `saktum docs -- <server>` | A Markdown tools table and ready-to-paste configuration for Claude Desktop, Cursor and VS Code |
| `saktum allowlist reports/*.json` | An allowlist for MCP firewalls and gateways: only servers meeting your grades, each pinned to the exact tools that were checked (signatures verified first) |
| `saktum attest saktum-report.json` | A compact signed attestation (grades, maturity evidence, tool fingerprint) plus a README badge; anyone can check it with `saktum verify` |
| `saktum packet saktum-report.json` | A printable **security packet** for customers' security reviews, built from a verified signed result, with a section for your own statements (clearly marked as not verified) |

## In CI (GitHub Action)

```yaml
- uses: actions/checkout@v4
- uses: soodhere/saktum-check@v0.8.1
  with:
    target: "-- node build/index.js"     # or an https URL
    args: "--active --tests saktum.tests.yaml"   # optional; --active only for your own server
    fail-on: high
    sarif: "true"        # findings in GitHub's Security tab (add permissions: security-events: write)
    baseline: saktum-baseline.json   # optional: fail only on new findings
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
