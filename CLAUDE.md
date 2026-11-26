# CLAUDE.md: working rules for this repository

Saktum Trust Check tests MCP servers and agents (conformance, sign-in, security, function, agent experience) and produces a score, fixes and a signed, verifiable result. It is the base of the Saktum platform: its contracts, engine, transports and signing are reused by hosted certification, bounties and the gateway (from April 2027). **Nothing here is throwaway.**

Plan of record: "Saktum Trust Check — product, design and release plan to 1.0" (Baseline 7.0, v0.1.1 shipped publicly; public name Saktum Check, internal name Trust Check). Current step (rebaselined 3 Nov 2026): **finish Infrastructure by 16 Nov**, then v0.1 private beta by 30 Nov; v0.2 14 Dec; public launch with v0.3 about 19 Jan 2027; v1.0 by 30 Apr 2027.

## Commands
- `pnpm install` · `pnpm build` (tsc project references) · `pnpm test` (Vitest; spawns fixture servers)
- `pnpm saktum check -- <command that starts a server>` or `pnpm saktum check https://host/mcp`
- `pnpm saktum verify saktum-report.json`
- Fixtures: `pnpm fixture:good|broken|malicious` (add `--http 0` for Streamable HTTP)

## Repository map
- `contracts/` JSON Schemas (2020-12): pack, result, test cases, call envelope, receipt. **Change contracts first, then code.** Every schema has an example in `contracts/examples/`.
- `packs/` checks as data (YAML). Steps use a closed set of actions; logic lives in named analysers.
- `packages/testkit-core` engine: pack loader (signature-aware), runner, analysers, scoring, sanitiser.
- `packages/transports` MCP sessions over Streamable HTTP and stdio via the official SDK, read **tolerantly** (see ADR 0006).
- `packages/sign` RFC 8785 canonical JSON, Ed25519 detached JWS, did:key, local key storage.
- `packages/report` terminal and HTML renderers.
- `packages/cli` the `saktum` command.
- `fixtures/` good, broken, malicious and raw-protocol servers. `corpus/` real servers for validation runs.
- `docs/adr/` architecture decisions. Read them before changing anything structural.

## Non-negotiable rules
1. **Untrusted input.** Everything from a tested server is hostile. No server text reaches a terminal, report or log without `sanitizeText` (terminal) or `escapeHtml(sanitizeText(...))` (HTML). Responses are size- and depth-limited.
2. **Packs are data.** Never execute code from a pack. New logic goes into `analysers.ts`, versioned with the engine.
3. **Testing the tests.** Every scored check needs a fixture where it passes and one where it fails (`test/packs.test.ts` enforces this).
4. **Deterministic scoring.** Weights: critical 5, high 3, medium 2, low 1. Trust score = conformance 30%, sign-in 30%, security 40%; any failed critical check caps it at 49. Agent experience, functional tests and context cost are reported, never part of the trust score. No model ever decides a pass or fail.
5. **Inconclusive is not fail.** Timeouts, network errors and size limits produce `inconclusive`. A server that answers wrongly produces `fail`.
6. **Safety model.** Passive checks run against anything. Active checks and side-effect tests run only with `--active` against owned targets. Local servers get a minimal environment; secrets only via explicit `--env`.
7. **Honest signatures.** Local results are "self-run, self-signed": they prove integrity, not independence. Say so in every report.
8. **Polite.** Low concurrency, timeouts, identifying user agent (`saktum-trust-check/...`).
9. **Formats are versioned contracts** (`packFormat`, `resultFormat`, ...). Additive changes only within a minor version; breaking changes need a new major and a migration.
10. **Standards first**: MCP specification, JSON Schema 2020-12, JSON-RPC 2.0, OAuth RFCs, SARIF, RFC 7515/8785, did:key, CWE references.

## Definition of done (every change)
Typecheck and tests pass on Linux, macOS, Windows; new checks have passing and failing fixtures; no secret or raw payload in any output; docs updated; corpus run shows no new false positives.

## Lean backlog (Baseline 1.7), in order. Do the smallest thing that ships.

### Infrastructure, minimum before v0.1
- [ ] Release workflow: changesets, npm publish with provenance, SBOM (set up; do not publish until the employer IP confirmation)
- [ ] Nightly corpus runner over `corpus/corpus.yaml`, diffing against the previous run (the false-positive safety net)
- Later in the step, only if time allows: benchmarks in CI, pack-signing key ceremony, docs site skeleton, recovery runbook

### v0.1 private beta (target 30 Nov): beta users test their own, trusted servers
- [ ] Every check carries its OWASP MCP Top 10 ID in `references` (started in the packs); reports show an "OWASP MCP Top 10 coverage" section listing categories tested in this run and those planned (Baseline 3.3)
- [ ] Auth pack: 5 passive metadata checks (`auth.https`, `auth.www-authenticate`, `auth.resource-metadata`, `auth.server-metadata`, `auth.invalid-token`), each with passing and failing fixtures (add an OAuth-metadata fixture server)
- [x] `sec.secrets.exposed` and `sec.errors.leakage` (secrets, stack traces, paths in results and errors)
- [x] Context cost in money: `--price-per-mtok <n>` (user-set), shown next to tokens; never part of the trust score
- [ ] Human layer first: letter grade (A 90-100, B 80-89, C 70-79, D 50-69, F below 50 or any failed critical check) and a three-sentence plain-language summary at the top of terminal and HTML reports; "why this matters to your users" line on every finding. Plain words first, technical detail second. Publicly the tool is "Saktum Check".
- [x] Basic `saktum doctor`: runtime and version, npx and NVM on PATH, server starts, needs network or credentials at start, handshake
- [ ] Invite the beta users (see the Trust Check plan's evidence section)

### v0.3 additions (public launch)
Framework tags on every finding (NIST AI RMF function and Generative AI Profile, ISO/IEC 27001 and 42001 control areas, OWASP Top 10 for LLM applications, OWASP Top 10 for agentic applications, MITRE ATLAS, CWE), resolved from a signed framework reference catalogue (data file shared with Govern), shown in reports and SARIF. GitLab CI and Azure DevOps templates alongside the GitHub Action.

### Contracts note (Baseline 2.0)
The call envelope has an optional `context` (task, process, orchestrator, rationale, executor) and the receipt an optional `explanation` and `compensates` link, for the gateway's governance features (main plan LLD 39). Keep them optional and additive.

### Deferred to v0.2 (before the public launch)
Docker sandbox for local servers; remaining passive checks; (v0.3: badge with grade and date that fades after 90 days or when tools change; shareable report-card image); basic `saktum test`; active checks with proof of ownership; sign-in registration and redirect checks; lock file and "what changed"; `explain`; signed pack feed.

## Scope discipline (Baseline 4.0)
- Each release ships its **core** scope only (see the plan's 4.0 table). Stretch items wait for Saktum Check 1.1 (Jun 2027) or 1.2 (Sep 2027): `--semantic` mode, memory-leakage and unsafe-delegation tests, compensation tests, `inspect`, `docs`, open benchmark publication, VS Code preview.
- v0.9 includes `--registry <path>`: write the signed result into `evidence/test_results/` of the open governance registry format.
- New ideas go to the backlog by default; they enter a release only by replacing something of equal size, or after a decision gate. If a task is not in the current release's core, ask before building it.

## Traceable conformance (Baseline 4.1)
- Every check gets a structured `normative` list (source, version, clause, level MUST/SHOULD/MAY/best-practice). Four checks are filled; fill the rest by v0.3 and **verify clause wording against the current MCP specification and RFCs** (entries marked `verify-latest`).
- Generate the public traceability matrix and test specification from the packs (never hand-written separately). Publish accuracy (false-positive and false-negative rates) per check from the corpus.
- Every report states its assurance level; Saktum Check results are L1 (self-tested).

## Standards-traced core (Baseline 5.0)
Read docs/adr/0007-0010. Core additions: clause traceability for sign-in checks; token-passthrough and audience check (v0.2); refresh-rotation reporting (v0.4); OpenSSF Scorecard signals (v0.5); Saktum Agent Security Profile Baseline tests (draft at launch, conformance in v1.0); every report states its assurance level (L1). Saktum's own releases target SLSA level 3.

## Pre-execution freeze (Baseline 6.0)
- The plan is frozen. Do not add scope: anything new goes to a BACKLOG.md entry with its source, for review at the next decision gate.
- Exception: a public MCP incident becomes a fixture and regression test in the incident library (start at v0.3; supply-chain patterns in v0.5).
- v0.5 report: flag tool sets enabling the lethal trifecta (private data + untrusted content + external communication) using capability classes.
- Never claim that nobody certifies AI: Saktum's evidence feeds AIUC-1, CSA STAR for AI, HITRUST AI and ISO/IEC 42001 audits.

## Four-week cadence (Baseline 6.1): the only work until 13 Dec 2026
Goal by Tue 8 Dec: 5 developers ran it on their own servers, 3 fixed a finding, 2 quotes. v0.1 scope, exactly:
- [x] Grade (A 90-100, B 80-89, C 70-79, D 50-69, F below 50 or any failed critical) and three-sentence plain summary
- [x] Five sign-in metadata checks (HTTPS, WWW-Authenticate, protected-resource metadata RFC 9728, server metadata RFC 8414, invalid-token rejection) with an OAuth fixture server
- [x] `sec.secrets.exposed` and `sec.errors.leakage` with passing and failing fixtures
- [x] Context cost in money (`--price-per-mtok`) and largest tools
- [x] Basic `saktum doctor`
- [x] OWASP MCP Top 10 coverage section in reports; one-page quickstart
- [x] Single-file bundle `saktum.mjs` (esbuild) attached to a private GitHub Release
Not in scope: Docker sandbox, GitHub Action, hosted services, telemetry. See docs/BETA.md for invites and metrics.

## v0.1.0 built and validated (16 Nov 2026)
24 checks in 5 packs (conformance 6, auth 6, security 5, agent experience 3, performance 4); 62 tests. Validated on 37 real
npm and Python servers (31 assessed): see docs/VALIDATION.md for results and the six Saktum bugs the run found and fixed.
Observation for the December gate: grades cluster at A because v0.1 checks are mostly hygiene; v0.2's active and deeper
sign-in checks will differentiate. Revisit severity weights (for example missing danger annotations) with beta feedback.
Before inviting users: run a few real remote servers, with and without a token (the sandbox could not reach any).
Next: push to the private repository, tag v0.1.0, invite beta users (docs/BETA.md, docs/QUICKSTART.md).

## Status (Baseline 7.0, 17 Nov 2026)
- PUBLIC: github.com/soodhere/saktum-check and npm `saktum` (v0.1.1). Releases: bump the version in npm/package.json,
  packages/cli/package.json, ENGINE_VERSION and the user agent, then Actions > release > Run workflow with the same version.
- Until the 13 Dec gate: v0.1.x fixes from public feedback only. Gate: at least 10 people giving feedback, at least 3
  server reports, and a clear v0.2 priority. v0.2 scope is chosen from the Discussions poll and issues.
- Posture: public repository, no LinkedIn promotion. Never name specific servers' findings in public.

## v0.2.0 (22 Nov 2026): functional testing and transparency
Functional pack (active: respond, output schema, graceful errors, survival); provider test cases (`saktum test`,
docs/TESTS.md); load (latency percentiles, 1/5/20 concurrency, memory growth); conservative capability profile and
lethal-trifecta warning; trust card and scope of run in every report; `saktum checks` (docs/CHECKS.md); `--ignore` with
reasons; `--badge`. Safety: tools are called only with --active, only read-only tools unless named with --call or in a
test case; destructive tools never automatically. 94 tests; validated passive on 30 servers and active on 7 with no
false failures (docs/VALIDATION.md). Keep capability inference conservative: any new rule must be re-reviewed on the corpus.

## v0.3.0 (23 Nov 2026): the provider toolkit
fix (annotation suggestions as TS/Python code, conflicts), snapshot/diff (tool lock file, breaking and risky changes,
semver advice, CI exit code), docs (tools table, client configuration), packet (security packet from a verified signed
result; provider statements marked unverified), sec.http.origin (local HTTP servers must refuse foreign origins: DNS
rebinding), ax.client-compat (informational), negotiated protocol version recorded. 108 tests.

## v0.4.0 (24 Nov 2026): agents, set-ups and CI
saktum mcp (Saktum as an MCP server; dogfood trust A, readiness A, functional 4/4), attest (signed attestation from a
verified result; L1 to L4 evidence only), scan-config (client configurations; consent; secrets never printed; total
cost, duplicates, look-alike tools, allowlist), SARIF 2.1.0 and baseline (fail only on new findings), Action inputs
sarif and baseline, server.json for the official MCP Registry. 122 tests.
Shift left (also v0.4.0): init (TS with the MCP SDK and zod; Python pinned to mcp<2, since the v2 SDK renamed FastMCP to
MCPServer; both templates validated end to end at trust A, readiness A, functional 6/6), lint (only files importing an
MCP SDK; file and line; SARIF), call --save-test, check --watch, skill pack (skills/, agents/).
First run (also v0.4.0): `saktum` with no command shows four journeys; README "Start here"; website install buttons
(Cursor and VS Code links, Claude Code command). Feature freeze after v0.4.0 until census v2 and update 3. 126 tests.
Enterprise (also v0.4.0): policy as code (contracts/policy.schema.json; --policy on check, scan-config and the Action;
exceptions with reason, approver and expiry), saktum fleet (organisation inventory from many scan-config outputs; command
lines redacted), CycloneDX SBOM attached to every release (scripts/sbom.mjs), docs/ENTERPRISE.md with the MCP Trust Pilot.
133 tests.
Trust ledger (also v0.4.0): Certificate Transparency for MCP servers. ledger.ts (append-only, hash-chained, signature-
verified; tamper-evident), CLI ledger verify/find/append, attest --publish (pre-filled issue link), allowlist
--from-ledger --trusted-signers; the bot lives in saktum-index (.github/workflows/ledger.yml; never runs anyone's code).
Agent governance preview (also v0.4.0): agentid.ts (mandate contract: did:key agent, owner-signed scope and expiry),
receipts.ts (receipt-contract instances signed by the agent side, hash-chained; path summary with retry storms), proxy.ts
(stdio relay: observe or --enforce; arguments stored as digests). Real run: memory server, read-only mandate, write
blocked, receipts verified. 143 tests. Next for this line: bilateral receipts and HTTP in the gateway.

## v0.5.0 (25 Nov 2026): trust you can see, and the pilot kit
passport (server: identity, interface, maturity, verification; agent: mandate and receipt timeline with repeated calls
highlighted), ledger pages (public passport per ledger entry and a gallery; generated by the ledger bot), assess
(executive MCP Trust Assessment from fleet, policy and receipts), docs/PILOT.md (playbook, proposal, letter of intent,
discovery questions including bounty interest). 152 tests. Bounty marketplace deferred until interviews show demand.
Packaging rule (25 Nov 2026): saktum-index zips must never contain docs/ledger/ledger.jsonl or docs/passports/ (the
ledger is append-only and lives only in the repository; copying a starter file over it once emptied the public ledger,
restored from git history).

## v0.6.0 (26 Nov 2026): plugs into what you run, and pays for itself
watch (allowlist re-checks: changed tools, grade drops, unreachable; webhook; daily workflow template), receipts export
--otel (OTLP/JSON, GenAI semconv execute_tool + saktum.* attributes), attest --vc and vc verify (W3C VC 2.0 as vc+jwt,
EdDSA, did:key issuer), roi and the assessment business case (assumptions always shown). ADR 0012 interoperability. 157 tests.

## v0.6.1 (26 Nov 2026): risk-aware trust, permissions, and the demo
risk.ts (R0 to R4 from capabilities and annotations; shown with grades; policy maxRiskTier), mandate v0.2 (autonomy
notify/propose/act, argument constraints, daily limits, approval threshold, disclosures, delegation off by default;
contract updated), decideCall with reason codes enforced by the proxy before each call (money tools denied unless
granted; daily usage from the receipt log, which records only governed values), agent risk tier, Agent Passport
permissions table, ax.payments-idempotent (informational), `saktum demo` (built-in shop server, three mandates, signed
receipts, passports). 162 tests.

## v0.7.0 (26 Nov 2026): the trust model in code (supersedes the unreleased 0.6.1)
vocab.ts (commerce and travel vocabularies; semantic bindings declared in tool _meta io.saktum/bindings and
io.saktum/action, or inferred from argument names; action classes), mandate v0.3 (purpose, actions with autonomy,
rules, preferences, substitution, upsell, approval triggers, counterparties, data sharing; contract updated),
decideIntent with rationale (rules checked, preferences, flags) applied by the proxy after decideCall, describeMandate
(plain language), passports with instructions and per-step reasons, `saktum agent create --intent`, `saktum bindings`,
`saktum demo` (grocery and travel stories; autonomy story kept). Includes 0.6.1: risk tiers, permissions, reason codes.
167 tests.
v0.7.0 also closes the honest gaps: personal-data fields and enforced data sharing (data-not-permitted), operator
countersignature (cosign; checkMandate ignores it; checkOperator verifies it against mandateDigest), revocation
(agent revoke; proxy --revocations; code revoked), agent software, trust statement (track record, never a score), and
the demo shows a hidden-instruction attack held by the mandate, data kept from a hotel partner and the stop button. 171 tests.
v0.7.0 final additions (unreleased until now, so folded in): enterprise data classes (enterprise.data_class enforced
through dataSharing like personal data), signed single-use approvals of exactly one action (approvalRequestId over
mandate digest, tool and argument digest; agent approve; proxy --approvals; receipts record "approved by"), mandate
digest normalised through JSON, finance demo story. All seven board questions (Snowflake ebook list) answered. 174 tests.

## v0.8.0 (28 Nov 2026): from trust to a marketplace (the October vision's market half)
market.ts: identity chains (organisationRoot, issueCredential signed without chain then chain attached, verifyChain link
by link, findOrphans), manifests (intents from action classes and bindings; signed by publisher) and searchCatalogue,
agreements (draft by provider from DEFAULT_TERMS, accept by invoker countersignature, verifyAgreement), wallet
(double-entry prepaid tokens; chargeCall refuses on insufficient credit), usageStatement, kpis. Proxy: --credential
(identity-chain), --agreement (no-valid-agreement, outside-agreement), --wallet (insufficient-credit); receipts carry
metering. Contracts: credential, manifest, agreement, bounty (11 total). CLI: org, identity, manifest, catalog,
agreement, wallet, usage, kpi, bounty validate. Demo story marketplace. 179 tests.
v0.8.1: agent maturity A1-A5 (agentMaturity, evidence-based, shown in Agent Passports); marketplace demo mandate gains
an approval threshold so it is Bounded; demo agents earn A4 (A5 needs a 10-action track record). 180 tests.
