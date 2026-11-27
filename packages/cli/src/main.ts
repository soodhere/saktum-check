#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { passportSlug, renderAgentPassport, renderAssessment, renderLedgerPassport, renderPassportGallery, renderServerPassport, badgeSvg, checksTable, renderHtml, renderPacket, renderTerminal, SELF_SIGNED_NOTE, toSarif } from "@saktum/report";
import { loadOrCreateKey, signDocument, verifyDocument } from "@saktum/sign";
import { actionClass, bindingsFor, describeMandate, attestationToCredential, receiptsToOtlp, roiEstimate, ROI_DEFAULTS, signCredentialJwt, verifyCredentialJwt, watchAllowlist, type WatchEntry, crosswalk, coverageSummary, DISCLAIMER, agentMaturity, acceptAgreement, buildManifest, draftAgreement, findOrphans, issueCredential, kpis, organisationRoot, searchCatalogue, topUp, usageStatement, verifyAgreement, verifyChain, walletBalance, type Agreement, type Credential, type Manifest, approveAction, checkOperator, cosignMandate, revocationOf, revokeMandate, trustStatement, agentRiskTier, checkMandate, createMandate, parseReceiptLog, summariseReceipts, verifyReceiptLog, type Mandate, allowlistFromLedger, appendToLedger, DEFAULT_LEDGER_URL, extractJson, findInLedger, parseLedger, verifyLedger, buildFleet, evaluatePolicy, fleetHtml, parsePolicy, redactCommand, redactUrl, renderFleet, renderVerdict, subjectFromResult, type Policy, appendTestCase, lintPaths, lintSarif, analyseSetup, configLocations, parseClientConfig, renderSetup, type ServerScan, buildAllowlist, buildAttestation, compileContract, diffLocks, docsFor, ENGINE_VERSION, loadEmbeddedPacks, loadPackDir, parseTestCases, renderFix, runTrustCheck, sanitizeText, toolsLock, type Result, type Severity, type ToolsLock } from "@saktum/testkit-core";
import { connect } from "@saktum/transports";
import { runDoctor } from "./doctor.js";
import { parseTarget } from "@saktum/transports";

const SEV: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Load a policy file and the allowlist it names (relative to the policy file). */
async function loadPolicy(file: string): Promise<{ policy: Policy; allow?: Set<string> }> {
  const { readFileSync: rf, existsSync: ex } = await import("node:fs");
  const { dirname, resolve } = await import("node:path");
  if (!ex(file)) throw new Error(`Policy file not found: ${file}`);
  const policy = await parsePolicy(rf(file, "utf8"));
  let allow: Set<string> | undefined;
  if (policy.allowlist) {
    const path = resolve(dirname(file), policy.allowlist);
    if (!ex(path)) throw new Error(`The policy's allowlist was not found: ${policy.allowlist}`);
    allow = new Set((JSON.parse(rf(path, "utf8")) as { allowed: { toolsFingerprint?: string }[] }).allowed.map((a) => a.toolsFingerprint).filter((f): f is string => Boolean(f)));
  }
  return { policy, allow };
}

/** Read a ledger from a file or an https URL. */
async function readLedgerText(src: string): Promise<string> {
  if (/^https:\/\//.test(src)) { const r = await fetch(src, { headers: { "User-Agent": "saktum" } }); if (!r.ok) throw new Error(`Could not read the ledger (HTTP ${r.status})`); return r.text(); }
  const { readFileSync: rf, existsSync: ex } = await import("node:fs");
  return ex(src) ? rf(src, "utf8") : "";
}

/** First run: `saktum` with no command shows four journeys instead of the full command list. */
export const WELCOME = `Saktum Check \u2014 make the tools AI agents use trustworthy.

What would you like to do?

  0. See it in 60 seconds        npx saktum demo
  1. Test an MCP server          npx saktum check -- npx -y some-mcp-server
                                 npx saktum check https://your-server.example/mcp
  2. Start a new MCP server      npx saktum init my-server --lang ts   (or --lang py)
  3. Let your coding agent       claude mcp add saktum -- npx -y saktum mcp
     test and fix servers        (Cursor and VS Code: one-click buttons at saktum.vercel.app)
  4. Check your agent set-up     npx saktum scan-config

All commands: npx saktum --help \u00b7 Guide: https://github.com/soodhere/saktum-check
`;
const bundledPacks = fileURLToPath(new URL("../../../packs/", import.meta.url));
const collect = (v: string, acc: string[]) => [...acc, v];
const parseHeaders = (hs: string[]) => Object.fromEntries(hs.map((h) => { const i = h.indexOf(":"); if (i < 1) throw new Error(`--header must look like "Name: value"`); return [h.slice(0, i).trim(), h.slice(i + 1).trim()]; }));
const parseEnv = (kvs: string[]) => Object.fromEntries(kvs.map((kv) => { const i = kv.indexOf("="); if (i < 1) throw new Error(`--env must look like NAME=VALUE`); return [kv.slice(0, i), kv.slice(i + 1)]; }));

export async function main(argv = process.argv): Promise<number> {
  let exitCode = 0;
  const program = new Command().name("saktum").version(ENGINE_VERSION).description("Saktum Check: test MCP servers for trust (conformance, sign-in, security), functional behaviour, performance and agent readiness.").exitOverride();

  type CheckOpts = { packs?: string; out: string; html?: string; failOn: Severity; active: boolean; key?: string; env: string[]; header: string[]; pricePerMtok: string; call: string[]; tests?: string; ignore: string[]; badge?: string; sarif?: string; sarifAnchor: string; baseline?: string; updateBaseline: boolean; watch: boolean; watchDir: string; policy?: string };
  const withCheckOptions = (c: Command, testsDefault?: string) => c
    .option("--packs <dir>", "directory of packs (default: the built-in packs)")
    .option("--out <file>", "signed JSON result", "saktum-report.json")
    .option("--html <file>", "also write an HTML report")
    .option("--badge <file>", "also write a README badge (SVG) with the trust and agent-readiness grades")
    .option("--sarif <file>", "also write SARIF 2.1.0 for GitHub code scanning")
    .option("--sarif-anchor <path>", "file that SARIF results point to in your repository", "package.json")
    .option("--baseline <file>", "fail only on findings that are not in this baseline file (accepted existing findings)")
    .option("--update-baseline", "write the current failed checks to the --baseline file and exit successfully", false)
    .option("--policy <file>", "your organisation's policy (saktum-policy.yaml): exit 1 if the server violates it")
    .option("--watch", "re-run whenever a file changes (development loop; Ctrl+C to stop)", false)
    .option("--watch-dir <dir>", "folder to watch with --watch", ".")
    .option("--fail-on <severity>", "exit 1 if any failure at or above this severity", "high")
    .option("--active", "call tools and measure load (only against servers you own; read-only tools unless named with --call)", false)
    .option("--call <tool>", "with --active: also call this tool even if it is not annotated read-only (repeatable)", collect, [] as string[])
    .option("--tests <file>", "run your test cases (YAML or JSON, see docs/TESTS.md)", testsDefault)
    .option("--ignore <check=reason>", "ignore a check, with a reason shown in the report; check IDs may end with * (repeatable)", collect, [] as string[])
    .option("--key <path>", "signing key file (created on first use)")
    .option("--env <KEY=VALUE>", "environment variable for a local server (repeatable); your own environment is never passed", collect, [] as string[])
    .option("--header <Name: value>", "HTTP header for a remote server, e.g. \"Authorization: Bearer <token>\" (repeatable)", collect, [] as string[])
    .option("--price-per-mtok <usd>", "your model's price per million input tokens, for the context-cost estimate", "3");

  const runCheckCommand = async (targetParts: string[], o: CheckOpts): Promise<number> => {
    if (!SEV.includes(o.failOn)) throw new Error(`--fail-on must be one of ${SEV.join(", ")}`);
    const price = Number(o.pricePerMtok);
    if (!Number.isFinite(price) || price < 0) throw new Error("--price-per-mtok must be a number of US dollars, e.g. 3");
    const ignore = o.ignore.map((x) => { const i = x.indexOf("="); if (i < 1 || !x.slice(i + 1).trim()) throw new Error(`--ignore must look like check.id="reason" (a reason is required)`); return { check: x.slice(0, i).trim(), reason: x.slice(i + 1).trim() }; });
    let testCases;
    if (o.tests) {
      if (!existsSync(o.tests)) throw new Error(`Test file not found: ${o.tests}. See docs/TESTS.md for the format.`);
      testCases = await parseTestCases(readFileSync(o.tests, "utf8"));
    }
    const target = parseTarget(targetParts);
    if (target.kind === "stdio" && o.env.length) target.env = parseEnv(o.env);
    if (target.kind === "streamable-http" && o.header.length) target.headers = parseHeaders(o.header);
    const packs = o.packs ? loadPackDir(o.packs) : existsSync(bundledPacks) ? loadPackDir(bundledPacks) : loadEmbeddedPacks();
    let result: Result;
    try {
      result = await runTrustCheck(target, { packs, mode: o.active ? "active" : "passive", pricePerMTokUsd: price, callTools: o.call, testCases, ignore });
    } catch (e) {
      process.stderr.write(`Could not connect to ${sanitizeText(targetParts.join(" "), 120)}: ${sanitizeText((e as Error).message, 300)}\n`);
      process.stderr.write(`Hint: run saktum doctor ${targetParts[0]?.startsWith("http") ? "" : "-- "}${sanitizeText(targetParts.join(" "), 120)} to see why.\n`);
      return 2;
    }
    const signed = signDocument(result, loadOrCreateKey(o.key)) as Result;
    writeFileSync(o.out, JSON.stringify(signed, null, 2));
    if (o.html) writeFileSync(o.html, renderHtml(signed));
    if (o.badge) writeFileSync(o.badge, badgeSvg(signed));
    const keyOf = (f: { check: string; subject?: string }) => `${f.check}:${f.subject ?? ""}`;
    const failing = signed.findings.filter((f) => f.status === "fail" && !f.suppressed);
    let accepted = new Set<string>();
    if (o.baseline && o.updateBaseline) {
      writeFileSync(o.baseline, JSON.stringify({ baselineFormat: "0.1", createdAt: new Date().toISOString(), accepted: failing.map((f) => ({ check: f.check, subject: f.subject, severity: f.severity, title: f.title })) }, null, 2) + "\n");
      process.stdout.write(`Wrote baseline ${sanitizeText(o.baseline)} accepting ${failing.length} existing finding(s). Commit it; later runs fail only on new findings.\n`);
    } else if (o.baseline && existsSync(o.baseline)) {
      accepted = new Set((JSON.parse(readFileSync(o.baseline, "utf8")) as { accepted: { check: string; subject?: string }[] }).accepted.map(keyOf));
    }
    if (o.sarif) writeFileSync(o.sarif, JSON.stringify(toSarif(signed, o.sarifAnchor, accepted), null, 2) + "\n");
    process.stdout.write(renderTerminal(signed) + "\n");
    process.stdout.write(`\nSigned result: ${sanitizeText(o.out)}  (verify with: saktum verify ${sanitizeText(o.out)})${o.badge ? `\nBadge: ${sanitizeText(o.badge)}` : ""}\n`);
    const threshold = SEV.indexOf(o.failOn);
    if (o.updateBaseline) return 0;
    if (o.policy) {
      const { policy, allow } = await loadPolicy(o.policy);
      const verdict = evaluatePolicy(subjectFromResult(signed), policy, allow);
      process.stdout.write(`\nPOLICY${policy.name ? ` (${sanitizeText(policy.name, 80)})` : ""}\n${renderVerdict(verdict)}\n`);
      if (!verdict.compliant) return 1;
    }
    const newFails = failing.filter((f) => !accepted.has(keyOf(f)));
    if (accepted.size) process.stdout.write(`Baseline: ${failing.length - newFails.length} accepted finding(s) ignored for the exit code; ${newFails.length} new.\n`);
    return newFails.some((f) => SEV.indexOf(f.severity) <= threshold) ? 1 : 0;
  };

  withCheckOptions(program.command("check")
    .description("Test an MCP server: a URL, or the command that starts a local server (after --)")
    .argument("<target...>", "https://host/mcp  or  -- node server.js"))
    .action(async (targetParts: string[], o: CheckOpts) => { exitCode = o.watch ? await watchLoop(targetParts, o) : await runCheckCommand(targetParts, o); });

  /** Development loop: run, then re-run on every change (ignoring dependencies, builds and reports). */
  const watchLoop = async (targetParts: string[], o: CheckOpts): Promise<number> => {
    const { watch } = await import("node:fs");
    let timer: NodeJS.Timeout | undefined, running = false, again = false;
    const once = async () => {
      if (running) { again = true; return; }
      running = true;
      process.stdout.write(`\n\u2500\u2500 ${new Date().toLocaleTimeString()} \u2500\u2500\n`);
      try { await runCheckCommand(targetParts, o); } catch (e) { process.stderr.write(`${sanitizeText((e as Error).message, 300)}\n`); }
      running = false;
      if (again) { again = false; await once(); }
    };
    await once();
    process.stdout.write(`\nWatching ${sanitizeText(o.watchDir)} for changes (Ctrl+C to stop).\n`);
    watch(o.watchDir, { recursive: true }, (_e, f) => {
      const name = String(f ?? "");
      if (/(^|[\\/])(node_modules|\.git|dist|build|\.venv|__pycache__)([\\/]|$)|saktum-report|\.sarif$/.test(name)) return;
      clearTimeout(timer); timer = setTimeout(() => void once(), 600);
    });
    return new Promise<number>(() => undefined);
  };

  withCheckOptions(program.command("test")
    .description("Run your test cases (saktum.tests.yaml by default) plus every check, against a server")
    .argument("<target...>", "https://host/mcp  or  -- node server.js"), "saktum.tests.yaml")
    .action(async (targetParts: string[], o: CheckOpts) => { exitCode = await runCheckCommand(targetParts, o); });

  program.command("checks")
    .description("List every check: what it tests, the standard behind it, and when it runs")
    .option("--markdown", "print a Markdown table (as in docs/CHECKS.md)", false)
    .option("--packs <dir>", "directory of packs (default: the built-in packs)")
    .action((o: { markdown: boolean; packs?: string }) => {
      const packs = o.packs ? loadPackDir(o.packs) : existsSync(bundledPacks) ? loadPackDir(bundledPacks) : loadEmbeddedPacks();
      process.stdout.write(checksTable(packs, o.markdown));
    });


  /** Connect to a target and list its tools (for the provider toolkit commands). */
  const listTarget = async (targetParts: string[], env: string[], header: string[]) => {
    const target = parseTarget(targetParts);
    if (target.kind === "stdio" && env.length) target.env = parseEnv(env);
    if (target.kind === "streamable-http" && header.length) target.headers = parseHeaders(header);
    const s = await connect(target);
    try { return { target, tools: await s.listTools(), server: s.serverInfo as Record<string, unknown> | undefined }; } finally { await s.close(); }
  };

  program.command("fix")
    .description("Suggest annotations (and other quick fixes) for every tool, as code to paste")
    .argument("<target...>", "https://host/mcp  or  -- node server.js")
    .option("--format <ts|py|json>", "code style: TypeScript SDK, Python SDK, or JSON", "ts")
    .option("--env <KEY=VALUE>", "environment variable for a local server (repeatable)", collect, [] as string[])
    .option("--header <Name: value>", "HTTP header for a remote server (repeatable)", collect, [] as string[])
    .action(async (targetParts: string[], o: { format: "ts" | "py" | "json"; env: string[]; header: string[] }) => {
      const { tools } = await listTarget(targetParts, o.env, o.header);
      process.stdout.write(renderFix(tools, o.format));
    });

  program.command("snapshot")
    .description("Write a lock file of the server's tools, to detect breaking or silent changes later with saktum diff")
    .argument("<target...>", "https://host/mcp  or  -- node server.js")
    .option("--out <file>", "lock file", "saktum.lock.json")
    .option("--env <KEY=VALUE>", "environment variable for a local server (repeatable)", collect, [] as string[])
    .option("--header <Name: value>", "HTTP header for a remote server (repeatable)", collect, [] as string[])
    .action(async (targetParts: string[], o: { out: string; env: string[]; header: string[] }) => {
      const { tools, server } = await listTarget(targetParts, o.env, o.header);
      writeFileSync(o.out, JSON.stringify(toolsLock(tools, server), null, 2) + "\n");
      process.stdout.write(`Wrote ${sanitizeText(o.out)} with ${tools.length} tools. Commit it; run saktum diff in CI to catch breaking or silent changes.\n`);
    });

  program.command("diff")
    .description("Compare tools with a lock file: breaking changes, risky changes (silent tool changes), additions, and the version bump they need")
    .argument("<lock>", "the lock file written by saktum snapshot")
    .argument("[target...]", "a second lock file, or the server to compare (after --)")
    .option("--allow-breaking", "do not fail on breaking or risky changes", false)
    .option("--env <KEY=VALUE>", "environment variable for a local server (repeatable)", collect, [] as string[])
    .option("--header <Name: value>", "HTTP header for a remote server (repeatable)", collect, [] as string[])
    .action(async (lock: string, rest: string[], o: { allowBreaking: boolean; env: string[]; header: string[] }) => {
      const before = JSON.parse(readFileSync(lock, "utf8")) as ToolsLock;
      const after = rest.length === 1 && rest[0]!.endsWith(".json") ? (JSON.parse(readFileSync(rest[0]!, "utf8")) as ToolsLock) : { tools: (await listTarget(rest, o.env, o.header)).tools };
      const d = diffLocks(before, after);
      const mark = { breaking: "\u2717 BREAKING", risky: "! REVIEW  ", addition: "+ ADDED   ", change: "~ CHANGED " };
      for (const c of d.changes) process.stdout.write(`${mark[c.kind]} ${sanitizeText(c.tool, 60)}: ${sanitizeText(c.detail, 200)}\n`);
      process.stdout.write(`\n${d.summary}\n`);
      exitCode = !o.allowBreaking && d.changes.some((c) => c.kind === "breaking" || c.kind === "risky") ? 1 : 0;
    });

  program.command("docs")
    .description("Generate a Markdown tools table and ready-to-paste client configuration")
    .argument("<target...>", "https://host/mcp  or  -- npx -y your-package")
    .option("--name <name>", "server name in the client configuration")
    .option("--env <KEY=VALUE>", "environment variable for a local server (repeatable)", collect, [] as string[])
    .option("--header <Name: value>", "HTTP header for a remote server (repeatable)", collect, [] as string[])
    .action(async (targetParts: string[], o: { name?: string; env: string[]; header: string[] }) => {
      const { target, tools, server } = await listTarget(targetParts, o.env, o.header);
      const name = o.name ?? String(server?.["name"] ?? "server");
      process.stdout.write(docsFor(tools, name, target.kind === "stdio" ? { command: target.command, args: target.args } : { url: target.url }));
    });

  program.command("packet")
    .description("Turn a signed result into a printable security packet for customers' security reviews")
    .argument("<result>", "a signed result (saktum-report.json)")
    .option("--out <file>", "HTML packet (print to PDF from a browser)", "saktum-security-packet.html")
    .action((file: string, o: { out: string }) => {
      const doc = JSON.parse(readFileSync(file, "utf8")) as Result & { signature?: unknown };
      const v = verifyDocument(doc);
      if (!v.valid) throw new Error(`The result's signature is not valid (${v.reason}); a packet must be built from an unaltered signed result.`);
      writeFileSync(o.out, renderPacket(doc, v.kid));
      process.stdout.write(`Wrote ${sanitizeText(o.out)}: open it in a browser and print to PDF. Send it with ${sanitizeText(file)} so customers can verify it.\n`);
    });

  program.command("allowlist")
    .description("Build an allowlist for MCP firewalls and gateways from signed results: only servers meeting your criteria, pinned to the tools that were checked")
    .argument("[results...]", "signed results (saktum-report.json files)")
    .option("--from-ledger [source]", "build it from the public Saktum trust ledger (or a ledger file or URL) instead of results")
    .option("--trusted-signers <file>", "with --from-ledger: only accept entries signed by these keys (one did:key per line)")
    .option("--min-trust <grade>", "minimum trust grade", "A")
    .option("--min-readiness <grade>", "minimum agent-readiness grade", "B")
    .option("--allow-critical", "do not exclude servers with a failed critical check", false)
    .option("--out <file>", "allowlist file", "saktum-allowlist.json")
    .action(async (files: string[], o: { minTrust: string; minReadiness: string; allowCritical: boolean; out: string; fromLedger?: string | boolean; trustedSigners?: string }) => {
      if (o.fromLedger) {
        const entries = parseLedger(await readLedgerText(typeof o.fromLedger === "string" ? o.fromLedger : DEFAULT_LEDGER_URL));
        const check = verifyLedger(entries);
        if (!check.ok) throw new Error(`The ledger does not verify: ${check.errors[0]}`);
        const signers = o.trustedSigners ? new Set(readFileSync(o.trustedSigners, "utf8").split(/\r?\n/).map((l) => l.trim()).filter(Boolean)) : undefined;
        const list = allowlistFromLedger(entries, { minTrust: o.minTrust.toUpperCase(), minReadiness: o.minReadiness.toUpperCase(), trustedSigners: signers });
        writeFileSync(o.out, JSON.stringify(list, null, 2) + "\n");
        process.stdout.write(`Ledger verified (${check.count} entries). Wrote ${sanitizeText(o.out)}: ${list.allowed.length} allowed, ${list.excluded.length} excluded.\n`);
        return;
      }
      if (!files.length) throw new Error("Give signed results, or use --from-ledger.");
      const inputs = files.map((f) => {
        const doc = JSON.parse(readFileSync(f, "utf8")) as Result;
        const v = verifyDocument(doc);
        if (!v.valid) throw new Error(`${f}: signature not valid (${v.reason}); only unaltered signed results can be allowlisted.`);
        return { result: doc, signedBy: v.kid };
      });
      const list = buildAllowlist(inputs, { minTrust: o.minTrust.toUpperCase(), minReadiness: o.minReadiness.toUpperCase(), noFailedCritical: !o.allowCritical });
      writeFileSync(o.out, JSON.stringify(list, null, 2) + "\n");
      for (const a of list.allowed) process.stdout.write(`\u2713 ${sanitizeText(a.server, 60)} ${sanitizeText(a.version ?? "", 20)}  trust ${a.trustGrade} \u00b7 readiness ${a.readinessGrade} \u00b7 ${a.toolCount} tools pinned\n`);
      for (const x of list.excluded) process.stdout.write(`\u2717 ${sanitizeText(x.server, 60)}: ${sanitizeText(x.reason, 200)}\n`);
      process.stdout.write(`\nWrote ${sanitizeText(o.out)}: ${list.allowed.length} allowed, ${list.excluded.length} excluded.\n`);
    });

  program.command("init")
    .description("Start a new MCP server that is trustworthy by default (annotations, output schema, test cases, CI, agent rules)")
    .argument("[dir]", "folder to create the project in", ".")
    .option("--lang <ts|py>", "TypeScript (MCP SDK) or Python (FastMCP)", "ts")
    .option("--name <name>", "server name")
    .action(async (dir: string, o: { lang: string; name?: string }) => {
      const { initProject } = await import("./init.js");
      const { basename, resolve } = await import("node:path");
      const lang = o.lang === "py" ? "py" : "ts";
      const files = initProject(dir, lang, o.name ?? basename(resolve(dir)));
      process.stdout.write(`Created ${files.length} files in ${sanitizeText(dir)}:\n${files.map((f) => `  ${f}`).join("\n")}\n\nNext:\n`
        + (lang === "ts" ? `  cd ${sanitizeText(dir)} && npm install\n  npx saktum test -- npx tsx src/index.ts\n` : `  cd ${sanitizeText(dir)}\n  npx saktum test -- uv run server.py\n`)
        + `  Coding agents: AGENTS.md holds the rules they should follow.\n`);
    });

  program.command("lint")
    .description("Static checks on tool registrations in your source code (TypeScript and Python MCP SDKs), with file and line")
    .argument("[paths...]", "files or folders (default: the current folder)")
    .option("--sarif <file>", "also write SARIF 2.1.0 (for GitHub code scanning and editors)")
    .option("--strict", "exit 1 on warnings as well as errors", false)
    .action((paths: string[], o: { sarif?: string; strict: boolean }) => {
      const findings = lintPaths(paths.length ? paths : ["."], process.cwd());
      for (const f of findings) process.stdout.write(`${sanitizeText(f.file)}:${f.line}: ${f.severity} ${f.check}: ${sanitizeText(f.message, 300)}\n    fix: ${sanitizeText(f.fix, 200)}\n`);
      process.stdout.write(findings.length ? `\n${findings.length} finding(s) in tool definitions.\n` : "No problems found in tool definitions (files importing an MCP SDK).\n");
      if (o.sarif) writeFileSync(o.sarif, JSON.stringify(lintSarif(findings, ENGINE_VERSION), null, 2) + "\n");
      exitCode = findings.some((f) => f.severity === "error" || o.strict) ? 1 : 0;
    });

  program.command("call")
    .description("Call one tool and show the result; --save-test turns the call into a test case (save as test)")
    .argument("<tool>", "tool name")
    .argument("<target...>", "https://host/mcp  or  -- node server.js")
    .option("--args <json>", "arguments as JSON", "{}")
    .option("--save-test <id>", "append this call and its result as a test case")
    .option("--tests <file>", "test file to append to", "saktum.tests.yaml")
    .option("--env <KEY=VALUE>", "environment variable for a local server (repeatable)", collect, [] as string[])
    .option("--header <Name: value>", "HTTP header for a remote server (repeatable)", collect, [] as string[])
    .action(async (toolName: string, targetParts: string[], o: { args: string; saveTest?: string; tests: string; env: string[]; header: string[] }) => {
      let args: Record<string, unknown>;
      try { args = JSON.parse(o.args) as Record<string, unknown>; } catch { throw new Error("--args must be JSON, for example '{\"city\":\"Toronto\"}'"); }
      const target = parseTarget(targetParts);
      if (target.kind === "stdio" && o.env.length) target.env = parseEnv(o.env);
      if (target.kind === "streamable-http" && o.header.length) target.headers = parseHeaders(o.header);
      const s = await connect(target);
      let outcome, tool;
      try { tool = (await s.listTools()).find((t) => t.name === toolName); if (!tool) throw new Error(`The server has no tool named ${sanitizeText(toolName, 60)}.`); outcome = await s.callTool(toolName, args); } finally { await s.close(); }
      const text = outcome.kind === "result" ? (outcome.content as { type?: string; text?: string }[] ?? []).filter((c) => c.type === "text").map((c) => c.text ?? "").join("\n") : "";
      const structured = outcome.kind === "result" ? (outcome as { structuredContent?: Record<string, unknown> }).structuredContent : undefined;
      const isError = outcome.kind !== "result" || outcome.isError === true;
      process.stdout.write(`${isError ? "\u2717 error" : "\u2713 ok"} in ${outcome.latencyMs} ms\n${sanitizeText(outcome.kind === "protocol-error" ? `protocol error ${outcome.code}: ${outcome.message}` : text, 2000)}\n${structured ? `structured: ${sanitizeText(JSON.stringify(structured), 1000)}\n` : ""}`);
      if (o.saveTest) {
        const expect: Record<string, unknown> = { isError };
        const firstLine = text.trim().split("\n")[0]!.slice(0, 60).trim();
        if (!isError && firstLine) expect.textContains = firstLine;
        if (!isError && structured) expect.structured = Object.fromEntries(Object.entries(structured).filter(([, v]) => v === null || typeof v !== "object").slice(0, 5));
        if (!isError && (tool as { outputSchema?: unknown }).outputSchema) expect.outputSchema = true;
        expect.latencyMs = { lt: Math.max(2000, outcome.latencyMs * 5) };
        const tc = { id: o.saveTest, tool: toolName, input: args, ...((tool!.annotations as { readOnlyHint?: boolean } | undefined)?.readOnlyHint === true ? {} : { sideEffects: true }), expect };
        writeFileSync(o.tests, await appendTestCase(existsSync(o.tests) ? readFileSync(o.tests, "utf8") : undefined, tc as never));
        process.stdout.write(`Saved test case ${sanitizeText(o.saveTest, 60)} to ${sanitizeText(o.tests)}. Run: saktum test -- <start command>\n`);
      }
    });

  program.command("scan-config")
    .description("Check every MCP server your agents load (Claude Desktop, Claude Code, Cursor, VS Code): total context cost, duplicate tools, unvetted servers")
    .option("--config <file>", "a specific configuration file (repeatable); default: the known locations", collect, [] as string[])
    .option("--yes", "start the servers without asking (they run with the settings in your configuration)", false)
    .option("--turns-per-day <n>", "agent turns a day, for the monthly cost estimate", "50")
    .option("--price-per-mtok <usd>", "your model's price per million input tokens", "3")
    .option("--allowlist <file>", "saktum-allowlist.json: flag servers that are not on it")
    .option("--out <file>", "also write the analysis as JSON (input for saktum fleet)")
    .option("--policy <file>", "your organisation's policy: show which servers violate it")
    .option("--machine <label>", "label for this machine in fleet reports (default: the host name)")
    .action(async (o: { config: string[]; yes: boolean; turnsPerDay: string; pricePerMtok: string; allowlist?: string; out?: string; policy?: string; machine?: string }) => {
      const { homedir } = await import("node:os");
      const locations = o.config.length ? o.config.map((file) => ({ client: "configuration", file })) : configLocations(homedir(), process.cwd(), process.platform, process.env.APPDATA);
      const servers = locations.filter((l) => existsSync(l.file)).flatMap((l) => parseClientConfig(readFileSync(l.file, "utf8"), l.client, l.file)).filter((x) => !x.disabled);
      if (!servers.length) { process.stdout.write("No MCP servers found in the known configuration locations. Point to one with --config <file>.\n"); return; }
      process.stdout.write(`Found ${servers.length} MCP server(s):\n`);
      for (const x of servers) process.stdout.write(`  ${sanitizeText(x.name, 40).padEnd(28)} ${x.client.padEnd(22)} ${x.url ? sanitizeText(x.url, 80) : sanitizeText([x.command, ...(x.args ?? [])].join(" "), 100)}${x.env && Object.keys(x.env).length ? `  (with ${Object.keys(x.env).length} configured setting(s), not shown)` : ""}\n`);
      if (!o.yes) {
        if (!process.stdin.isTTY) { process.stdout.write("\nTo check them, Saktum starts each server with your configured settings. Re-run with --yes to agree.\n"); return; }
        const rl = (await import("node:readline/promises")).createInterface({ input: process.stdin, output: process.stdout });
        const answer = await rl.question("\nStart these servers on this machine to check them (passive: no tool is called)? [y/N] ");
        rl.close();
        if (!/^y(es)?$/i.test(answer.trim())) { process.stdout.write("Nothing was started.\n"); return; }
      }
      const packs = existsSync(bundledPacks) ? loadPackDir(bundledPacks) : loadEmbeddedPacks();
      const scans: ServerScan[] = [];
      for (const x of servers) {
        let tools: ServerScan["tools"] = [];
        try {
          const target = x.url ? { kind: "streamable-http" as const, url: x.url, headers: x.headers } : { kind: "stdio" as const, command: x.command!, args: x.args ?? [], env: x.env };
          const r = await runTrustCheck(target, { packs, onTools: (t) => { tools = t; } });
          const subj = subjectFromResult(r, x.name);
          scans.push({ name: x.name, client: x.client, trustGrade: r.grade ?? null, readinessGrade: r.readiness?.grade ?? null, tools, tokens: r.readiness?.contextTokens ?? 0, fingerprint: r.target.toolsFingerprint,
            target: x.url ? redactUrl(x.url) : redactCommand(x.command, x.args), capabilities: subj.capabilities, lethalTrifecta: subj.lethalTrifecta, failedSeverities: subj.failedSeverities });
        } catch (e) { scans.push({ name: x.name, client: x.client, trustGrade: null, readinessGrade: null, tools: [], tokens: 0, target: x.url ? redactUrl(x.url) : redactCommand(x.command, x.args), error: sanitizeText((e as Error).message, 120) }); }
      }
      const allow = o.allowlist ? new Set((JSON.parse(readFileSync(o.allowlist, "utf8")) as { allowed: { toolsFingerprint?: string }[] }).allowed.map((a) => a.toolsFingerprint).filter((f): f is string => Boolean(f))) : undefined;
      const report = analyseSetup(scans, { turnsPerDay: Number(o.turnsPerDay) || 50, pricePerMTokUsd: Number(o.pricePerMtok) || 3, allowlistFingerprints: allow });
      process.stdout.write("\n" + renderSetup(report));
      if (o.policy) {
        const { policy, allow } = await loadPolicy(o.policy);
        process.stdout.write(`\nPOLICY${policy.name ? ` (${sanitizeText(policy.name, 80)})` : ""}\n`);
        for (const sc of scans.filter((x) => !x.error)) process.stdout.write(renderVerdict(evaluatePolicy({ server: sc.name, trustGrade: sc.trustGrade, readinessGrade: sc.readinessGrade, capabilities: sc.capabilities ?? [], lethalTrifecta: Boolean(sc.lethalTrifecta), contextTokens: sc.tokens, failedSeverities: sc.failedSeverities ?? [], toolsFingerprint: sc.fingerprint }, policy, allow)) + "\n");
      }
      const { hostname } = await import("node:os");
      if (o.out) writeFileSync(o.out, JSON.stringify({ ...report, machine: o.machine ?? hostname() }, null, 2) + "\n");
    });

  program.command("vc").description("W3C Verifiable Credentials made by saktum attest --vc").command("verify")
    .description("Verify a Saktum credential (vc+jwt): signature and issuer did:key")
    .argument("<file>", "the .vc.jwt file")
    .action((f: string) => {
      const r = verifyCredentialJwt(readFileSync(f, "utf8"));
      if (r.valid) { const cs = (r.credential.credentialSubject ?? {}) as Record<string, unknown>; process.stdout.write(`\u2713 Valid credential from ${r.issuer}: ${sanitizeText(String(cs.server ?? ""), 80)} trust ${cs.trustGrade ?? "-"}, readiness ${cs.readinessGrade ?? "-"}.\n`); }
      else { process.stdout.write(`\u2717 Not valid: ${r.reason}\n`); exitCode = 1; }
    });

  const ledger = program.command("ledger").description("The public Saktum trust ledger: signed attestations in an append-only, hash-chained log");
  ledger.command("verify")
    .description("Verify every signature and the hash chain of a ledger (default: the public ledger)")
    .argument("[source]", "ledger file or https URL", DEFAULT_LEDGER_URL)
    .action(async (src: string) => {
      const r = verifyLedger(parseLedger(await readLedgerText(src)));
      process.stdout.write(r.ok ? `\u2713 Ledger verified: ${r.count} entries, every signature valid, chain intact.\n` : `\u2717 Ledger does NOT verify:\n${r.errors.slice(0, 10).map((e) => `  ${sanitizeText(e, 200)}`).join("\n")}\n`);
      exitCode = r.ok ? 0 : 1;
    });
  ledger.command("find")
    .description("Find ledger entries for a server name or tool fingerprint")
    .argument("<query>", "server name (or part of it) or tool fingerprint")
    .option("--ledger <source>", "ledger file or https URL", DEFAULT_LEDGER_URL)
    .action(async (q: string, o: { ledger: string }) => {
      const hits = findInLedger(parseLedger(await readLedgerText(o.ledger)), q);
      if (!hits.length) process.stdout.write("No entries found.\n");
      for (const e of hits) process.stdout.write(`#${e.seq} ${sanitizeText(e.subject.server, 80)} ${sanitizeText(e.subject.version ?? "", 20)}  trust ${e.attestation.claims.trustGrade ?? "-"} \u00b7 readiness ${e.attestation.claims.readinessGrade ?? "-"} \u00b7 ${e.attestation.claims.assuranceLevel} \u00b7 checked ${e.attestation.checkedAt.slice(0, 10)} \u00b7 signed by ${e.signer.slice(0, 24)}\u2026\n`);
    });
  ledger.command("pages")
    .description("Generate public passport pages (one per server) and a gallery from a ledger (used by the ledger bot)")
    .argument("[source]", "ledger file or https URL", DEFAULT_LEDGER_URL)
    .option("--out <dir>", "output folder", "passports")
    .action(async (src: string, o: { out: string }) => {
      const entries = parseLedger(await readLedgerText(src));
      const v = verifyLedger(entries);
      if (!v.ok) throw new Error(`The ledger does not verify: ${v.errors[0]}`);
      const { mkdirSync } = await import("node:fs");
      mkdirSync(o.out, { recursive: true });
      const latest = new Map<string, (typeof entries)[number]>();
      for (const e of entries) latest.set(e.subject.server, e);
      for (const e of latest.values()) writeFileSync(`${o.out}/${passportSlug(e.subject.server)}.html`, renderLedgerPassport(e as never));
      writeFileSync(`${o.out}/index.html`, renderPassportGallery(entries as never));
      process.stdout.write(`Wrote ${latest.size} passport page(s) and the gallery to ${sanitizeText(o.out)}.\n`);
    });
  ledger.command("append")
    .description("Append a signed attestation to a ledger file after verifying it (used by the ledger bot)")
    .argument("<input>", "attestation JSON, or a text file (such as an issue body) containing it")
    .requiredOption("--ledger <file>", "ledger file to append to")
    .option("--issue <n>", "issue number that requested it")
    .action((input: string, o: { ledger: string; issue?: string }) => {
      const att = extractJson(readFileSync(input, "utf8"));
      const { text, entry } = appendToLedger(existsSync(o.ledger) ? readFileSync(o.ledger, "utf8") : "", att, { via: "saktum-index issue", ...(o.issue ? { issue: Number(o.issue) } : {}) });
      writeFileSync(o.ledger, text);
      process.stdout.write(`Recorded entry #${entry.seq} for ${sanitizeText(entry.subject.server, 80)} (signed by ${entry.signer}); entry hash ${entry.entryHash}.\n`);
    });

  const agent = program.command("agent").description("Agent identity: give an agent its own key and a mandate signed by its owner (preview)");
  agent.command("create")
    .description("Create an agent identity (did:key) and a mandate you sign: allowed servers and tools, destructive actions, expiry")
    .requiredOption("--name <name>", "agent name, for example \"Billing assistant\"")
    .option("--purpose <text>", "what the agent is for")
    .option("--owner-name <name>", "your name or team, shown in receipts")
    .option("--allow-server <name>", "server the agent may use (repeatable; default: any)", collect, [] as string[])
    .option("--allow-tool <name>", "tool the agent may use (repeatable; default: any)", collect, [] as string[])
    .option("--allow-destructive", "allow tools declared destructive", false)
    .option("--autonomy <level>", "notify (only alert), propose (suggest, the user approves) or act (within the limits)", "propose")
    .option("--max <tool.arg=value>", "cap a numeric argument, for example checkout.amount=50 (repeatable)", collect, [] as string[])
    .option("--allow-value <tool.arg=v1,v2>", "allowed values for an argument, for example checkout.currency=CAD (repeatable)", collect, [] as string[])
    .option("--daily-calls <n>", "at most this many actions a day")
    .option("--daily-total <arg=max>", "at most this total a day for an argument, for example amount=200")
    .option("--approve-above <arg=value>", "ask the user above this value, for example amount=25")
    .option("--operator <name>", "who operates the agent (disclosure)")
    .option("--incentives <text>", "incentives that could influence the agent, for example sponsored products (disclosure)")
    .option("--data-use <text>", "what the agent does with the user's data (disclosure)")
    .option("--allow-delegation", "allow the agent to hand work to other agents", false)
    .option("--software <name@version>", "the agent software that will act under this mandate")
    .option("--intent <file>", "instructions as JSON: purpose, actions, rules, preferences, substitution, upsell, approvalTriggers, counterparties, dataSharing (see examples/mandate-grocery.json)")
    .option("--expires <date>", "last valid day, YYYY-MM-DD", new Date(Date.now() + 30 * 864e5).toISOString().slice(0, 10))
    .option("--out <file>", "mandate file", "agent-mandate.json")
    .option("--agent-key <file>", "where to keep the agent's own key", "agent-key.json")
    .option("--key <file>", "your (owner's) signing key")
    .action((o: { name: string; purpose?: string; ownerName?: string; allowServer: string[]; allowTool: string[]; allowDestructive: boolean; expires: string; out: string; agentKey: string; key?: string;
      autonomy: string; max: string[]; allowValue: string[]; dailyCalls?: string; dailyTotal?: string; approveAbove?: string; operator?: string; incentives?: string; dataUse?: string; allowDelegation: boolean; intent?: string; software?: string }) => {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(o.expires)) throw new Error("--expires must be YYYY-MM-DD");
      if (!["notify", "propose", "act"].includes(o.autonomy)) throw new Error("--autonomy must be notify, propose or act");
      const ta = (x: string, flag: string) => { const m2 = /^([^.=]+)\.([^=]+)=(.+)$/.exec(x); if (!m2) throw new Error(`${flag} must look like tool.arg=value`); return { tool: m2[1]!, arg: m2[2]!, value: m2[3]! }; };
      const av = (x: string, flag: string) => { const m2 = /^([^=]+)=(-?[\d.]+)$/.exec(x); if (!m2) throw new Error(`${flag} must look like arg=number`); return { arg: m2[1]!, value: Number(m2[2]) }; };
      const constraints = [...o.max.map((x) => { const t = ta(x, "--max"); return { tool: t.tool, arg: t.arg, max: Number(t.value) }; }), ...o.allowValue.map((x) => { const t = ta(x, "--allow-value"); return { tool: t.tool, arg: t.arg, oneOf: t.value.split(",").map((v) => v.trim()) }; })];
      const dt = o.dailyTotal ? av(o.dailyTotal, "--daily-total") : undefined, aa = o.approveAbove ? av(o.approveAbove, "--approve-above") : undefined;
      const agentKey = loadOrCreateKey(o.agentKey);
      const m = createMandate({ agentId: agentKey.kid, agentName: o.name, ownerName: o.ownerName, purpose: o.purpose, servers: o.allowServer, tools: o.allowTool, destructive: o.allowDestructive, expires: o.expires,
        autonomy: o.autonomy as "notify" | "propose" | "act", constraints, limits: { ...(o.dailyCalls ? { callsPerDay: Number(o.dailyCalls) } : {}), ...(dt ? { totalPerDay: { arg: dt.arg, max: dt.value } } : {}) },
        approveAbove: aa, disclosures: { ...(o.operator ? { operator: o.operator } : {}), ...(o.incentives ? { incentives: o.incentives } : {}), ...(o.dataUse ? { dataUse: o.dataUse } : {}) }, delegation: o.allowDelegation,
        ...(o.intent ? (JSON.parse(readFileSync(o.intent, "utf8")) as object) : {}) } as never, loadOrCreateKey(o.key));
      if (o.software) {
        const { signature: _old, ...body } = m as unknown as Record<string, unknown> & { agent: Record<string, unknown> };
        body.agent = { ...(body.agent as Record<string, unknown>), software: o.software };
        Object.assign(m, signDocument(body, loadOrCreateKey(o.key)));
      }
      const valid = compileContract("mandate.schema.json");
      if (!valid(m)) throw new Error(`The mandate is not valid: ${(valid.errors ?? []).map((e) => `${e.instancePath || "/"} ${e.message}`).join("; ")}`);
      writeFileSync(o.out, JSON.stringify(m, null, 2) + "\n");
      for (const line of describeMandate(m as never)) process.stdout.write(`  ${line}\n`);
      process.stdout.write(`Agent ${sanitizeText(o.name, 80)}: ${agentKey.kid}\nMandate signed by ${m.owner.id}, valid until ${o.expires}: ${m.allow.servers ? `servers ${m.allow.servers.join(", ")}` : "any server"}; ${m.allow.tools ? `tools ${m.allow.tools.join(", ")}` : "any tool"}; destructive actions ${m.allow.destructive ? "allowed" : "not allowed"}; autonomy ${m.autonomy}; risk tier ${agentRiskTier(m).tier} (${agentRiskTier(m).note}).\nWrote ${sanitizeText(o.out)} and the agent key ${sanitizeText(o.agentKey)} (keep it private).\n`);
    });
  agent.command("verify")
    .description("Check a mandate: the principal's signature, the operator's countersignature, expiry and revocation")
    .argument("<mandate>", "mandate file")
    .action((f: string) => {
      const m = JSON.parse(readFileSync(f, "utf8")) as Mandate;
      const c = checkMandate(m), op = checkOperator(m as never), rev = revocationOf(m);
      process.stdout.write(c.ok ? `\u2713 Valid mandate for ${sanitizeText(m.agent.name, 80)} (${m.agent.id}), signed by ${m.owner.name ?? m.owner.id}, until ${m.expires}.\n` : `\u2717 ${c.reason}\n`);
      if (op.present) process.stdout.write(op.valid ? `\u2713 Countersigned by the operator ${sanitizeText(op.name ?? "", 80)} (${op.id}).\n` : `\u2717 Operator countersignature: ${op.reason}\n`);
      if (rev) process.stdout.write(`\u2717 Revoked on ${rev.at.slice(0, 10)}${rev.reason ? `: ${sanitizeText(rev.reason, 200)}` : ""}.\n`);
      exitCode = c.ok && (!op.present || op.valid) && !rev ? 0 : 1;
    });
  agent.command("cosign")
    .description("As the operator (who runs the agent and is accountable), countersign a principal's mandate")
    .argument("<mandate>", "mandate file (updated in place)")
    .requiredOption("--name <operator>", "the operator's name")
    .option("--key <path>", "the operator's signing key (created if missing)", "saktum-operator-key.json")
    .action((f: string, o: { name: string; key: string }) => {
      const m = JSON.parse(readFileSync(f, "utf8")) as Mandate;
      if (!checkMandate(m).ok) throw new Error("The mandate is not valid; it cannot be countersigned.");
      const signed = cosignMandate(m, loadOrCreateKey(o.key), o.name);
      writeFileSync(f, JSON.stringify(signed, null, 2) + "\n");
      process.stdout.write(`Countersigned by ${sanitizeText(o.name, 80)} (${loadOrCreateKey(o.key).kid}). Check: npx saktum agent verify ${sanitizeText(f)}\n`);
    });
  agent.command("approve")
    .description("As the mandate's owner, approve exactly one pending action (by its request id), for a limited time, once")
    .argument("<request-id>", "the approval request id from the blocked call (apr_...)")
    .requiredOption("--mandate <file>", "the mandate")
    .option("--key <path>", "the owner's signing key (the one that signed the mandate)")
    .option("--minutes <n>", "how long the approval stays valid", "60")
    .option("--approvals <file>", "approvals file the proxy reads (default ~/.saktum/approvals.json)")
    .action((rid: string, o: { mandate: string; key?: string; minutes: string; approvals?: string }) => {
      const m = JSON.parse(readFileSync(o.mandate, "utf8")) as Mandate;
      const a = approveAction(m, rid, loadOrCreateKey(o.key), Number(o.minutes), o.approvals);
      process.stdout.write(`Approved ${sanitizeText(rid, 40)} for ${sanitizeText(m.agent.name, 80)}, valid until ${a.expires}, once. The agent can now retry exactly that action.\n`);
    });
  agent.command("revoke")
    .description("Stop an agent now: every Saktum proxy on this machine refuses calls under this mandate")
    .argument("<mandate>", "mandate file")
    .option("--reason <text>", "why")
    .action((f: string, o: { reason?: string }) => {
      const m = JSON.parse(readFileSync(f, "utf8")) as Mandate;
      const r = revokeMandate(m, o.reason);
      process.stdout.write(`Revoked the mandate for ${sanitizeText(m.agent.name, 80)} at ${r.at}. Its calls are now refused (code: revoked).\n`);
    });

  program.command("proxy")
    .description("Put Saktum between an agent and a local MCP server: signed receipts for every tool call, and the agent's mandate observed or enforced (preview)")
    .argument("<command...>", "the server command, after --")
    .option("--mandate <file>", "the agent's mandate (from saktum agent create)")
    .option("--agent-key <file>", "the agent's key, which signs receipts", "agent-key.json")
    .option("--enforce", "block calls outside the mandate (default: observe and record only)", false)
    .option("--receipts <file>", "receipt log (append-only, hash-chained)")
    .option("--revocations <file>", "revocation list to honour (default ~/.saktum/revocations.json)")
    .option("--approvals <file>", "signed approvals to honour (default ~/.saktum/approvals.json)")
    .option("--credential <file>", "the agent's credential: its accountability chain is verified on every call")
    .option("--revoked-credentials <file>", "JSON list of revoked credential ids")
    .option("--agreement <file>", "the signed agreement with the provider: calls outside it are refused and every call is metered")
    .option("--wallet <file>", "prepaid token wallet charged per call under the agreement")
    .action(async (parts: string[], o: { mandate?: string; agentKey: string; enforce: boolean; receipts?: string; revocations?: string; approvals?: string; credential?: string; revokedCredentials?: string; agreement?: string; wallet?: string }) => {
      const { homedir } = await import("node:os");
      const { join } = await import("node:path");
      let mandate: Mandate | undefined;
      if (o.mandate) { mandate = JSON.parse(readFileSync(o.mandate, "utf8")) as Mandate; const c = checkMandate(mandate); if (!c.ok) throw new Error(`Mandate refused: ${c.reason}`); }
      const agentKey = loadOrCreateKey(o.agentKey);
      if (mandate && agentKey.kid !== mandate.agent.id) throw new Error("The agent key does not match the mandate's agent.");
      const { runProxy } = await import("./proxy.js");
      exitCode = await runProxy({ command: parts[0]!, args: parts.slice(1), receiptsPath: o.receipts ?? join(homedir(), ".saktum", "receipts.jsonl"), agentKey, mandate, enforce: o.enforce, ...(o.revocations ? { revocationsPath: o.revocations } : {}), ...(o.approvals ? { approvalsPath: o.approvals } : {}),
        ...(o.credential ? { credential: JSON.parse(readFileSync(o.credential, "utf8")) as Credential } : {}), ...(o.revokedCredentials ? { revokedCredentials: JSON.parse(readFileSync(o.revokedCredentials, "utf8")) as string[] } : {}),
        ...(o.agreement ? { agreement: JSON.parse(readFileSync(o.agreement, "utf8")) as Agreement } : {}), ...(o.wallet ? { walletPath: o.wallet } : {}), log: (m) => process.stderr.write(`saktum: ${m}\n`) });
    });

  const receipts = program.command("receipts").description("Signed receipts of agent tool calls (from saktum proxy)");
  receipts.command("verify")
    .description("Verify every receipt's signature and the hash chain")
    .argument("[file]", "receipt log")
    .action(async (f?: string) => {
      const { homedir } = await import("node:os"); const { join } = await import("node:path");
      const r = verifyReceiptLog(parseReceiptLog(readFileSync(f ?? join(homedir(), ".saktum", "receipts.jsonl"), "utf8")));
      process.stdout.write(r.ok ? `\u2713 ${r.count} receipts verified: every signature valid, chain intact.\n` : `\u2717 Receipts do NOT verify:\n${r.errors.slice(0, 10).map((e) => `  ${e}`).join("\n")}\n`);
      exitCode = r.ok ? 0 : 1;
    });
  receipts.command("export")
    .description("Export receipts as OpenTelemetry traces (OTLP/JSON) for your observability or security tools")
    .argument("[file]", "receipt log")
    .option("--otel <file>", "write OTLP/JSON traces to this file", "saktum-receipts.otlp.json")
    .option("--endpoint <url>", "also send them to an OpenTelemetry collector (OTLP/HTTP), for example http://localhost:4318")
    .action(async (f: string | undefined, o: { otel: string; endpoint?: string }) => {
      const { homedir } = await import("node:os"); const { join } = await import("node:path");
      const entries = parseReceiptLog(readFileSync(f ?? join(homedir(), ".saktum", "receipts.jsonl"), "utf8"));
      const v = verifyReceiptLog(entries);
      const otlp = receiptsToOtlp(entries, { verified: v.ok, version: ENGINE_VERSION });
      writeFileSync(o.otel, JSON.stringify(otlp, null, 2) + "\n");
      process.stdout.write(`Wrote ${entries.length} span(s) to ${sanitizeText(o.otel)} (receipts ${v.ok ? "verified" : "DO NOT verify"}).\n`);
      if (o.endpoint) {
        const url = o.endpoint.replace(/\/+$/, "") + "/v1/traces";
        const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(otlp) });
        process.stdout.write(`Sent to ${sanitizeText(url)}: HTTP ${res.status}\n`);
        if (!res.ok) exitCode = 1;
      }
    });
  receipts.command("summary")
    .description("The path, not the answer: which tools were called, how often, in what order, retries, denials, destructive actions")
    .argument("[file]", "receipt log")
    .option("--json", "print JSON", false)
    .action(async (f: string | undefined, o: { json: boolean }) => {
      const { homedir } = await import("node:os"); const { join } = await import("node:path");
      const entries = parseReceiptLog(readFileSync(f ?? join(homedir(), ".saktum", "receipts.jsonl"), "utf8"));
      const v = verifyReceiptLog(entries), s = summariseReceipts(entries);
      if (o.json) { process.stdout.write(JSON.stringify({ verified: v.ok, ...s }, null, 2) + "\n"); return; }
      process.stdout.write(`${s.calls} tool calls by ${s.agents.length} agent(s) on ${s.servers.join(", ") || "-"} \u00b7 receipts ${v.ok ? "verified" : "DO NOT verify"}\n`
        + `  denied ${s.denied} \u00b7 errors ${s.errors} \u00b7 destructive actions allowed ${s.destructiveAllowed}${s.medianLatencyMs !== undefined ? ` \u00b7 median ${s.medianLatencyMs} ms` : ""}\n`
        + s.byTool.map((t) => `  ${t.tool.padEnd(30)} ${t.count}`).join("\n") + "\n"
        + (s.repeatedIdenticalCalls.length ? `  Repeated identical calls (possible retry storms): ${s.repeatedIdenticalCalls.map((r) => `${r.call} \u00d7${r.times}`).join(", ")}\n` : "")
        + `  Order: ${s.order.join(" \u2192 ")}\n`);
    });

  program.command("passport")
    .description("A visual passport: for an MCP server (checks it first) or, with --agent, for an agent (mandate and receipt timeline)")
    .argument("[target...]", "the server: https URL, or -- <command that starts it>")
    .option("--agent <mandate>", "make an Agent Passport from this mandate instead")
    .option("--receipts <file>", "with --agent: the agent's receipt log, for the timeline")
    .option("--out <file>", "HTML file", "saktum-passport.html")
    .option("--key <path>", "signing key for the server's result")
    .option("--env <KEY=VALUE>", "environment variable for a local server (repeatable)", collect, [] as string[])
    .option("--header <Name: value>", "HTTP header for a remote server (repeatable)", collect, [] as string[])
    .action(async (parts: string[], o: { agent?: string; receipts?: string; out: string; key?: string; env: string[]; header: string[] }) => {
      if (o.agent) {
        const m = JSON.parse(readFileSync(o.agent, "utf8")) as Mandate;
        const valid = checkMandate(m);
        let receipts;
        if (o.receipts) {
          const entries = parseReceiptLog(readFileSync(o.receipts, "utf8"));
          const counts = new Map<string, number>();
          for (const e of entries) { const k = `${e.receipt.envelope.tool}|${e.receipt.envelope.argumentsHash}`; counts.set(k, (counts.get(k) ?? 0) + 1); }
          receipts = { verified: verifyReceiptLog(entries).ok, summary: summariseReceipts(entries),
            timeline: entries.map((e) => ({ tool: e.receipt.envelope.tool, outcome: e.receipt.outcome, status: e.result.status, repeated: (counts.get(`${e.receipt.envelope.tool}|${e.receipt.envelope.argumentsHash}`) ?? 0) >= 3 })) };
        }
        const rev = revocationOf(m), op = checkOperator(m as never);
        const ts = o.receipts ? trustStatement(parseReceiptLog(readFileSync(o.receipts, "utf8")), receipts?.verified ?? false) : undefined;
        writeFileSync(o.out, renderAgentPassport(m, rev ? { ok: false, reason: `Revoked on ${rev.at.slice(0, 10)}${rev.reason ? `: ${rev.reason}` : ""}` } : valid.ok ? { ok: true } : { ok: false, reason: valid.reason }, receipts, agentRiskTier(m), describeMandate(m as never),
          { operator: op.present && op.valid ? `${op.name} (${op.id})` : undefined, track: ts?.lines,
            maturity: agentMaturity(m as never, { entries: o.receipts ? parseReceiptLog(readFileSync(o.receipts, "utf8")) : [], verified: receipts?.verified, revoked: Boolean(rev) }) }));
        process.stdout.write(`Wrote the Agent Passport for ${sanitizeText(m.agent.name, 80)} to ${sanitizeText(o.out)}. Open it in a browser.\n`);
        return;
      }
      if (!parts.length) throw new Error("Give a server (an https URL, or -- <command>), or use --agent <mandate>.");
      const target = parseTarget(parts);
      if (target.kind === "stdio" && o.env.length) target.env = parseEnv(o.env);
      if (target.kind === "streamable-http" && o.header.length) target.headers = parseHeaders(o.header);
      const packs = existsSync(bundledPacks) ? loadPackDir(bundledPacks) : loadEmbeddedPacks();
      let tools: never[] = [];
      const r = await runTrustCheck(target, { packs, onTools: (t) => { tools = t as never[]; } });
      const signed = signDocument(r, loadOrCreateKey(o.key)) as Result & { signature: { kid: string } };
      writeFileSync(o.out, renderServerPassport(signed, tools));
      writeFileSync(o.out.replace(/\.html?$/i, "") + ".json", JSON.stringify(signed, null, 2));
      process.stdout.write(`Wrote the MCP Server Passport for ${sanitizeText(String(r.target.serverInfo?.["name"] ?? "server"), 80)} to ${sanitizeText(o.out)} (trust ${r.grade ?? "-"}, readiness ${r.readiness?.grade ?? "-"}), and its signed result beside it.\n`);
    });

  program.command("watch")
    .description("Continuous monitoring: re-check every server on an allowlist and alert on changed tools, grade drops or unreachable servers")
    .argument("<allowlist>", "saktum-allowlist.json (from saktum allowlist)")
    .option("--out <file>", "write the results as JSON")
    .option("--webhook <url>", "POST a summary to this URL when something changed (for example a chat or incident webhook)")
    .action(async (file: string, o: { out?: string; webhook?: string }) => {
      const list = JSON.parse(readFileSync(file, "utf8")) as { allowed: WatchEntry[] };
      const packs = existsSync(bundledPacks) ? loadPackDir(bundledPacks) : loadEmbeddedPacks();
      const r = await watchAllowlist(list.allowed ?? [], packs);
      const mark = { unchanged: "\u2713", changed: "\u2717", degraded: "!", unreachable: "?" };
      for (const f of r.findings) process.stdout.write(`${mark[f.status]} ${sanitizeText(f.server, 60).padEnd(32)} ${f.status}${f.details.length ? `: ${sanitizeText(f.details.join("; "), 300)}` : ""}\n`);
      process.stdout.write(`\n${r.findings.length} server(s) checked; ${r.alerts} need attention.\n`);
      if (o.out) writeFileSync(o.out, JSON.stringify(r, null, 2) + "\n");
      if (o.webhook && r.alerts) {
        const text = `Saktum watch: ${r.alerts} MCP server(s) need attention. ${r.findings.filter((f) => f.status !== "unchanged").map((f) => `${f.server}: ${f.details.join("; ")}`).join(" | ")}`.slice(0, 3000);
        try { const res = await fetch(o.webhook, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text, findings: r.findings }) }); process.stdout.write(`Webhook: HTTP ${res.status}\n`); } catch (e) { process.stderr.write(`Webhook failed: ${sanitizeText((e as Error).message, 200)}\n`); }
      }
      exitCode = r.alerts ? 1 : 0;
    });

  program.command("roi")
    .description("What tool definitions cost your agents a year, and what Saktum's fixes and passports can save (assumptions shown)")
    .option("--tokens-per-turn <n>", "tokens of tool definitions per turn (from saktum check or scan-config)", "5047")
    .option("--turns-per-day <n>", "agent turns a day, per agent", String(ROI_DEFAULTS.turnsPerDay))
    .option("--agents <n>", "number of agents", String(ROI_DEFAULTS.agents))
    .option("--price-per-mtok <usd>", "price per million input tokens", String(ROI_DEFAULTS.pricePerMTok))
    .option("--waste <share>", "share removable by fixes (0 to 1)", String(ROI_DEFAULTS.wasteShare))
    .option("--vendor-reviews <n>", "AI vendor or tool security reviews a year", "0")
    .option("--hours-per-review <n>", "hours per review", String(ROI_DEFAULTS.hoursPerReview))
    .option("--hourly-cost <usd>", "loaded cost per hour", String(ROI_DEFAULTS.hourlyCost))
    .action((o: Record<string, string>) => {
      const n = (k: string) => Number(o[k]);
      const r = roiEstimate({ tokensPerTurn: n("tokensPerTurn"), turnsPerDay: n("turnsPerDay"), agents: n("agents"), pricePerMTok: n("pricePerMtok"), wasteShare: n("waste"), vendorReviews: n("vendorReviews"), hoursPerReview: n("hoursPerReview"), hourlyCost: n("hourlyCost"), reviewTimeSaved: ROI_DEFAULTS.reviewTimeSaved });
      const usd = (x: number) => `$${x.toLocaleString("en-US")}`;
      process.stdout.write(`Tool definitions cost about ${usd(r.annualToolCost)} a year.\nFixes could save about ${usd(r.tokenSavings)} a year${r.reviewSavings ? `; passports could save about ${usd(r.reviewSavings)} of review effort` : ""}.\nTotal: about ${usd(r.totalSavings)} a year.\nAssumptions: ${r.assumptions}.\n`);
    });

  program.command("assess")
    .description("An executive MCP Trust Assessment for an organisation, from a fleet inventory and agent receipts (pilot deliverable)")
    .requiredOption("--fleet <file>", "inventory JSON from saktum fleet --out")
    .option("--org <name>", "organisation name", "Your organisation")
    .option("--receipts <file>", "an agent's receipt log (repeatable)", collect, [] as string[])
    .option("--out <file>", "HTML report (print to PDF from a browser)", "saktum-assessment.html")
    .option("--agents <n>", "agents in production, for the business case", "10")
    .option("--turns-per-day <n>", "turns a day per agent", "1000")
    .option("--price-per-mtok <usd>", "price per million input tokens", "3")
    .option("--vendor-reviews <n>", "AI vendor or tool security reviews a year", "20")
    .action((o: { fleet: string; org: string; receipts: string[]; out: string; agents: string; turnsPerDay: string; pricePerMtok: string; vendorReviews: string }) => {
      const fleet = JSON.parse(readFileSync(o.fleet, "utf8"));
      const rec = o.receipts.map((f) => { const e = parseReceiptLog(readFileSync(f, "utf8")); return { agent: e[0]?.receipt.envelope.caller.agent?.slice(0, 32) ?? f, summary: summariseReceipts(e), verified: verifyReceiptLog(e).ok }; });
      const distinctTokens = (fleet.servers ?? []).reduce((a: number, x: { tokens?: number }) => a + (x.tokens ?? 0), 0);
      const roi = roiEstimate({ ...ROI_DEFAULTS, tokensPerTurn: distinctTokens, agents: Number(o.agents), turnsPerDay: Number(o.turnsPerDay), pricePerMTok: Number(o.pricePerMtok), vendorReviews: Number(o.vendorReviews) });
      writeFileSync(o.out, renderAssessment(o.org, fleet, rec, roi, crosswalk().map((x) => ({ name: x.name, summary: coverageSummary(x) })), DISCLAIMER));
      process.stdout.write(`Wrote the MCP Trust Assessment for ${sanitizeText(o.org, 80)} to ${sanitizeText(o.out)}: ${fleet.servers?.length ?? 0} servers, ${fleet.nonCompliant ?? 0} violating policy. Open it in a browser and print to PDF.\n`);
    });

  program.command("fleet")
    .description("Merge scan-config results from many machines into one organisation inventory, checked against your policy")
    .argument("<setups...>", "JSON files written by saktum scan-config --out")
    .option("--policy <file>", "your organisation's policy")
    .option("--out <file>", "inventory as JSON")
    .option("--html <file>", "inventory as an HTML page")
    .action(async (files: string[], o: { policy?: string; out?: string; html?: string }) => {
      const setups = files.map((f) => { const j = JSON.parse(readFileSync(f, "utf8")) as { machine?: string; servers: never[] }; return { machine: j.machine ?? f, servers: j.servers ?? [] }; });
      const pol = o.policy ? await loadPolicy(o.policy) : undefined;
      const fleet = buildFleet(setups, pol?.policy, pol?.allow);
      process.stdout.write(renderFleet(fleet));
      if (o.out) writeFileSync(o.out, JSON.stringify(fleet, null, 2) + "\n");
      if (o.html) writeFileSync(o.html, fleetHtml(fleet));
      exitCode = fleet.nonCompliant ? 1 : 0;
    });

  program.command("bindings")
    .description("How Saktum reads a server's tools (action class, what each argument means), and the _meta block to declare them")
    .argument("<target...>", "https://host/mcp  or  -- node server.js")
    .option("--env <KEY=VALUE>", "environment variable for a local server (repeatable)", collect, [] as string[])
    .action(async (parts: string[], o: { env: string[] }) => {
      const target = parseTarget(parts);
      if (target.kind === "stdio" && o.env.length) target.env = parseEnv(o.env);
      const s2 = await connect(target);
      let tools: { name: string; description?: string; inputSchema?: unknown; _meta?: Record<string, unknown> }[] = [];
      try { tools = (await s2.listTools()) as never; } finally { await s2.close(); }
      for (const t of tools) {
        const a = actionClass(t), b = bindingsFor(t);
        process.stdout.write(`${sanitizeText(t.name, 60).padEnd(28)} ${a.cls.padEnd(12)} ${b.basis === "declared" ? "declared" : "inferred"}: ${Object.entries(b.bindings).map(([k, f]) => `${k} \u2192 ${f}`).join(", ") || "(no domain arguments)"}\n`);
      }
      const undeclared = tools.filter((t) => !t._meta?.["io.saktum/bindings"]);
      if (undeclared.length) {
        process.stdout.write(`\nTo declare them, add to each tool's definition (MCP tools accept _meta):\n`);
        for (const t of undeclared.slice(0, 5)) process.stdout.write(`  ${t.name}: _meta: ${JSON.stringify({ "io.saktum/action": actionClass(t).cls, "io.saktum/bindings": bindingsFor(t).bindings })}\n`);
      }
    });

  const org = program.command("org").description("Organisations: the root of every accountability chain");
  org.command("init").description("Create your organisation's root identity credential")
    .requiredOption("--name <name>", "organisation name").option("--domain <domain>", "the organisation's domain")
    .option("--key <path>", "the organisation's signing key (created if missing)", "saktum-org-key.json").option("--expires <date>", "YYYY-MM-DD", new Date(Date.now() + 365 * 864e5).toISOString().slice(0, 10))
    .option("--out <file>", "credential file", "org-credential.json")
    .action((o: { name: string; domain?: string; key: string; expires: string; out: string }) => {
      const c = organisationRoot({ name: o.name, domain: o.domain, expires: o.expires }, loadOrCreateKey(o.key));
      writeFileSync(o.out, JSON.stringify(c, null, 2) + "\n");
      process.stdout.write(`Organisation ${sanitizeText(o.name, 80)}: ${c.subject.id}. Root credential ${c.id} in ${sanitizeText(o.out)}.\n`);
    });
  const identity = program.command("identity").description("Identity chains: organisation -> people -> agents");
  identity.command("issue").description("Issue a credential to a person or an agent, from your own credential")
    .requiredOption("--from <credential>", "your credential (the organisation's, or one it issued to you)").requiredOption("--key <path>", "your signing key")
    .requiredOption("--type <type>", "member or agent").requiredOption("--name <name>", "the subject's name")
    .option("--subject-key <path>", "the subject's key file (its id is used)").option("--subject <did>", "the subject's did:key")
    .option("--role <role>", "role, for a member").option("--expires <date>", "YYYY-MM-DD", new Date(Date.now() + 180 * 864e5).toISOString().slice(0, 10)).option("--out <file>", "credential file", "credential.json")
    .action((o: { from: string; key: string; type: string; name: string; subjectKey?: string; subject?: string; role?: string; expires: string; out: string }) => {
      const subject = o.subject ?? (o.subjectKey ? loadOrCreateKey(o.subjectKey).kid : undefined);
      if (!subject) throw new Error("Give --subject <did:key> or --subject-key <file>.");
      const c = issueCredential(JSON.parse(readFileSync(o.from, "utf8")) as Credential, loadOrCreateKey(o.key), { type: o.type as "member" | "agent", id: subject, name: o.name, role: o.role, expires: o.expires });
      writeFileSync(o.out, JSON.stringify(c, null, 2) + "\n");
      process.stdout.write(`Issued ${c.id} to ${sanitizeText(o.name, 80)} (${o.type}). Chain: ${verifyChain(c).path.join(" -> ")}\n`);
    });
  identity.command("verify").description("Walk a credential's chain to its organisation").argument("<credential>")
    .option("--revoked <file>", "JSON list of revoked credential ids")
    .action((f: string, o: { revoked?: string }) => {
      const v = verifyChain(JSON.parse(readFileSync(f, "utf8")) as Credential, { revoked: o.revoked ? JSON.parse(readFileSync(o.revoked, "utf8")) : [] });
      process.stdout.write(v.valid ? `\u2713 ${v.path.join(" -> ")}: accountable organisation ${v.organisation}\n` : `\u2717 ${v.reason}\n`);
      exitCode = v.valid ? 0 : 1;
    });
  identity.command("orphans").description("Agents whose accountability chain is broken (expired, revoked or invalid)").argument("<credentials...>")
    .option("--revoked <file>", "JSON list of revoked credential ids")
    .action((fs: string[], o: { revoked?: string }) => {
      const orphans = findOrphans(fs.map((f) => JSON.parse(readFileSync(f, "utf8")) as Credential), { revoked: o.revoked ? JSON.parse(readFileSync(o.revoked, "utf8")) : [] });
      for (const x of orphans) process.stdout.write(`\u2717 ${sanitizeText(x.agent, 80)} (${x.id}): ${x.reason}\n`);
      process.stdout.write(`${orphans.length} orphaned agent(s).\n`);
      exitCode = orphans.length ? 1 : 0;
    });
  const manifest = program.command("manifest").description("What a server offers, signed by its publisher");
  manifest.command("create").description("Build and sign a manifest from a server's tools (with its grades and risk tier)")
    .argument("<target...>", "https://host/mcp  or  -- node server.js").requiredOption("--publisher <name>", "publishing organisation").option("--domain <domain>")
    .option("--key <path>", "the publisher's signing key", "saktum-publisher-key.json").option("--per-call <tokens>", "default tokens per call", "1")
    .option("--rate <tool=tokens>", "tokens for one tool (repeatable)", collect, [] as string[]).option("--out <file>", "manifest file", "saktum-manifest.json")
    .action(async (parts: string[], o: { publisher: string; domain?: string; key: string; perCall: string; rate: string[]; out: string }) => {
      const target = parseTarget(parts);
      const packs = existsSync(bundledPacks) ? loadPackDir(bundledPacks) : loadEmbeddedPacks();
      let tools: never[] = [];
      const r = await runTrustCheck(target, { packs, onTools: (t) => { tools = t as never[]; } });
      const perTool = Object.fromEntries(o.rate.map((x) => { const [t, n] = x.split("="); return [t!, Number(n)]; }));
      const m = buildManifest({ publisher: { name: o.publisher, ...(o.domain ? { domain: o.domain } : {}) }, server: { name: String(r.target.serverInfo?.["name"] ?? "server"), version: String(r.target.serverInfo?.["version"] ?? ""), toolsFingerprint: r.target.toolsFingerprint },
        tools, rates: { perCall: Number(o.perCall), ...(o.rate.length ? { perTool } : {}) }, quality: { trustGrade: r.grade ?? null, readinessGrade: r.readiness?.grade ?? null, riskTier: r.riskTier?.tier } }, loadOrCreateKey(o.key));
      writeFileSync(o.out, JSON.stringify(m, null, 2) + "\n");
      process.stdout.write(`Manifest ${m.id} for ${sanitizeText(m.server.name, 80)}: intents ${m.intents.join(", ")}; trust ${r.grade ?? "-"}, readiness ${r.readiness?.grade ?? "-"}, risk ${r.riskTier?.tier ?? "-"}.\n`);
    });
  const catalog = program.command("catalog").description("A catalogue of signed manifests, searchable by intent");
  catalog.command("add").argument("<manifest>").option("--catalog <file>", "catalogue file", "saktum-catalog.json")
    .action((f: string, o: { catalog: string }) => {
      const m = JSON.parse(readFileSync(f, "utf8")) as Manifest;
      if (!verifyDocument(m as never).valid) throw new Error("The manifest's signature is not valid.");
      const c: Manifest[] = existsSync(o.catalog) ? JSON.parse(readFileSync(o.catalog, "utf8")) : [];
      writeFileSync(o.catalog, JSON.stringify([...c.filter((x) => x.server.name !== m.server.name || x.publisher.id !== m.publisher.id), m], null, 2) + "\n");
      process.stdout.write(`Added ${sanitizeText(m.server.name, 80)} by ${sanitizeText(m.publisher.name, 80)} to ${sanitizeText(o.catalog)}.\n`);
    });
  catalog.command("search").argument("<query...>").option("--catalog <file>", "catalogue file", "saktum-catalog.json").option("--max-risk <tier>", "only servers at or below this risk tier")
    .action((q: string[], o: { catalog: string; maxRisk?: string }) => {
      const res = searchCatalogue(JSON.parse(readFileSync(o.catalog, "utf8")) as Manifest[], q.join(" "), { maxRisk: o.maxRisk });
      for (const r of res.slice(0, 10)) process.stdout.write(`${String(r.score).padStart(3)}  ${sanitizeText(r.manifest.server.name, 40).padEnd(24)} ${sanitizeText(r.manifest.publisher.name, 40).padEnd(20)} trust ${r.manifest.quality?.trustGrade ?? "-"} \u00b7 risk ${r.manifest.quality?.riskTier ?? "-"} \u00b7 ${r.matched.join(", ")}\n`);
      if (!res.length) process.stdout.write("No match.\n");
    });
  const agreement = program.command("agreement").description("Agreements between providers and invokers (smart contracts as signed documents)");
  agreement.command("draft").description("As the provider, draft and sign an agreement from the default template")
    .requiredOption("--manifest <file>").requiredOption("--invoker-name <name>").requiredOption("--invoker <did>", "the invoker organisation's id").requiredOption("--purpose <text>")
    .option("--tools <list>", "comma-separated tools in scope").option("--tokens-per-month <n>").option("--term <text>", "a specific term (repeatable)", collect, [] as string[])
    .option("--valid-until <date>", "YYYY-MM-DD", new Date(Date.now() + 365 * 864e5).toISOString().slice(0, 10)).option("--key <path>", "the provider's key", "saktum-publisher-key.json").option("--out <file>", "agreement file", "saktum-agreement.json")
    .action((o: { manifest: string; invokerName: string; invoker: string; purpose: string; tools?: string; tokensPerMonth?: string; term: string[]; validUntil: string; key: string; out: string }) => {
      const a = draftAgreement({ manifest: JSON.parse(readFileSync(o.manifest, "utf8")), invoker: { id: o.invoker, name: o.invokerName }, purpose: o.purpose, tools: o.tools?.split(",").map((x) => x.trim()), tokensPerMonth: o.tokensPerMonth ? Number(o.tokensPerMonth) : undefined, specificTerms: o.term, validUntil: o.validUntil }, loadOrCreateKey(o.key));
      writeFileSync(o.out, JSON.stringify(a, null, 2) + "\n");
      process.stdout.write(`Drafted ${a.id} (${a.terms.length} default terms, ${a.specificTerms?.length ?? 0} specific), signed by the provider. The invoker accepts with: npx saktum agreement accept ${sanitizeText(o.out)} --key <invoker-key>\n`);
    });
  agreement.command("accept").argument("<agreement>").requiredOption("--key <path>", "the invoker's key")
    .action((f: string, o: { key: string }) => { const a = acceptAgreement(JSON.parse(readFileSync(f, "utf8")), loadOrCreateKey(o.key)); writeFileSync(f, JSON.stringify(a, null, 2) + "\n"); process.stdout.write(`Accepted ${a.id}: signed by both parties.\n`); });
  agreement.command("verify").argument("<agreement>")
    .action((f: string) => { const a = JSON.parse(readFileSync(f, "utf8")) as Agreement; const v = verifyAgreement(a); process.stdout.write(v.valid ? `\u2713 ${a.id}: ${sanitizeText(a.provider.name, 80)} and ${sanitizeText(a.invoker.name, 80)}, until ${a.validUntil}.\n` : `\u2717 ${v.reason}\n`); exitCode = v.valid ? 0 : 1; });
  const wallet = program.command("wallet").description("Prepaid tokens (bought outside Saktum; no money is handled here)");
  wallet.command("topup").requiredOption("--account <id>").requiredOption("--tokens <n>").option("--wallet <file>", "wallet file", "saktum-wallet.json")
    .action((o: { account: string; tokens: string; wallet: string }) => { process.stdout.write(`Balance of ${sanitizeText(o.account, 80)}: ${topUp(o.wallet, o.account, Number(o.tokens))} tokens.\n`); });
  wallet.command("balance").requiredOption("--account <id>").option("--wallet <file>", "wallet file", "saktum-wallet.json")
    .action((o: { account: string; wallet: string }) => { process.stdout.write(`${walletBalance(o.wallet, o.account)} tokens\n`); });
  program.command("usage").description("A usage statement for an agreement, from the receipts (optionally signed)")
    .requiredOption("--agreement <file>").argument("[receipts]").option("--key <path>", "sign the statement with this key").option("--out <file>")
    .action(async (f: string | undefined, o: { agreement: string; key?: string; out?: string }) => {
      const { homedir } = await import("node:os"); const { join } = await import("node:path");
      const st = usageStatement(parseReceiptLog(readFileSync(f ?? join(homedir(), ".saktum", "receipts.jsonl"), "utf8")), JSON.parse(readFileSync(o.agreement, "utf8")), o.key ? loadOrCreateKey(o.key) : undefined) as { lines: { tool: string; calls: number; tokens: number }[]; totalTokens: number };
      for (const l of st.lines) process.stdout.write(`${sanitizeText(l.tool, 60).padEnd(24)} ${String(l.calls).padStart(5)} calls ${String(l.tokens).padStart(7)} tokens\n`);
      process.stdout.write(`Total: ${st.totalTokens} tokens\n`);
      if (o.out) writeFileSync(o.out, JSON.stringify(st, null, 2) + "\n");
    });
  program.command("kpi").description("KPIs over receipts: calls, outcomes, approvals, tokens, latency, by tool").argument("[receipts]")
    .option("--tool <name>").option("--agent <did>").option("--since <date>")
    .action(async (f: string | undefined, o: { tool?: string; agent?: string; since?: string }) => {
      const { homedir } = await import("node:os"); const { join } = await import("node:path");
      const k = kpis(parseReceiptLog(readFileSync(f ?? join(homedir(), ".saktum", "receipts.jsonl"), "utf8")), o);
      process.stdout.write(`Calls ${k.calls} \u00b7 allowed ${k.allowed} \u00b7 blocked ${k.blocked} \u00b7 approved ${k.approvals} \u00b7 tokens ${k.tokens} \u00b7 latency p50 ${k.latencyP50 ?? "-"} ms, p95 ${k.latencyP95 ?? "-"} ms\n`);
      process.stdout.write(`By outcome: ${k.byOutcome.map(([c, n]) => `${c} ${n}`).join(", ")}\nBy tool: ${k.byTool.map(([c, n]) => `${c} ${n}`).join(", ")}\n`);
    });
  program.command("bounty").description("Bounties (contract only for now)").command("validate").argument("<file>")
    .action((f: string) => { const ok = compileContract("bounty.schema.json")(JSON.parse(readFileSync(f, "utf8"))); process.stdout.write(ok ? "\u2713 Valid bounty document.\n" : "\u2717 Not a valid bounty document.\n"); exitCode = ok ? 0 : 1; });

  program.command("evidence")
    .description("Saktum's evidence mapped to the frameworks you're held to (supports evidence; never a compliance claim)")
    .option("--framework <id>", "all, eu-ai-act, nist-ai-rmf, iso-42001, owasp-llm, dora-nis2, gdpr-dpdp", "all")
    .option("--markdown", "print as Markdown tables", false)
    .action((o: { framework: string; markdown: boolean }) => {
      const fs2 = crosswalk(o.framework);
      if (!fs2.length) throw new Error("Unknown framework. Use all, eu-ai-act, nist-ai-rmf, iso-42001, owasp-llm, dora-nis2 or gdpr-dpdp.");
      const mark = { covered: "\u2713 covered", partial: "\u25D0 partly", gap: "\u2013 not covered" };
      for (const f of fs2) {
        const sm = coverageSummary(f);
        if (o.markdown) {
          process.stdout.write(`## ${f.name}\n\n${f.note}\n\n| Ref | Obligation | Coverage | Saktum evidence | Commands |\n| --- | --- | --- | --- | --- |\n`);
          for (const i of f.items) process.stdout.write(`| ${i.ref} | ${i.obligation} | ${mark[i.coverage]} | ${i.evidence} | ${i.commands.map((c) => "`" + c + "`").join(", ")} |\n`);
          process.stdout.write("\n");
        } else {
          process.stdout.write(`\n${f.name}: ${sm.covered} covered, ${sm.partial} partly, ${sm.gap} not covered\n  ${f.note}\n`);
          for (const i of f.items) process.stdout.write(`  ${mark[i.coverage].padEnd(15)} ${i.ref.padEnd(18)} ${i.obligation}\n${" ".repeat(36)}${i.evidence}${i.commands.length ? ` (${i.commands.join("; ")})` : ""}\n`);
        }
      }
      process.stdout.write(`\n${DISCLAIMER}\n`);
    });

  program.command("demo")
    .description("See permissions, autonomy, risk and receipts in 60 seconds: one shopping agent under three mandates")
    .option("--out <dir>", "folder for the demo's mandates, receipts and passports", "saktum-demo")
    .option("--story <name>", "grocery, travel, finance, coding, marketplace, autonomy, or all (grocery, travel, finance, coding and marketplace)", "all")
    .action(async (o: { out: string; story: string }) => {
      const { runDemo } = await import("./demo.js");
      await runDemo(o.out, (l) => process.stdout.write(l + "\n"), o.story);
    });
  program.command("demo-server", { hidden: true })
    .description("The demo MCP servers (used by saktum demo)")
    .option("--story <name>", "grocery, travel, finance, coding or autonomy", "autonomy")
    .action(async (o: { story: string }) => { const { startDemoServer } = await import("./demo.js"); await startDemoServer(o.story); });

  program.command("mcp")
    .description("Run Saktum Check as an MCP server (stdio), so coding agents can test, fix, diff and document MCP servers")
    .option("--packs <dir>", "directory of packs (default: the built-in packs)")
    .action(async (o: { packs?: string }) => {
      const packs = o.packs ? loadPackDir(o.packs) : existsSync(bundledPacks) ? loadPackDir(bundledPacks) : loadEmbeddedPacks();
      const { startMcpServer } = await import("./mcp-server.js");
      await startMcpServer(packs);
    });

  program.command("attest")
    .description("Turn a signed result into a compact signed attestation for your README or registry listing")
    .argument("<result>", "a signed result (saktum-report.json)")
    .option("--out <file>", "attestation file", "saktum-attestation.json")
    .option("--key <path>", "signing key file")
    .option("--publish", "also print a link that publishes it to the public Saktum trust ledger (a pre-filled GitHub issue)", false)
    .option("--vc", "also write it as a W3C Verifiable Credential (vc+jwt, issued by your did:key)", false)
    .action((file: string, o: { out: string; key?: string; publish: boolean; vc: boolean }) => {
      const doc = JSON.parse(readFileSync(file, "utf8")) as Result;
      const v = verifyDocument(doc);
      if (!v.valid) throw new Error(`The result's signature is not valid (${v.reason}); attestations are built only from unaltered signed results.`);
      const att = signDocument(buildAttestation(doc), loadOrCreateKey(o.key));
      writeFileSync(o.out, JSON.stringify(att, null, 2) + "\n");
      const c = att.claims, colour = (g: string | null) => ({ A: "2e7d32", B: "558b2f", C: "f9a825", D: "ef6c00", F: "c62828" } as Record<string, string>)[g ?? ""] ?? "757575";
      process.stdout.write(`Wrote ${sanitizeText(o.out)} (trust ${c.trustGrade ?? "-"}, agent readiness ${c.readinessGrade ?? "-"}; evidence: ${Object.entries(c.evidence).filter(([, x]) => x).map(([k]) => k).join(", ") || "none"}).\n`
        + `Anyone can check it: npx saktum verify ${sanitizeText(o.out)}\n\nREADME badge:\n`
        + `[![Saktum trust ${c.trustGrade ?? "-"}](https://img.shields.io/badge/Saktum-trust%20${c.trustGrade ?? "-"}%20%C2%B7%20readiness%20${c.readinessGrade ?? "-"}-${colour(c.trustGrade)})](${sanitizeText(o.out)})\n`);
      if (o.vc) {
        const key = loadOrCreateKey(o.key);
        const cred = attestationToCredential(att, key.kid);
        const base = o.out.replace(/\.json$/i, "");
        writeFileSync(`${base}.vc.jwt`, signCredentialJwt(cred, key) + "\n");
        writeFileSync(`${base}.vc.json`, JSON.stringify(cred, null, 2) + "\n");
        process.stdout.write(`\nW3C Verifiable Credential: ${sanitizeText(base)}.vc.jwt (check it: npx saktum vc verify ${sanitizeText(base)}.vc.jwt)\n`);
      }
      if (o.publish) {
        const body = `Publishing a signed Saktum attestation to the public trust ledger. The bot verifies the signature and appends it.\n\n\`\`\`json\n${JSON.stringify(att)}\n\`\`\`\n`;
        const url = `https://github.com/soodhere/saktum-index/issues/new?title=${encodeURIComponent(`Attest: ${att.subject.server}`)}&body=${encodeURIComponent(body)}`;
        process.stdout.write(`\nPublish to the public trust ledger (opens a pre-filled GitHub issue; anyone can then verify it):\n${url}\n`);
      }
    });

  program.command("doctor")
    .description("Check your environment, and why a server will not start or connect")
    .argument("[target...]", "optional: the same target you would pass to check")
    .option("--env <KEY=VALUE>", "environment variable for a local server (repeatable)", collect, [] as string[])
    .option("--header <Name: value>", "HTTP header for a remote server (repeatable)", collect, [] as string[])
    .action(async (targetParts: string[], o: { env: string[]; header: string[] }) => {
      const r = await runDoctor(targetParts ?? [], o.env, o.header);
      process.stdout.write(r.text + "\n");
      exitCode = r.code;
    });

  program.command("verify")
    .description("Verify a signed Saktum Check result")
    .argument("<file>")
    .action((file: string) => {
      const doc = JSON.parse(readFileSync(file, "utf8")) as Result;
      const validate = compileContract("result.schema.json");
      if (!(validate as (d: unknown) => boolean)(doc)) { process.stdout.write(`Invalid result format: ${JSON.stringify(validate.errors?.slice(0, 2))}\n`); exitCode = 1; return; }
      const v = verifyDocument(doc);
      if (!v.valid) { process.stdout.write(`\u2717 NOT VALID: ${sanitizeText(v.reason)}\n`); exitCode = 1; return; }
      process.stdout.write(`\u2713 Valid signature by ${v.kid}\n  Grade: ${doc.grade ?? "-"} (score ${doc.scores.overall ?? "n/a"}) \u00b7 assurance ${doc.assuranceLevel ?? "L1"}\n  Runner: ${doc.run.runner}${doc.run.runner === "self" ? ` \u2014 ${SELF_SIGNED_NOTE}` : ""}\n  Packs: ${doc.packs.map((p: { id: string; version: string }) => `${p.id} ${p.version}`).join(", ")}\n  Tools fingerprint: ${doc.target.toolsFingerprint}\n`);
    });

  if (argv.length <= 2) { process.stdout.write(WELCOME); return 0; }
  try { await program.parseAsync(argv); }
  catch (e) {
    const err = e as { code?: string; exitCode?: number; message?: string };
    if (err.code === "commander.helpDisplayed" || err.code === "commander.version") return 0;
    if (!err.code?.startsWith("commander.")) process.stderr.write(`${sanitizeText(err.message ?? String(e), 300)}\n`);
    return 2;
  }
  return exitCode;
}

const invokedDirectly = import.meta.url === `file://${process.argv[1]}` || /(?:main\.ts|saktum|saktum\.mjs)$/.test(process.argv[1] ?? "");
if (invokedDirectly) {
  main().then((c) => process.exit(c));
}
