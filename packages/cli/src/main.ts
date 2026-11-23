#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { badgeSvg, checksTable, renderHtml, renderPacket, renderTerminal, SELF_SIGNED_NOTE } from "@saktum/report";
import { loadOrCreateKey, signDocument, verifyDocument } from "@saktum/sign";
import { buildAllowlist, compileContract, diffLocks, docsFor, ENGINE_VERSION, loadEmbeddedPacks, loadPackDir, parseTestCases, renderFix, runTrustCheck, sanitizeText, toolsLock, type Result, type Severity, type ToolsLock } from "@saktum/testkit-core";
import { connect } from "@saktum/transports";
import { runDoctor } from "./doctor.js";
import { parseTarget } from "@saktum/transports";

const SEV: Severity[] = ["critical", "high", "medium", "low", "info"];
const bundledPacks = fileURLToPath(new URL("../../../packs/", import.meta.url));
const collect = (v: string, acc: string[]) => [...acc, v];
const parseHeaders = (hs: string[]) => Object.fromEntries(hs.map((h) => { const i = h.indexOf(":"); if (i < 1) throw new Error(`--header must look like "Name: value"`); return [h.slice(0, i).trim(), h.slice(i + 1).trim()]; }));
const parseEnv = (kvs: string[]) => Object.fromEntries(kvs.map((kv) => { const i = kv.indexOf("="); if (i < 1) throw new Error(`--env must look like NAME=VALUE`); return [kv.slice(0, i), kv.slice(i + 1)]; }));

export async function main(argv = process.argv): Promise<number> {
  let exitCode = 0;
  const program = new Command().name("saktum").version(ENGINE_VERSION).description("Saktum Check: test MCP servers for trust (conformance, sign-in, security), functional behaviour, performance and agent readiness.").exitOverride();

  type CheckOpts = { packs?: string; out: string; html?: string; failOn: Severity; active: boolean; key?: string; env: string[]; header: string[]; pricePerMtok: string; call: string[]; tests?: string; ignore: string[]; badge?: string };
  const withCheckOptions = (c: Command, testsDefault?: string) => c
    .option("--packs <dir>", "directory of packs (default: the built-in packs)")
    .option("--out <file>", "signed JSON result", "saktum-report.json")
    .option("--html <file>", "also write an HTML report")
    .option("--badge <file>", "also write a README badge (SVG) with the trust and agent-readiness grades")
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
    process.stdout.write(renderTerminal(signed) + "\n");
    process.stdout.write(`\nSigned result: ${sanitizeText(o.out)}  (verify with: saktum verify ${sanitizeText(o.out)})${o.badge ? `\nBadge: ${sanitizeText(o.badge)}` : ""}\n`);
    const threshold = SEV.indexOf(o.failOn);
    return signed.findings.some((f) => f.status === "fail" && !f.suppressed && SEV.indexOf(f.severity) <= threshold) ? 1 : 0;
  };

  withCheckOptions(program.command("check")
    .description("Test an MCP server: a URL, or the command that starts a local server (after --)")
    .argument("<target...>", "https://host/mcp  or  -- node server.js"))
    .action(async (targetParts: string[], o: CheckOpts) => { exitCode = await runCheckCommand(targetParts, o); });

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
    .argument("<results...>", "signed results (saktum-report.json files)")
    .option("--min-trust <grade>", "minimum trust grade", "A")
    .option("--min-readiness <grade>", "minimum agent-readiness grade", "B")
    .option("--allow-critical", "do not exclude servers with a failed critical check", false)
    .option("--out <file>", "allowlist file", "saktum-allowlist.json")
    .action((files: string[], o: { minTrust: string; minReadiness: string; allowCritical: boolean; out: string }) => {
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
