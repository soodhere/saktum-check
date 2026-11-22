#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { badgeSvg, checksTable, renderHtml, renderTerminal, SELF_SIGNED_NOTE } from "@saktum/report";
import { loadOrCreateKey, signDocument, verifyDocument } from "@saktum/sign";
import { compileContract, ENGINE_VERSION, loadEmbeddedPacks, loadPackDir, parseTestCases, runTrustCheck, sanitizeText, type Result, type Severity } from "@saktum/testkit-core";
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
