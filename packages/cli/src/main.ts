#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { renderHtml, renderTerminal, SELF_SIGNED_NOTE } from "@saktum/report";
import { loadOrCreateKey, signDocument, verifyDocument } from "@saktum/sign";
import { compileContract, ENGINE_VERSION, loadEmbeddedPacks, loadPackDir, runTrustCheck, sanitizeText, type Result, type Severity } from "@saktum/testkit-core";
import { runDoctor } from "./doctor.js";
import { parseTarget } from "@saktum/transports";

const SEV: Severity[] = ["critical", "high", "medium", "low", "info"];
const bundledPacks = fileURLToPath(new URL("../../../packs/", import.meta.url));
const collect = (v: string, acc: string[]) => [...acc, v];
const parseHeaders = (hs: string[]) => Object.fromEntries(hs.map((h) => { const i = h.indexOf(":"); if (i < 1) throw new Error(`--header must look like "Name: value"`); return [h.slice(0, i).trim(), h.slice(i + 1).trim()]; }));
const parseEnv = (kvs: string[]) => Object.fromEntries(kvs.map((kv) => { const i = kv.indexOf("="); if (i < 1) throw new Error(`--env must look like NAME=VALUE`); return [kv.slice(0, i), kv.slice(i + 1)]; }));

export async function main(argv = process.argv): Promise<number> {
  let exitCode = 0;
  const program = new Command().name("saktum").version(ENGINE_VERSION).description("Saktum Check: test MCP servers for conformance, sign-in, security and agent experience.").exitOverride();

  program.command("check")
    .description("Test an MCP server: a URL, or the command that starts a local server (after --)")
    .argument("<target...>", "https://host/mcp  or  -- node server.js")
    .option("--packs <dir>", "directory of packs (default: the built-in packs)")
    .option("--out <file>", "signed JSON result", "saktum-report.json")
    .option("--html <file>", "also write an HTML report")
    .option("--fail-on <severity>", "exit 1 if any failure at or above this severity", "high")
    .option("--active", "run active checks (only against servers you own)", false)
    .option("--key <path>", "signing key file (created on first use)")
    .option("--env <KEY=VALUE>", "environment variable for a local server (repeatable); your own environment is never passed", collect, [] as string[])
    .option("--header <Name: value>", "HTTP header for a remote server, e.g. \"Authorization: Bearer <token>\" (repeatable)", collect, [] as string[])
    .option("--price-per-mtok <usd>", "your model's price per million input tokens, for the context-cost estimate", "3")
    .action(async (targetParts: string[], o: { packs?: string; out: string; html?: string; failOn: Severity; active: boolean; key?: string; env: string[]; header: string[]; pricePerMtok: string }) => {
      if (!SEV.includes(o.failOn)) throw new Error(`--fail-on must be one of ${SEV.join(", ")}`);
      const price = Number(o.pricePerMtok);
      if (!Number.isFinite(price) || price < 0) throw new Error("--price-per-mtok must be a number of US dollars, e.g. 3");
      const target = parseTarget(targetParts);
      if (target.kind === "stdio" && o.env.length) target.env = parseEnv(o.env);
      if (target.kind === "streamable-http" && o.header.length) target.headers = parseHeaders(o.header);
      const packs = o.packs ? loadPackDir(o.packs) : existsSync(bundledPacks) ? loadPackDir(bundledPacks) : loadEmbeddedPacks();
      let result: Result;
      try {
        result = await runTrustCheck(target, { packs, mode: o.active ? "active" : "passive", pricePerMTokUsd: price });
      } catch (e) {
        process.stderr.write(`Could not connect to ${sanitizeText(targetParts.join(" "), 120)}: ${sanitizeText((e as Error).message, 300)}\n`);
        process.stderr.write(`Hint: run saktum doctor ${targetParts[0]?.startsWith("http") ? "" : "-- "}${sanitizeText(targetParts.join(" "), 120)} to see why.\n`);
        exitCode = 2; return;
      }
      const signed = signDocument(result, loadOrCreateKey(o.key)) as Result;
      writeFileSync(o.out, JSON.stringify(signed, null, 2));
      if (o.html) writeFileSync(o.html, renderHtml(signed));
      process.stdout.write(renderTerminal(signed) + "\n");
      process.stdout.write(`\nSigned result: ${sanitizeText(o.out)}  (verify with: saktum verify ${sanitizeText(o.out)})\n`);
      const threshold = SEV.indexOf(o.failOn);
      exitCode = signed.findings.some((f) => f.status === "fail" && SEV.indexOf(f.severity) <= threshold) ? 1 : 0;
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
