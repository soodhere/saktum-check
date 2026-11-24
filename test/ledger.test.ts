// The Saktum trust ledger: append-only, hash-chained, signature-verified; tamper-evident; allowlists from it.
import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { allowlistFromLedger, appendToLedger, buildAttestation, extractJson, findInLedger, loadPackDir, parseLedger, runTrustCheck, verifyLedger } from "@saktum/testkit-core";
import { generateSigningKey, signDocument } from "@saktum/sign";
import { fixture, root } from "./helpers.js";

const packs = loadPackDir(root + "packs");
const cli = (args: string[], cwd = root) => spawnSync(process.execPath, ["--import", "tsx", root + "packages/cli/src/main.ts", ...args], { cwd, encoding: "utf8", timeout: 120_000 });

describe("trust ledger", async () => {
  const key = generateSigningKey(), other = generateSigningKey();
  const good = signDocument(buildAttestation(await runTrustCheck(fixture("good"), { packs })), key);
  const broken = signDocument(buildAttestation(await runTrustCheck(fixture("broken"), { packs })), other);
  const two = appendToLedger(appendToLedger("", good, { issue: 1 }).text, broken, { issue: 2 }).text;

  it("appends verified attestations into a hash chain that verifies", () => {
    const entries = parseLedger(two);
    expect(entries.map((e) => e.seq)).toEqual([1, 2]);
    expect(entries[1]!.prevHash).toBe(entries[0]!.entryHash);
    expect(verifyLedger(entries)).toMatchObject({ ok: true, count: 2 });
  });
  it("detects tampering: an edited claim, a deleted entry, a reordered log", () => {
    const e = parseLedger(two);
    const edited = structuredClone(e); edited[0]!.attestation.claims.trustGrade = "A+";
    expect(verifyLedger(edited).errors.join(" ")).toMatch(/contents changed|signature not valid/);
    expect(verifyLedger([e[1]!]).errors.join(" ")).toMatch(/sequence|chain broken/);
    expect(verifyLedger([e[1]!, e[0]!]).ok).toBe(false);
  });
  it("refuses forged, unsigned and duplicate attestations", () => {
    expect(() => appendToLedger("", { ...good, claims: { ...good.claims, trustGrade: "A" }, subject: { ...good.subject, server: "someone-else" } }, {})).toThrow(/signature not valid/);
    const { signature: _s, ...unsigned } = good;
    expect(() => appendToLedger("", unsigned, {})).toThrow(/Refused/);
    expect(() => appendToLedger(two, good, {})).toThrow(/already in the ledger/);
    expect(() => appendToLedger("", { hello: "world" }, {})).toThrow(/not a Saktum attestation/);
  });
  it("finds entries and builds allowlists, optionally only from trusted signers", () => {
    const e = parseLedger(two);
    expect(findInLedger(e, "fixture-good").length).toBe(1);
    const all = allowlistFromLedger(e, { minTrust: "A", minReadiness: "B" });
    expect(all.allowed.map((a) => a.server)).toEqual(["fixture-good"]);
    expect(all.excluded[0]!.reason).toMatch(/below/);
    const none = allowlistFromLedger(e, { minTrust: "A", minReadiness: "B", trustedSigners: new Set(["did:key:z-nobody"]) });
    expect(none.allowed).toEqual([]);
  });
  it("extracts the attestation from a GitHub issue body", () => {
    expect((extractJson(`Publishing.\n\n\`\`\`json\n${JSON.stringify(good)}\n\`\`\`\n`) as { attestationFormat: string }).attestationFormat).toBe("0.1");
  });
  it("works end to end: attest --publish, bot append from an issue body, verify, allowlist from the ledger", () => {
    const dir = mkdtempSync(join(tmpdir(), "ledger-"));
    cli(["check", "--key", join(dir, "k.json"), "--out", join(dir, "r.json"), "--", process.execPath, "--import", "tsx", `${root}fixtures/src/good.ts`]);
    const att = cli(["attest", join(dir, "r.json"), "--key", join(dir, "k.json"), "--out", join(dir, "a.json"), "--publish"]);
    expect(att.stdout).toMatch(/https:\/\/github\.com\/soodhere\/saktum-index\/issues\/new\?title=Attest%3A%20fixture-good&body=/);
    writeFileSync(join(dir, "issue.md"), `Publishing.\n\n\`\`\`json\n${readFileSync(join(dir, "a.json"), "utf8")}\n\`\`\`\n`);
    const ledger = join(dir, "ledger.jsonl");
    expect(cli(["ledger", "append", join(dir, "issue.md"), "--ledger", ledger, "--issue", "7"]).stdout).toMatch(/Recorded entry #1 for fixture-good/);
    expect(cli(["ledger", "verify", ledger]).stdout).toMatch(/Ledger verified: 1 entries/);
    expect(cli(["ledger", "find", "fixture", "--ledger", ledger]).stdout).toMatch(/#1 fixture-good/);
    expect(cli(["allowlist", "--from-ledger", ledger, "--out", join(dir, "allow.json")]).stdout).toMatch(/1 allowed/);
    writeFileSync(ledger, readFileSync(ledger, "utf8").replace('"trustGrade":"A"', '"trustGrade":"B"'));
    expect(cli(["ledger", "verify", ledger]).status).toBe(1);
  }, 120_000);
});
