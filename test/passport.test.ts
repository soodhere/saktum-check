// v0.5: passports (server, agent, ledger pages and gallery) and the executive assessment.
import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appendToLedger, buildAttestation, buildFleet, loadPackDir, runTrustCheck } from "@saktum/testkit-core";
import { levelFromResult, renderAgentPassport, renderAssessment, renderServerPassport } from "@saktum/report";
import { generateSigningKey, signDocument } from "@saktum/sign";
import { fixture, root } from "./helpers.js";

const packs = loadPackDir(root + "packs");
const cli = (args: string[], cwd = root) => spawnSync(process.execPath, ["--import", "tsx", root + "packages/cli/src/main.ts", ...args], { cwd, encoding: "utf8", timeout: 120_000 });

describe("passports", () => {
  it("renders a server passport with identity, interface, maturity and verification, escaping all text", async () => {
    let tools: never[] = [];
    const r = await runTrustCheck(fixture("good"), { packs, onTools: (t) => { tools = t as never[]; } });
    expect(levelFromResult(r)).toBe(4);
    const html = renderServerPassport(r, tools);
    for (const s of ["MCP SERVER PASSPORT", "fixture-good", "get_forecast", "Agent-ready", "npx saktum verify"]) expect(html).toContain(s);
    const evil = renderServerPassport(r, [{ name: "<script>x</script>", description: "a<b" }] as never);
    expect(evil).not.toContain("<script>x</script>");
  });
  it("renders an agent passport with the receipt timeline and repeated calls highlighted", () => {
    const m = { agent: { id: "did:key:zA", name: "Billing bot" }, owner: { id: "did:key:zO", name: "Finance" }, allow: { tools: ["get_invoice"], destructive: false }, issuedAt: "2026-11-25T00:00:00Z", expires: "2027-01-31" };
    const summary = { calls: 4, denied: 1, errors: 0, destructiveAllowed: 0, repeatedIdenticalCalls: [{ call: "billing/get_invoice", times: 3 }], servers: ["billing"] };
    const timeline = [1, 2, 3].map(() => ({ tool: "get_invoice", outcome: "allow", status: "ok", repeated: true })).concat([{ tool: "refund", outcome: "deny", status: "blocked", repeated: false }]);
    const html = renderAgentPassport(m, { ok: true }, { verified: true, summary, timeline });
    for (const s of ["AGENT PASSPORT", "Billing bot", "The path, not the answer", "billing/get_invoice ×3", "step deny"]) expect(html).toContain(s);
  });
  it("works end to end: passport for a server, and for an agent", () => {
    const dir = mkdtempSync(join(tmpdir(), "pp-"));
    expect(cli(["passport", "--out", join(dir, "p.html"), "--key", join(dir, "k.json"), "--", process.execPath, "--import", "tsx", `${root}fixtures/src/good.ts`]).stdout).toMatch(/MCP Server Passport for fixture-good/);
    expect(existsSync(join(dir, "p.json"))).toBe(true);
    cli(["agent", "create", "--name", "Bot", "--out", join(dir, "m.json"), "--agent-key", join(dir, "a.json"), "--key", join(dir, "k.json")]);
    expect(cli(["passport", "--agent", join(dir, "m.json"), "--out", join(dir, "ap.html")]).stdout).toMatch(/Agent Passport for Bot/);
    expect(readFileSync(join(dir, "ap.html"), "utf8")).toMatch(/Mandate/);
  }, 120_000);
  it("generates ledger passport pages and a gallery", async () => {
    const dir = mkdtempSync(join(tmpdir(), "lp-"));
    const att = signDocument(buildAttestation(await runTrustCheck(fixture("good"), { packs })), generateSigningKey());
    writeFileSync(join(dir, "l.jsonl"), appendToLedger("", att, { issue: 1 }).text);
    expect(cli(["ledger", "pages", join(dir, "l.jsonl"), "--out", join(dir, "out")]).stdout).toMatch(/1 passport page/);
    expect(readFileSync(join(dir, "out", "fixture-good.html"), "utf8")).toMatch(/TRUST LEDGER ENTRY #1/);
    expect(readFileSync(join(dir, "out", "index.html"), "utf8")).toMatch(/MCP Server Passports/);
  }, 120_000);
});

describe("executive assessment", () => {
  it("summarises inventory, risk heat map, attention list, receipts and recommendations", () => {
    const rec = (name: string, extra = {}) => ({ name, client: "Cursor", target: "x", fingerprint: `fp-${name}`, trustGrade: "A", readinessGrade: "A", toolCount: 3, tokens: 30_000, capabilities: ["network"], ...extra });
    const f = buildFleet([{ machine: "m1", servers: [rec("payments", { capabilities: ["money"], readinessGrade: "C" }), rec("docs")] }, { machine: "m2", servers: [rec("docs")] }], { policyFormat: "0.1", forbidCapabilities: ["money"] });
    const html = renderAssessment("Acme Bank", f, [{ agent: "did:key:zA", verified: true, summary: { calls: 5, denied: 1, errors: 0, destructiveAllowed: 0, repeatedIdenticalCalls: [], servers: ["docs"] } }]);
    for (const s of ["MCP TRUST ASSESSMENT", "Acme Bank", "Risk heat map", "payments", "has a forbidden capability: money", "Agent receipts", "Recommendations", "move money or run code"]) expect(html).toContain(s);
  });
});
