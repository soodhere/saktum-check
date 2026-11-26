// v0.8: from trust to a marketplace: identity chains, manifests and catalogue, agreements, metering and wallet, KPIs.
import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { acceptAgreement, buildManifest, chargeCall, compileContract, draftAgreement, findOrphans, issueCredential, kpis, organisationRoot, searchCatalogue, topUp, verifyAgreement, verifyChain, walletBalance } from "@saktum/testkit-core";
import { generateSigningKey } from "@saktum/sign";
import { root } from "./helpers.js";

const cli = (args: string[], cwd = root) => spawnSync(process.execPath, ["--import", "tsx", root + "packages/cli/src/main.ts", ...args], { cwd, encoding: "utf8", timeout: 240_000 });
const exp = "2099-01-01";
const org = generateSigningKey(), person = generateSigningKey(), agent = generateSigningKey(), pub = generateSigningKey();
const rootCred = organisationRoot({ name: "Acme", domain: "acme.example", expires: exp }, org);
const personCred = issueCredential(rootCred, org, { type: "member", id: person.kid, name: "Priya", role: "lead", expires: exp });
const agentCred = issueCredential(personCred, person, { type: "agent", id: agent.kid, name: "Bot", expires: exp });
const tools = [
  { name: "search_products", description: "Search the catalogue.", inputSchema: { type: "object", properties: { query: {} } } },
  { name: "pay_for_order", description: "Pay for the order.", inputSchema: { type: "object", properties: { amount: {}, currency: {} } } }];

describe("identity chains", () => {
  it("walks agent -> person -> organisation, and catches breaks", () => {
    expect(verifyChain(agentCred)).toMatchObject({ valid: true, path: ["Acme", "Priya (lead)", "Bot"], organisation: "Acme (acme.example)" });
    expect(verifyChain(agentCred, { revoked: [personCred.id] })).toMatchObject({ valid: false, reason: expect.stringMatching(/Priya's credential was revoked/) });
    expect(verifyChain({ ...agentCred, subject: { ...agentCred.subject, name: "Evil" } }).valid).toBe(false);
    expect(verifyChain(agentCred, { today: "2100-01-01" }).reason).toMatch(/expired/);
    expect(() => issueCredential(agentCred, agent, { type: "agent", id: generateSigningKey().kid, name: "x", expires: exp })).toThrow(/Agents cannot issue/);
    expect(findOrphans([agentCred], { revoked: [personCred.id] })).toHaveLength(1);
    for (const c of [rootCred, personCred, agentCred]) expect(compileContract("credential.schema.json")(c)).toBe(true);
  });
});

describe("manifests, catalogue, agreements, wallet", () => {
  const m = buildManifest({ publisher: { name: "Shop" }, server: { name: "shop", version: "1" }, tools, rates: { perCall: 1, perTool: { pay_for_order: 5 } } }, pub);
  it("derives intents and finds servers by intent; ignores tampered manifests", () => {
    expect(m.intents).toEqual(expect.arrayContaining(["search:commerce", "pay:commerce"]));
    expect(compileContract("manifest.schema.json")(m)).toBe(true);
    expect(searchCatalogue([m], "buy groceries")[0]?.manifest.id).toBe(m.id);
    expect(searchCatalogue([{ ...m, publisher: { ...m.publisher, name: "Fake" } }], "buy groceries")).toHaveLength(0);
  });
  it("requires both signatures on an agreement, and detects tampering and expiry", () => {
    const d = draftAgreement({ manifest: m, invoker: { id: org.kid, name: "Acme" }, purpose: "Groceries", validUntil: exp }, pub);
    expect(verifyAgreement(d)).toMatchObject({ valid: false, reason: expect.stringMatching(/not yet accepted/) });
    const a = acceptAgreement(d, org);
    expect(verifyAgreement(a).valid).toBe(true);
    expect(compileContract("agreement.schema.json")(a)).toBe(true);
    expect(verifyAgreement({ ...a, rates: { perCall: 0 } }).valid).toBe(false);
    expect(verifyAgreement(a, "2100-01-01").reason).toMatch(/expired/);
    expect(() => acceptAgreement(d, generateSigningKey())).toThrow(/named invoker/);
    expect(() => draftAgreement({ manifest: m, invoker: { id: org.kid, name: "Acme" }, purpose: "x", validUntil: exp }, generateSigningKey())).toThrow(/publisher/);
  });
  it("meters calls with double-entry tokens and refuses when credit runs out", () => {
    const a = acceptAgreement(draftAgreement({ manifest: m, invoker: { id: org.kid, name: "Acme" }, purpose: "Groceries", validUntil: exp }, pub), org);
    const w = join(mkdtempSync(join(tmpdir(), "w-")), "w.json");
    topUp(w, org.kid, 6);
    expect(chargeCall(w, a, "pay_for_order", "r1")).toMatchObject({ ok: true, tokens: 5, balance: 1 });
    expect(chargeCall(w, a, "pay_for_order", "r2")).toMatchObject({ ok: false, balance: 1 });
    expect(walletBalance(w, org.kid) + walletBalance(w, pub.kid)).toBe(6);
    expect(kpis([]).calls).toBe(0);
    expect(compileContract("bounty.schema.json")(JSON.parse(readFileSync(root + "contracts/examples/bounty.example.json", "utf8")))).toBe(true);
  });
});

describe("saktum demo --story marketplace", () => {
  it("runs the October vision end to end", () => {
    const out = cli(["demo", "--story", "marketplace", "--out", join(mkdtempSync(join(tmpdir(), "mk-")), "d")]).stdout;
    for (const s of ["Acme Corp \u2192 Priya (procurement lead) \u2192 Acme shopping agent", "signed by Demo Grocer and Acme Corp (verified)", "balance 0", "insufficient-credit", "total 12 tokens", "Acme 0 tokens, Demo Grocer 12 tokens", "identity-chain", "verified \u00b7 passport"]) expect(out).toContain(s);
  }, 240_000);
});

describe("agent maturity (A1-A5)", () => {
  it("is earned level by level from evidence, never skipping a level", async () => {
    const { createMandate, cosignMandate, agentMaturity } = await import("@saktum/testkit-core");
    const owner = generateSigningKey(), op = generateSigningKey(), ag = generateSigningKey();
    const base = createMandate({ agentId: ag.kid, agentName: "B", destructive: false, expires: exp, tools: ["search_products"] }, owner);
    expect(agentMaturity(base).level).toBe(1);
    const signed = cosignMandate(base, op, "Op");
    expect(agentMaturity(signed as never).label).toBe("A3 Bounded");
    expect(agentMaturity(createMandate({ agentId: ag.kid, agentName: "B", destructive: false, expires: exp }, owner)).level).toBe(1);
  });
});
