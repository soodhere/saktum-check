// v0.6.1: risk tiers, permissions enforced per call, reason codes, the demo.
import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { agentRiskTier, compileContract, createMandate, decideCall, loadPackDir, riskTier, runTrustCheck } from "@saktum/testkit-core";
import { generateSigningKey } from "@saktum/sign";
import { fixture, root } from "./helpers.js";

const packs = loadPackDir(root + "packs");
const cli = (args: string[], cwd = root) => spawnSync(process.execPath, ["--import", "tsx", root + "packages/cli/src/main.ts", ...args], { cwd, encoding: "utf8", timeout: process.platform === "win32" ? 450_000 : 150_000 });
const t = (name: string, description: string, annotations: Record<string, unknown> = {}) => ({ name, description, inputSchema: { type: "object" }, annotations });

describe("risk tiers", () => {
  it("separates public reads from changes, destructive actions and money", () => {
    expect(riskTier([t("get_weather", "Get the forecast for a city.", { readOnlyHint: true })]).tier).toBe("R0");
    expect(riskTier([t("create_ticket", "Create a support ticket.")]).tier).toBe("R2");
    expect(riskTier([t("delete_repo", "Delete a repository.", { destructiveHint: true })]).tier).toBe("R3");
    expect(riskTier([t("pay_invoice", "Charges the customer's card for an invoice.")]).tier).toBe("R4");
  });
  it("appears in results, and policy can cap it", async () => {
    const r = await runTrustCheck(fixture("good"), { packs });
    expect(r.riskTier?.tier).toMatch(/^R[0-4]$/);
    expect(r.riskTier?.requirement).toBeTruthy();
  });
});

describe("permissions enforced per call", () => {
  const owner = generateSigningKey(), agent = generateSigningKey();
  const base = { agentId: agent.kid, agentName: "Shopper", tools: ["get_deals", "pay_for_order", "add_to_cart"], destructive: false, expires: "2099-01-01" };
  const call = (m: ReturnType<typeof createMandate>, tool: string, args: Record<string, unknown>, ro = false, money = false, usage = { callsToday: 0, totalToday: 0 }) =>
    decideCall(m, { tool, server: "shop", args, annotations: ro ? { readOnlyHint: true } : { readOnlyHint: false, destructiveHint: false }, isMoney: money, usage });
  it("notify only alerts; propose asks; act works within limits", () => {
    const notify = createMandate({ ...base, autonomy: "notify" }, owner);
    expect(call(notify, "get_deals", {}, true).allow).toBe(true);
    expect(call(notify, "add_to_cart", { product: "x" }).code).toBe("notify-only");
    expect(call(createMandate({ ...base, autonomy: "propose" }, owner), "add_to_cart", {}).code).toBe("approval-needed");
    const act = createMandate({ ...base, autonomy: "act", constraints: [{ tool: "pay_for_order", arg: "amount", max: 50 }, { tool: "pay_for_order", arg: "currency", oneOf: ["CAD"] }], approveAbove: { arg: "amount", value: 25 }, limits: { totalPerDay: { arg: "amount", max: 100 }, callsPerDay: 5 } }, owner);
    expect(call(act, "pay_for_order", { amount: 18, currency: "CAD" }, false, true).code).toBe("ok");
    expect(call(act, "pay_for_order", { amount: 30, currency: "CAD" }, false, true).code).toBe("approval-needed");
    expect(call(act, "pay_for_order", { amount: 80, currency: "CAD" }, false, true).code).toBe("over-cap");
    expect(call(act, "pay_for_order", { amount: 10, currency: "USD" }, false, true).code).toBe("value-not-allowed");
    expect(call(act, "pay_for_order", { amount: 20, currency: "CAD" }, false, true, { callsToday: 1, totalToday: 90 }).code).toBe("daily-limit");
    expect(call(act, "add_to_cart", {}, false, false, { callsToday: 5, totalToday: 0 }).code).toBe("daily-limit");
  });
  it("denies money movement unless explicitly granted, and validates the new mandate fields", () => {
    const open = createMandate({ ...base, tools: undefined, autonomy: "act" }, owner);
    expect(call(open, "refund", { amount: 5 }, false, true).code).toBe("money-not-granted");
    const m = createMandate({ ...base, autonomy: "act", constraints: [{ tool: "pay_for_order", arg: "amount", max: 50 }], disclosures: { operator: "Shop", incentives: "none" } }, owner);
    expect(compileContract("mandate.schema.json")(m)).toBe(true);
    expect(m.delegation).toBe(false);
    expect(agentRiskTier(m)).toMatchObject({ tier: "R4", note: expect.stringMatching(/capped \(amount ≤ 50\)/) });
    expect(agentRiskTier(createMandate({ ...base, autonomy: "notify" }, owner)).tier).toBe("R0");
  });
});

describe("saktum demo", () => {
  it("runs one shopping agent under three mandates with signed receipts and passports", () => {
    const dir = mkdtempSync(join(tmpdir(), "demo-"));
    const out = cli(["demo", "--story", "autonomy", "--out", join(dir, "d")]);
    for (const s of ["blocked (notify-only)", "blocked (approval-needed)", "Paid $18 CAD", "blocked (over-cap)", "blocked (value-not-allowed)"]) expect(out.stdout).toContain(s);
    expect(out.stdout).not.toMatch(/NOT verified/);
    for (const p of ["notify", "propose", "act"]) expect(existsSync(join(dir, "d", `${p}-passport.html`))).toBe(true);
    expect(readFileSync(join(dir, "d", "act-passport.html"), "utf8")).toMatch(/Permissions[\s\S]*at most 50[\s\S]*Operated by/);
  }, 150_000);
});
