// v0.7: the trust model in code: vocabularies, semantic bindings, intent mandates with rationale, plain language, demo.
import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { approvalRequestId, approveAction, consumeApproval, actionClass, bindingsFor, checkMandate, checkOperator, compileContract, cosignMandate, createMandate, decideIntent, describeMandate, revocationOf, revokeMandate, semanticValues, trustStatement } from "@saktum/testkit-core";
import { generateSigningKey } from "@saktum/sign";
import { root } from "./helpers.js";

const cli = (args: string[], cwd = root) => spawnSync(process.execPath, ["--import", "tsx", root + "packages/cli/src/main.ts", ...args], { cwd, encoding: "utf8", timeout: 200_000 });
const owner = generateSigningKey(), agent = generateSigningKey();
const cart = { name: "add_to_cart", inputSchema: { type: "object", properties: { product: {}, brand: {}, category: {}, quantity: {}, price: {}, substitute_for: {}, reference_price: {}, upgrade: {}, sponsored: {} } } };
const grocery = createMandate({ agentId: agent.kid, agentName: "Shopper", destructive: false, expires: "2099-01-01", purpose: "Weekly groceries",
  actions: [{ cls: "cart", autonomy: "act" }, { cls: "pay", autonomy: "propose" }],
  rules: [{ field: "commerce.item.quantity", op: "max", value: 2 }, { field: "commerce.item.category", op: "notIn", value: ["alcohol"] }],
  substitution: { allowed: true, maxPriceChangePct: 10, neverFor: ["baby food"] }, upsell: "ask", approvalTriggers: ["sponsored"],
  preferences: [{ field: "commerce.item.brand", prefer: "Usual Farms" }], counterparties: ["Demo Grocer"] }, owner);

describe("semantic bindings and action classes", () => {
  it("infers bindings from argument names, prefers declared ones, and tells travel from commerce", () => {
    expect(bindingsFor(cart).bindings).toMatchObject({ quantity: "commerce.item.quantity", substitute_for: "commerce.item.substitute_for" });
    expect(bindingsFor({ name: "book_flight", description: "Book a flight", inputSchema: { type: "object", properties: { fare: {}, stops: {}, amount: {} } } }).bindings).toMatchObject({ stops: "travel.itinerary.connections", amount: "travel.fare.total" });
    expect(bindingsFor({ name: "x", _meta: { "io.saktum/bindings": { q: "commerce.item.quantity", bad: "not.a.field" } } })).toEqual({ bindings: { q: "commerce.item.quantity" }, basis: "declared" });
    expect(semanticValues(cart, { quantity: 3, brand: "B" })).toEqual({ "commerce.item.quantity": 3, "commerce.item.brand": "B" });
    expect(actionClass({ name: "pay_for_order" }).cls).toBe("pay");
    expect(actionClass({ name: "x", _meta: { "io.saktum/action": "book" } })).toEqual({ cls: "book", basis: "declared" });
  });
});

describe("intent decisions with rationale", () => {
  const d = (args: Record<string, unknown>, tool: object = cart) => decideIntent(grocery as never, tool as never, args);
  it("enforces rules, substitution and upsell policies, triggers and counterparties", () => {
    expect(d({ product: "milk", brand: "Usual Farms", quantity: 1, price: 4 })).toMatchObject({ allow: true, rationale: { preferences: ["matches preference: brand of the item Usual Farms"] } });
    expect(d({ product: "apples", quantity: 5, price: 1 }).code).toBe("rule-violated");
    expect(d({ product: "wine", category: "Alcohol", quantity: 1, price: 9 }).code).toBe("rule-violated");
    expect(d({ product: "rye", quantity: 1, price: 6.35, substitute_for: "sourdough", reference_price: 5.99 })).toMatchObject({ allow: true });
    expect(d({ product: "rye", quantity: 1, price: 7.5, substitute_for: "sourdough", reference_price: 5.99 }).code).toBe("substitution-not-allowed");
    expect(d({ product: "oatmeal", category: "baby food", quantity: 1, price: 4, substitute_for: "usual oatmeal" }).reason).toMatch(/never substitute baby food/);
    expect(d({ product: "coffee", quantity: 1, price: 40, upgrade: true }).code).toBe("approval-needed");
    expect(d({ product: "snack", quantity: 1, price: 3, sponsored: true }).reason).toMatch(/sponsored/);
    expect(decideIntent(grocery as never, { name: "add_to_cart", inputSchema: { type: "object", properties: { merchant: {}, quantity: {} } } } as never, { merchant: "Other Shop", quantity: 1 }).code).toBe("counterparty-not-allowed");
    expect(decideIntent(grocery as never, { name: "pay_for_order", inputSchema: { type: "object", properties: { amount: {} } } } as never, { amount: 20 }).code).toBe("approval-needed");
  });
  it("records which rules were checked and flags preference differences", () => {
    const r = d({ product: "bar", brand: "Promo", quantity: 1, price: 2 });
    expect(r.rationale.evaluated.map((e) => e.ok)).toEqual([true]);
    expect(r.rationale.flags.join(" ")).toMatch(/differs from the stated preference/);
  });
  it("describes the mandate in plain words, and the contract accepts it", () => {
    const text = describeMandate(grocery).join(" ");
    for (const s of ["Weekly groceries.", "asks you before pay", "Substitutes within 10% of the price, never for baby food.", "Asks before any upgrade.", "Only with: Demo Grocer."]) expect(text).toContain(s);
    expect(compileContract("mandate.schema.json")(grocery)).toBe(true);
  });
});

describe("saktum demo (grocery and travel)", () => {
  it("runs both stories through the real proxy with signed, explained receipts and passports", () => {
    const dir = mkdtempSync(join(tmpdir(), "d7-"));
    const out = cli(["demo", "--out", join(dir, "d")]).stdout;
    for (const s of ["never substitute baby food", "this is an upgrade: ask your user first", "sponsored option chosen", "at most one connection (got 2)", "refundable fares only (got false)", "there is a fee of 45", "matches preference: an aisle seat"]) expect(out).toContain(s);
    expect(out).not.toMatch(/NOT verified/);
    for (const p of ["grocery", "travel"]) expect(existsSync(join(dir, "d", `${p}-passport.html`))).toBe(true);
    expect(readFileSync(join(dir, "d", "grocery-passport.html"), "utf8")).toMatch(/Its instructions, in plain words[\s\S]*Why, step by step/);
  }, 200_000);
});

describe("closing the honest gaps: data, parties, revocation, track record", () => {
  it("lets personal data go only where the mandate allows", () => {
    const m = createMandate({ agentId: agent.kid, agentName: "T", destructive: false, expires: "2099-01-01", purpose: "Trip", rules: [], dataSharing: [{ data: "passport", to: "Maple Air" }] } as never, owner);
    const book = { name: "book_flight", inputSchema: { type: "object", properties: { carrier: {}, passport_number: {} } } };
    const share = { name: "share_details", inputSchema: { type: "object", properties: { recipient: {}, passport_number: {} } } };
    expect(decideIntent(m as never, book as never, { carrier: "Maple Air", passport_number: "X1" }).allow).toBe(true);
    expect(decideIntent(m as never, share as never, { recipient: "Hotel Partner", passport_number: "X1" })).toMatchObject({ allow: false, code: "data-not-permitted" });
  });
  it("verifies the operator's countersignature and detects a changed mandate", () => {
    const op = generateSigningKey();
    const signed = cosignMandate(grocery, op, "Demo Grocer");
    expect(checkMandate(signed).ok).toBe(true);
    expect(checkOperator(signed as never)).toMatchObject({ present: true, valid: true, name: "Demo Grocer", id: op.kid });
    expect(checkOperator({ ...signed, purpose: "Something else" } as never)).toMatchObject({ valid: false });
  });
  it("revokes a mandate, and summarises the track record without a score", () => {
    const dir = mkdtempSync(join(tmpdir(), "rev-"));
    expect(revocationOf(grocery, join(dir, "r.json"))).toBeUndefined();
    revokeMandate(grocery, "stop", join(dir, "r.json"));
    expect(revocationOf(grocery, join(dir, "r.json"))?.reason).toBe("stop");
    const ts = trustStatement([], true);
    expect(ts.lines[0]).toMatch(/0 action\(s\) within its instructions/);
  });
  it("tells the whole story in the demo: tricked but held, data kept, stop works, countersigned, track record", () => {
    const dir = mkdtempSync(join(tmpdir(), "d9-"));
    const out = cli(["demo", "--out", join(dir, "d")]).stdout;
    for (const s of ["countersigned by the operator, Demo Grocer", "adds 10 gift cards: rule-violated", "QuickCash is not an allowed counterparty", "passport may not be shared with Hotel Partner", "it tries to search again: revoked", "Track record:", "all signed and verified"]) expect(out).toContain(s);
    expect(readFileSync(join(dir, "d", "grocery-passport.html"), "utf8")).toMatch(/Track record[\s\S]*countersigned by the operator Demo Grocer/);
  }, 240_000);
});

describe("signed approvals and enterprise data classes", () => {
  it("approves exactly one action, once, by the owner only", () => {
    const dir = mkdtempSync(join(tmpdir(), "apr-")), f = join(dir, "a.json");
    const args = { amount: 12000, vendor: "Consulting LLP" };
    const rid = approvalRequestId(grocery, "pay_invoice", args);
    expect(rid).toMatch(/^apr_[0-9a-f]{16}$/);
    expect(approvalRequestId(grocery, "pay_invoice", { ...args, amount: 12001 })).not.toBe(rid);
    expect(() => approveAction(grocery, rid, generateSigningKey(), 60, f)).toThrow(/owner/);
    expect(consumeApproval(grocery, rid, f).ok).toBe(false);
    approveAction(grocery, rid, owner, 60, f);
    expect(consumeApproval(grocery, rid, f).ok).toBe(true);
    expect(consumeApproval(grocery, rid, f).ok).toBe(false);
    const rid2 = approvalRequestId(grocery, "pay_invoice", { amount: 1 });
    approveAction(grocery, rid2, owner, -1, f);
    expect(consumeApproval(grocery, rid2, f).ok).toBe(false);
  });
  it("lets classified data go only to the recipients named for its class", () => {
    const m = createMandate({ agentId: agent.kid, agentName: "F", destructive: false, expires: "2099-01-01", purpose: "Finance", rules: [], dataSharing: [{ data: "confidential", to: "External Auditor" }] } as never, owner);
    const send = { name: "send_report", inputSchema: { type: "object", properties: { recipient: {}, data_class: {} } } };
    expect(decideIntent(m as never, send as never, { recipient: "External Auditor", data_class: "confidential" }).allow).toBe(true);
    expect(decideIntent(m as never, send as never, { recipient: "Partner Agency", data_class: "confidential" }).code).toBe("data-not-permitted");
    expect(decideIntent(m as never, send as never, { recipient: "Anyone", data_class: "public" }).allow).toBe(true);
  });
  it("shows data classes and a signed approval in the finance demo", () => {
    const dir = mkdtempSync(join(tmpdir(), "fin-"));
    const out = cli(["demo", "--story", "finance", "--out", join(dir, "d")]).stdout;
    for (const s of ["confidential data may not be shared with Partner Agency", "sends confidential results to the external auditor", "retries the same $12,000 invoice: approved by you, once", "(1 after your signed approval)"]) expect(out).toContain(s);
  }, 200_000);
});
