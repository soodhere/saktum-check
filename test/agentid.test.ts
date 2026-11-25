// Agent identity, mandates, the proxy and signed receipts (preview of the gateway).
import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkMandate, compileContract, createMandate, mandateDecision, parseReceiptLog, summariseReceipts, verifyReceiptLog } from "@saktum/testkit-core";
import { generateSigningKey } from "@saktum/sign";
import { connect } from "@saktum/transports";
import { root } from "./helpers.js";

const cli = (args: string[], cwd = root) => spawnSync(process.execPath, ["--import", "tsx", root + "packages/cli/src/main.ts", ...args], { cwd, encoding: "utf8", timeout: 120_000 });

describe("mandates", () => {
  const owner = generateSigningKey(), agentKey = generateSigningKey();
  const m = createMandate({ agentId: agentKey.kid, agentName: "Forecast bot", ownerName: "Ops team", tools: ["get_forecast"], destructive: false, expires: "2099-01-01" }, owner);
  it("validates against the contract and checks signature and expiry", () => {
    expect(compileContract("mandate.schema.json")(m)).toBe(true);
    expect(checkMandate(m)).toEqual({ ok: true });
    expect(checkMandate({ ...m, allow: { ...m.allow, destructive: true } })).toMatchObject({ ok: false });
    expect(checkMandate(m, "2099-01-02")).toMatchObject({ ok: false, reason: expect.stringMatching(/expired/) });
    expect(checkMandate({ ...m, owner: { id: agentKey.kid } })).toMatchObject({ ok: false });
  });
  it("decides by tool, server and destructiveness", () => {
    expect(mandateDecision(m, "s", "get_forecast", { readOnlyHint: true }).allow).toBe(true);
    expect(mandateDecision(m, "s", "save_note", undefined).reason).toMatch(/not in the agent's mandate/);
    const open = createMandate({ agentId: agentKey.kid, agentName: "x", destructive: false, expires: "2099-01-01" }, owner);
    expect(mandateDecision(open, "s", "delete_all", { readOnlyHint: false }).reason).toMatch(/destructive/);
    expect(mandateDecision(open, "s", "update_row", { readOnlyHint: false, destructiveHint: false }).allow).toBe(true);
  });
});

describe("saktum proxy (end to end)", () => {
  const run = async (enforce: boolean) => {
    const dir = mkdtempSync(join(tmpdir(), "proxy-"));
    const mf = join(dir, "m.json"), ak = join(dir, "agent.json"), rf = join(dir, "receipts.jsonl");
    expect(cli(["agent", "create", "--name", "Forecast bot", "--owner-name", "Ops team", "--allow-tool", "get_forecast", "--out", mf, "--agent-key", ak, "--key", join(dir, "owner.json")]).status).toBe(0);
    const proxyArgs = ["--import", "tsx", root + "packages/cli/src/main.ts", "proxy", "--mandate", mf, "--agent-key", ak, "--receipts", rf, ...(enforce ? ["--enforce"] : []), "--", process.execPath, "--import", "tsx", root + "fixtures/src/good.ts"];
    const s = await connect({ kind: "stdio", command: process.execPath, args: proxyArgs, cwd: root });
    try {
      expect((await s.listTools()).length).toBeGreaterThan(0);
      for (let i = 0; i < 3; i++) expect((await s.callTool("get_forecast", { city: "Toronto" })).kind).toBe("result");
      const blocked = await s.callTool("save_note", { text: "hi" });
      return { dir, rf, blocked, mf };
    } finally { await s.close(); await new Promise((r) => setTimeout(r, 300)); }
  };
  it("enforce: blocks calls outside the mandate and records signed, chained receipts", async () => {
    const { rf, blocked, dir } = await run(true);
    expect(blocked.kind === "result" && blocked.isError).toBe(true);
    expect(JSON.stringify(blocked)).toMatch(/Blocked by Saktum \(not-in-mandate\): tool save_note is not in the agent.s mandate/);
    const entries = parseReceiptLog(readFileSync(rf, "utf8"));
    expect(verifyReceiptLog(entries)).toMatchObject({ ok: true, count: 4 });
    const receiptContract = compileContract("receipt.schema.json");
    for (const e of entries) expect(receiptContract(e.receipt), JSON.stringify(receiptContract.errors)).toBe(true);
    expect(entries[0]!.receipt.envelope.caller.onBehalfOf).toBe("Ops team");
    expect(entries[0]!.receipt.envelope.target.service).toBe("fixture-good");
    const s = summariseReceipts(entries);
    expect(s).toMatchObject({ calls: 4, denied: 1 });
    expect(s.repeatedIdenticalCalls).toEqual([{ call: "fixture-good/get_forecast", times: 3 }]);
    expect(cli(["receipts", "summary", rf]).stdout).toMatch(/Repeated identical calls \(possible retry storms\): fixture-good\/get_forecast ×3/);
    writeFileSync(rf, readFileSync(rf, "utf8").replace('"outcome":"deny"', '"outcome":"allow"'));
    expect(cli(["receipts", "verify", rf]).status).toBe(1);
    expect(dir).toBeTruthy();
  }, 120_000);
  it("observe: forwards calls outside the mandate but records them as such", async () => {
    const { rf, blocked } = await run(false);
    expect(blocked.kind === "result" && !blocked.isError).toBe(true);
    const last = parseReceiptLog(readFileSync(rf, "utf8")).pop()!;
    expect(last.receipt.reason).toMatch(/outside the mandate \(observed, not blocked\)/);
  }, 120_000);
});
