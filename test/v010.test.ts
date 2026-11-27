// v0.10: enterprise pilot-ready: remote servers through the bridge, protected keys, approvals by link,
// combined receipts, bindings overrides, agent inventory.
import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { approvalRequestId, approveAction, createMandate, listPending, recordPending, scanAgents } from "@saktum/testkit-core";
import { generateSigningKey, loadOrCreateKey } from "@saktum/sign";
import { connect } from "@saktum/transports";
import { root, startHttpFixture } from "./helpers.js";

const main = root + "packages/cli/src/main.ts";
const self = ["--import", "tsx", main];
const cli = (args: string[]) => spawnSync(process.execPath, [...self, ...args], { cwd: root, encoding: "utf8", timeout: process.platform === "win32" ? 360_000 : 120_000 });
const text = (o: { kind: string; content?: unknown }) => (o.kind === "result" ? (o.content as { text?: string }[]).map((c) => c.text ?? "").join(" ") : o.kind);

function setup(m: Record<string, unknown>) {
  const dir = mkdtempSync(join(tmpdir(), "v010-"));
  const owner = loadOrCreateKey(join(dir, "owner.json")), agent = loadOrCreateKey(join(dir, "agent.json"));
  const mandate = createMandate({ agentId: agent.kid, agentName: "Remote bot", destructive: false, expires: "2099-01-01", tools: ["get_forecast", "save_note"], ...m } as never, owner);
  writeFileSync(join(dir, "m.json"), JSON.stringify(mandate));
  return { dir, owner, mandate };
}
const proxyArgs = (dir: string, extra: string[], url: string) => [...self, "proxy", "--mandate", join(dir, "m.json"), "--agent-key", join(dir, "agent.json"), "--enforce", "--receipts", join(dir, "r.jsonl"), "--approvals", join(dir, "a.json"), ...extra, "--", process.execPath, ...self, "bridge", url];

describe("remote MCP servers through the bridge", () => {
  it("governs a remote server exactly like a local one, and records receipts", async () => {
    const fx = await startHttpFixture("good");
    try {
      const { dir } = setup({ tools: ["get_forecast"] });
      const s = await connect({ kind: "stdio", command: process.execPath, args: proxyArgs(dir, [], fx.url) });
      try {
        expect((await s.listTools()).map((t: { name: string }) => t.name)).toContain("get_forecast");
        expect(text(await s.callTool("get_forecast", { city: "Toronto" }))).not.toMatch(/Blocked/);
        expect(text(await s.callTool("save_note", { text: "x" }))).toMatch(/Blocked by Saktum \(not-in-mandate\)/);
      } finally { await s.close(); }
      await new Promise((r) => setTimeout(r, 300));
      const out = cli(["receipts", "view", join(dir, "r.jsonl"), "--html", join(dir, "v.html")]);
      expect(out.stdout).toMatch(/Combined 2 receipts from 1 log/);
      expect(readFileSync(join(dir, "v.html"), "utf8")).toMatch(/not-in-mandate/);
    } finally { fx.stop(); }
  }, 120_000);

  it("posts approval requests to a webhook, and applies a bindings override", async () => {
    const fx = await startHttpFixture("good");
    const got: string[] = [];
    const hook = createServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { got.push(b); res.end("ok"); }); });
    await new Promise<void>((r) => hook.listen(0, "127.0.0.1", () => r()));
    const hookUrl = `http://127.0.0.1:${(hook.address() as { port: number }).port}/`;
    try {
      const { dir } = setup({ purpose: "Weather", actions: [{ cls: "search", autonomy: "act" }, { cls: "change", autonomy: "propose" }], rules: [{ field: "travel.carrier", op: "notIn", value: ["Paris"] }] });
      writeFileSync(join(dir, "b.json"), JSON.stringify({ get_forecast: { action: "search", bindings: { city: "travel.carrier" } }, save_note: { action: "change" } }));
      const s = await connect({ kind: "stdio", command: process.execPath, args: proxyArgs(dir, ["--approval-webhook", hookUrl, "--bindings", join(dir, "b.json")], fx.url) });
      try {
        await s.listTools();
        expect(text(await s.callTool("get_forecast", { city: "Paris" }))).toMatch(/rule-violated/);
        expect(text(await s.callTool("save_note", { text: "hello" }))).toMatch(/approval-needed/);
      } finally { await s.close(); }
      await new Promise((r) => setTimeout(r, 500));
      expect(got.join(" ")).toMatch(/Approval needed: Remote bot wants to run save_note/);
      expect(listPending(join(dir, "a.json"))).toHaveLength(1);
    } finally { fx.stop(); hook.close(); }
  }, 120_000);
});

describe("protected keys, pending approvals, agent inventory", () => {
  it("loads a key from an environment variable", () => {
    const dir = mkdtempSync(join(tmpdir(), "key-"));
    const k = loadOrCreateKey(join(dir, "k.json"));
    process.env.SAKTUM_TEST_KEY = readFileSync(join(dir, "k.json"), "utf8");
    expect(loadOrCreateKey("env:SAKTUM_TEST_KEY").kid).toBe(k.kid);
    expect(() => loadOrCreateKey("env:SAKTUM_NOT_SET_XYZ")).toThrow(/not set/);
  });
  it("tracks pending approvals until the owner approves", () => {
    const owner = generateSigningKey(), agent = generateSigningKey();
    const m = createMandate({ agentId: agent.kid, agentName: "B", destructive: false, expires: "2099-01-01" }, owner);
    const f = join(mkdtempSync(join(tmpdir(), "pend-")), "a.json");
    const id = approvalRequestId(m, "pay", { amount: 1 });
    recordPending(f, { id, tool: "pay", reason: "above threshold", agent: "B" });
    expect(listPending(f).map((p) => p.id)).toEqual([id]);
    approveAction(m, id, owner, 60, f);
    expect(listPending(f)).toHaveLength(0);
  });
  it("finds agents and their accountability in an inventory", () => {
    const { dir } = setup({});
    const a = scanAgents([dir]);
    expect(a).toHaveLength(1);
    expect(a[0]).toMatchObject({ name: "Remote bot", operator: "", valid: true, revoked: false });
    expect(cli(["agents", "scan", dir]).stdout).toMatch(/1 agent\(s\); 1 without an operator countersignature/);
  });
});
