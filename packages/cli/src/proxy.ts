// `saktum proxy`: the gateway in miniature, for local (stdio) MCP servers. Put it between an agent and a server; it
// forwards every message unchanged, decides each tool call against the agent's mandate (observe by default, block with
// --enforce), and writes a signed, hash-chained receipt for every call. Arguments are stored only as a digest.
import { spawn } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { createInterface } from "node:readline";
import { randomUUID } from "node:crypto";
import type { SigningKey } from "@saktum/sign";
import { argumentsHash, chainEntry, mandateDecision, parseReceiptLog, signReceipt, type Mandate, type ReceiptLogEntry, type ToolAnnotations } from "@saktum/testkit-core";

export interface ProxyOptions { command: string; args: string[]; receiptsPath: string; agentKey: SigningKey; mandate?: Mandate; enforce: boolean; log?: (s: string) => void }

export async function runProxy(o: ProxyOptions): Promise<number> {
  mkdirSync(dirname(o.receiptsPath), { recursive: true });
  let last: { seq: number; entryHash: string } | undefined;
  if (existsSync(o.receiptsPath)) { const e = parseReceiptLog(readFileSync(o.receiptsPath, "utf8")); last = e[e.length - 1]; }
  const bare = !/[\\/]/.test(o.command);
  const child = spawn(o.command, o.args, { stdio: ["pipe", "pipe", "inherit"], shell: process.platform === "win32" && (bare || /\.(cmd|bat)$/i.test(o.command)) });
  let service = o.command.split(/[\\/]/).pop() ?? o.command, version: string | undefined;
  const annotations = new Map<string, ToolAnnotations>();
  const pendingKinds = new Map<string, "initialize" | "tools/list">();
  const calls = new Map<string, { tool: string; argsHash: string; start: number; reason: string; destructive: boolean }>();
  const key = (id: unknown) => JSON.stringify(id);
  const isDestructive = (a: ToolAnnotations) => a?.destructiveHint === true || (a?.readOnlyHint === false && a?.destructiveHint !== false);

  const record = (tool: string, argsHash: string, outcome: "allow" | "deny" | "error", reason: string, result: ReceiptLogEntry["result"]) => {
    const receipt = signReceipt({ receiptFormat: "0.1",
      envelope: { envelopeFormat: "0.1", id: randomUUID(), protocol: "mcp", operation: "tools/call", tool,
        caller: { agent: o.mandate?.agent.id ?? o.agentKey.kid, ...(o.mandate ? { onBehalfOf: o.mandate.owner.name ?? o.mandate.owner.id } : {}) },
        target: { service, ...(version ? { version } : {}) }, argumentsHash: argsHash, timestamp: new Date().toISOString(),
        ...(o.mandate?.purpose ? { context: { task: { purpose: o.mandate.purpose } } } : {}) },
      outcome, reason, issuedAt: new Date().toISOString() }, o.agentKey);
    const entry = chainEntry(last, receipt, result);
    appendFileSync(o.receiptsPath, JSON.stringify(entry) + "\n");
    last = entry;
  };

  // Agent -> server
  createInterface({ input: process.stdin }).on("line", (line) => {
    let msg: { id?: unknown; method?: string; params?: { name?: string; arguments?: unknown } };
    try { msg = JSON.parse(line); } catch { child.stdin.write(line + "\n"); return; }
    if (msg.method === "initialize" || msg.method === "tools/list") pendingKinds.set(key(msg.id), msg.method);
    if (msg.method === "tools/call" && msg.id !== undefined) {
      const tool = String(msg.params?.name ?? "");
      const argsHash = argumentsHash(msg.params?.arguments);
      const ann = annotations.get(tool);
      const d = o.mandate ? mandateDecision(o.mandate, service, tool, ann) : { allow: true, reason: "no mandate: observed" };
      if (!d.allow && o.enforce) {
        process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { isError: true, content: [{ type: "text", text: `Blocked by Saktum: ${d.reason}. Ask the agent's owner to extend its mandate if this action is needed.` }] } }) + "\n");
        record(tool, argsHash, "deny", d.reason, { status: "blocked", destructive: isDestructive(ann) });
        o.log?.(`denied ${tool}: ${d.reason}`);
        return;
      }
      calls.set(key(msg.id), { tool, argsHash, start: Date.now(), reason: d.allow ? d.reason : `outside the mandate (observed, not blocked): ${d.reason}`, destructive: isDestructive(ann) });
    }
    child.stdin.write(line + "\n");
  });
  process.stdin.on("end", () => child.stdin.end());

  // Server -> agent
  createInterface({ input: child.stdout! }).on("line", (line) => {
    let msg: { id?: unknown; result?: { serverInfo?: { name?: string; version?: string }; tools?: { name: string; annotations?: ToolAnnotations }[]; isError?: boolean }; error?: unknown };
    try { msg = JSON.parse(line); } catch { process.stdout.write(line + "\n"); return; }
    const k = key(msg.id);
    const kind = pendingKinds.get(k);
    if (kind === "initialize" && msg.result?.serverInfo?.name) { service = msg.result.serverInfo.name; version = msg.result.serverInfo.version; pendingKinds.delete(k); }
    if (kind === "tools/list" && Array.isArray(msg.result?.tools)) { for (const t of msg.result.tools) annotations.set(t.name, t.annotations); pendingKinds.delete(k); }
    const c = calls.get(k);
    if (c) {
      calls.delete(k);
      const status = msg.error ? "protocol-error" : msg.result?.isError ? "tool-error" : "ok";
      record(c.tool, c.argsHash, msg.error ? "error" : "allow", c.reason, { status, latencyMs: Date.now() - c.start, destructive: c.destructive });
    }
    process.stdout.write(line + "\n");
  });

  return new Promise<number>((resolve) => child.on("exit", (code) => {
    for (const c of calls.values()) record(c.tool, c.argsHash, "error", c.reason, { status: "no-response", destructive: c.destructive });
    resolve(code ?? 0);
  }));
}
