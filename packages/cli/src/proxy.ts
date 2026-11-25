// `saktum proxy`: the gateway in miniature, for local (stdio) MCP servers. Put it between an agent and a server; it
// forwards every message unchanged, decides each tool call against the agent's mandate (observe by default, block with
// --enforce), and writes a signed, hash-chained receipt for every call. Arguments are stored only as a digest.
import { spawn } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { createInterface } from "node:readline";
import { randomUUID } from "node:crypto";
import type { SigningKey } from "@saktum/sign";
import { approvalRequestId, argumentsHash, capabilityProfile, chainEntry, consumeApproval, decideCall, decideIntent, hasIntent, parseReceiptLog, revocationOf, signReceipt, type Mandate, type ReceiptLogEntry, type ToolAnnotations } from "@saktum/testkit-core";

export interface ProxyOptions { approvalsPath?: string; revocationsPath?: string; command: string; args: string[]; receiptsPath: string; agentKey: SigningKey; mandate?: Mandate; enforce: boolean; log?: (s: string) => void }

export async function runProxy(o: ProxyOptions): Promise<number> {
  mkdirSync(dirname(o.receiptsPath), { recursive: true });
  let last: { seq: number; entryHash: string } | undefined;
  let history: ReceiptLogEntry[] = [];
  if (existsSync(o.receiptsPath)) { history = parseReceiptLog(readFileSync(o.receiptsPath, "utf8")); last = history[history.length - 1]; }
  const today = () => new Date().toISOString().slice(0, 10);
  const totArg = o.mandate?.limits?.totalPerDay?.arg;
  const governed = new Set([...(o.mandate?.constraints ?? []).map((k) => k.arg), ...(totArg ? [totArg] : []), ...(o.mandate?.approveAbove ? [o.mandate.approveAbove.arg] : [])]);
  const usage = () => { const t = today(); const done = history.filter((e) => e.receipt.issuedAt.startsWith(t) && e.receipt.outcome === "allow" && e.result.status === "ok" && e.result.code === "ok-action");
    return { callsToday: done.length, totalToday: totArg ? done.reduce((a, e) => a + Number(e.result.values?.[totArg] ?? 0), 0) : 0 }; };
  const bare = !/[\\/]/.test(o.command);
  const child = spawn(o.command, o.args, { stdio: ["pipe", "pipe", "inherit"], shell: process.platform === "win32" && (bare || /\.(cmd|bat)$/i.test(o.command)) });
  let service = o.command.split(/[\\/]/).pop() ?? o.command, version: string | undefined;
  const annotations = new Map<string, ToolAnnotations>();
  const toolDefs = new Map<string, { name: string; description?: string; inputSchema?: unknown; annotations?: ToolAnnotations }>();
  const pendingKinds = new Map<string, "initialize" | "tools/list">();
  const calls = new Map<string, { tool: string; argsHash: string; start: number; reason: string; destructive: boolean; code: string; values: Record<string, string | number>; rationale?: ReceiptLogEntry["result"]["rationale"] }>();
  const key = (id: unknown) => JSON.stringify(id);
  const isDestructive = (a: ToolAnnotations) => a?.destructiveHint === true || (a?.readOnlyHint === false && a?.destructiveHint !== false);

  const record = (tool: string, argsHash: string, outcome: "allow" | "deny" | "error", reason: string, result: ReceiptLogEntry["result"]) => {
    if (result.code) reason = `[${result.code}] ${reason}`;
    const receipt = signReceipt({ receiptFormat: "0.1",
      envelope: { envelopeFormat: "0.1", id: randomUUID(), protocol: "mcp", operation: "tools/call", tool,
        caller: { agent: o.mandate?.agent.id ?? o.agentKey.kid, ...(o.mandate ? { onBehalfOf: o.mandate.owner.name ?? o.mandate.owner.id } : {}) },
        target: { service, ...(version ? { version } : {}) }, argumentsHash: argsHash, timestamp: new Date().toISOString(),
        ...(o.mandate?.purpose ? { context: { task: { purpose: o.mandate.purpose } } } : {}) },
      outcome, reason, issuedAt: new Date().toISOString() }, o.agentKey);
    const entry = chainEntry(last, receipt, result);
    appendFileSync(o.receiptsPath, JSON.stringify(entry) + "\n");
    last = entry; history.push(entry);
  };

  // Agent -> server
  createInterface({ input: process.stdin }).on("line", (line) => {
    let msg: { id?: unknown; method?: string; params?: { name?: string; arguments?: unknown } };
    try { msg = JSON.parse(line); } catch { child.stdin.write(line + "\n"); return; }
    if (msg.method === "initialize" || msg.method === "tools/list") pendingKinds.set(key(msg.id), msg.method);
    if (msg.method === "tools/call" && msg.id !== undefined) {
      const tool = String(msg.params?.name ?? "");
      const args = (msg.params?.arguments ?? {}) as Record<string, unknown>;
      const argsHash = argumentsHash(args);
      const ann = annotations.get(tool);
      const def = toolDefs.get(tool);
      const isMoney = def ? capabilityProfile([def as never]).capabilities.some((c) => c.capability === "money") : false;
      const values = Object.fromEntries([...governed].filter((k) => args[k] !== undefined && (typeof args[k] === "number" || typeof args[k] === "string")).map((k) => [k, args[k] as string | number]));
      const rev = o.mandate ? revocationOf(o.mandate, o.revocationsPath) : undefined;
      let d: { allow: boolean; code: string; reason: string } = rev ? { allow: false, code: "revoked", reason: `the mandate was revoked on ${rev.at.slice(0, 10)}${rev.reason ? ` (${rev.reason})` : ""}` }
        : o.mandate ? decideCall(o.mandate, { tool, server: service, args, annotations: ann, isMoney, usage: usage() }) : { allow: true, code: "ok", reason: "no mandate: observed" };
      let rationale: ReceiptLogEntry["result"]["rationale"];
      if (d.allow && o.mandate && hasIntent(o.mandate as never)) {
        const di = decideIntent(o.mandate as never, (def ?? { name: tool }) as never, args, { server: service });
        rationale = di.rationale;
        for (const [k, val] of Object.entries(di.values)) if (typeof val === "number" || typeof val === "string" || typeof val === "boolean") values[k] = val as string | number;
        if (!di.allow) d = { allow: false, code: di.code, reason: di.reason };
        else if (di.reason !== "within the mandate") d = { allow: true, code: "ok", reason: di.reason };
      }
      if (!d.allow && d.code === "approval-needed" && o.mandate) {
        const rid = approvalRequestId(o.mandate, tool, args);
        const ap = consumeApproval(o.mandate, rid, o.approvalsPath);
        if (ap.ok) d = { allow: true, code: "ok", reason: `approved by ${ap.by} (${rid}), after: ${d.reason}` };
        else d = { ...d, reason: `${d.reason} [approval request ${rid}]` };
      }
      if (!d.allow && o.enforce) {
        const hint = d.code === "revoked" ? " The agent's owner stopped it; do not retry." : d.code === "approval-needed" ? " Ask your user to approve it (saktum agent approve with the request id), then retry the same action once." : d.code === "notify-only" ? " Tell your user what you found instead." : " Ask the agent's owner to change the mandate if this action is needed.";
        process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { isError: true, content: [{ type: "text", text: `Blocked by Saktum (${d.code}): ${d.reason}.${hint}` }] } }) + "\n");
        record(tool, argsHash, "deny", d.reason, { status: "blocked", destructive: isDestructive(ann), code: d.code, values, ...(rationale ? { rationale } : {}) });
        o.log?.(`denied ${tool} (${d.code}): ${d.reason}`);
        return;
      }
      const code = !d.allow ? `observed-${d.code}` : ann?.readOnlyHint === true ? "ok-read" : "ok-action";
      calls.set(key(msg.id), { tool, argsHash, start: Date.now(), reason: d.allow ? d.reason : `outside the mandate (observed, not blocked): ${d.reason}`, destructive: isDestructive(ann), code, values, rationale });
    }
    child.stdin.write(line + "\n");
  });
  // When the agent disconnects, close the server's input and, if it has not exited within two seconds, stop it, so no
  // server process is ever left running behind the proxy (some servers do not exit when their input closes).
  process.stdin.on("end", () => { child.stdin.end(); setTimeout(() => { if (child.exitCode === null) child.kill("SIGTERM"); }, 2000).unref(); });
  for (const sig of ["SIGINT", "SIGTERM"] as const) process.once(sig, () => { if (child.exitCode === null) child.kill("SIGTERM"); });

  // Server -> agent
  createInterface({ input: child.stdout! }).on("line", (line) => {
    let msg: { id?: unknown; result?: { serverInfo?: { name?: string; version?: string }; tools?: { name: string; annotations?: ToolAnnotations }[]; isError?: boolean }; error?: unknown };
    try { msg = JSON.parse(line); } catch { process.stdout.write(line + "\n"); return; }
    const k = key(msg.id);
    const kind = pendingKinds.get(k);
    if (kind === "initialize" && msg.result?.serverInfo?.name) { service = msg.result.serverInfo.name; version = msg.result.serverInfo.version; pendingKinds.delete(k); }
    if (kind === "tools/list" && Array.isArray(msg.result?.tools)) { for (const t of msg.result.tools) { annotations.set(t.name, t.annotations); toolDefs.set(t.name, t as never); } pendingKinds.delete(k); }
    const c = calls.get(k);
    if (c) {
      calls.delete(k);
      const status = msg.error ? "protocol-error" : msg.result?.isError ? "tool-error" : "ok";
      record(c.tool, c.argsHash, msg.error ? "error" : "allow", c.reason, { status, latencyMs: Date.now() - c.start, destructive: c.destructive, code: c.code, values: c.values, ...(c.rationale ? { rationale: c.rationale } : {}) });
    }
    process.stdout.write(line + "\n");
  });

  return new Promise<number>((resolve) => child.on("exit", (code) => {
    for (const c of calls.values()) record(c.tool, c.argsHash, "error", c.reason, { status: "no-response", destructive: c.destructive, code: c.code, values: c.values });
    resolve(code ?? 0);
  }));
}
