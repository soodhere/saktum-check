// saktum bridge (v0.10): a remote MCP server (Streamable HTTP) presented as a local stdio server, so the proxy can
// govern it unchanged:  saktum proxy --mandate m.json --enforce -- saktum bridge https://host/mcp
// Headers (for example Authorization) are forwarded and never logged.
import { createInterface } from "node:readline";

export async function runBridge(url: string, headers: Record<string, string>): Promise<number> {
  let session: string | undefined;
  const out = (m: unknown) => process.stdout.write(JSON.stringify(m) + "\n");
  const rl = createInterface({ input: process.stdin });
  const pending: Promise<void>[] = [];
  const forward = async (line: string) => {
    let msg: { id?: unknown } = {};
    try { msg = JSON.parse(line); } catch { return; }
    try {
      const res = await fetch(url, { method: "POST", body: line,
        headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...(session ? { "Mcp-Session-Id": session } : {}), ...headers } });
      const sid = res.headers.get("mcp-session-id"); if (sid) session = sid;
      const text = await res.text();
      if (msg.id === undefined || res.status === 202) return;
      if (!res.ok && !text.trim()) { out({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: `upstream HTTP ${res.status}` } }); return; }
      if ((res.headers.get("content-type") ?? "").includes("text/event-stream")) {
        for (const l of text.split(/\r?\n/)) if (l.startsWith("data:")) { const d = l.slice(5).trim(); if (d) process.stdout.write(d + "\n"); }
      } else if (text.trim()) { const j = JSON.parse(text); for (const m of Array.isArray(j) ? j : [j]) out(m); }
    } catch (e) { if (msg.id !== undefined) out({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: `upstream unreachable: ${String((e as Error).message).slice(0, 120)}` } }); }
  };
  rl.on("line", (line) => { if (line.trim()) pending.push(forward(line)); });
  await new Promise<void>((r) => rl.on("close", () => r()));
  await Promise.allSettled(pending);
  if (session) { try { await fetch(url, { method: "DELETE", headers: { "Mcp-Session-Id": session, ...headers } }); } catch { /* best effort */ } }
  return 0;
}
