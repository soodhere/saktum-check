// A raw newline-delimited JSON-RPC server that answers in shapes the MCP specification does not allow.
// --mode init: initialize result without serverInfo or capabilities.
// --mode list: valid initialize, but tools/list returns no tools array.
import { createInterface } from "node:readline";

const mode = process.argv[process.argv.indexOf("--mode") + 1] ?? "init";
const send = (msg: unknown) => process.stdout.write(JSON.stringify(msg) + "\n");
for await (const line of createInterface({ input: process.stdin })) {
  let req: { id?: number | string; method?: string; params?: { protocolVersion?: string } };
  try { req = JSON.parse(line); } catch { continue; }
  if (req.id === undefined) continue; // notifications
  if (req.method === "initialize") {
    send({ jsonrpc: "2.0", id: req.id, result: mode === "init"
      ? { protocolVersion: req.params?.protocolVersion ?? "2025-06-18" }
      : { protocolVersion: req.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fixture-raw", version: "1.0.0" } } });
  } else if (req.method === "tools/list") {
    send({ jsonrpc: "2.0", id: req.id, result: { items: [] } });
  } else {
    send({ jsonrpc: "2.0", id: req.id, error: { code: -32601, message: "Method not found" } });
  }
}
