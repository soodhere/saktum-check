// Shared scaffolding for fixture servers. Fixtures are deliberately small, deterministic MCP servers
// used by tests and demos: good (passes everything), broken (common mistakes), malicious (attacks).
import { createServer } from "node:http";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export type CallHandler = (name: string, args: Record<string, unknown>) => Promise<unknown> | unknown;

export function makeServer(name: string, tools: unknown[], onCall: CallHandler): Server {
  const server = new Server({ name, version: "1.0.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }) as never);
  server.setRequestHandler(CallToolRequestSchema, async (req) => (await onCall(req.params.name, (req.params.arguments ?? {}) as Record<string, unknown>)) as never);
  return server;
}

/** Start over stdio, or over Streamable HTTP (stateless) when started with --http <port>. */
export async function start(factory: () => Server, opts: { validateOrigin?: boolean } = {}): Promise<void> {
  const i = process.argv.indexOf("--http");
  if (i < 0) { await factory().connect(new StdioServerTransport()); return; }
  const port = Number(process.argv[i + 1] ?? 0);
  const http = createServer(async (req, res) => {
    if (req.url !== "/mcp") { res.writeHead(404).end(); return; }
    const origin = req.headers["origin"];
    if (opts.validateOrigin && typeof origin === "string" && !/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) { res.writeHead(403).end("Forbidden origin"); return; }
    let body = ""; for await (const chunk of req) body += chunk;
    const server = factory();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => { void transport.close(); void server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, body ? JSON.parse(body) : undefined);
  });
  http.listen(port, "127.0.0.1", () => {
    const addr = http.address();
    process.stdout.write(`listening ${typeof addr === "object" && addr ? addr.port : port}\n`);
  });
}
