// An OAuth-protected MCP server over Streamable HTTP, for the sign-in checks.
//   --mode good:   401 with a Bearer challenge naming the resource metadata (RFC 9728), complete authorization server
//                  metadata with PKCE S256 (RFC 8414), invalid tokens rejected, the token "fixture-good-token" accepted.
//   --mode broken: 401 without a WWW-Authenticate header, no metadata documents, and any bearer token accepted.
// Usage: tsx fixtures/src/oauth.ts --mode good --http 0   (prints "listening <port>")
import { createServer } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { makeServer } from "./common.js";

const mode = process.argv[process.argv.indexOf("--mode") + 1] === "broken" ? "broken" : "good";
const port = Number(process.argv[process.argv.indexOf("--http") + 1] ?? 0);
const VALID = "fixture-good-token";

const tools = [{ name: "get_balance", description: "Get the signed-in user's account balance. Read-only; use for balance questions, not transactions.",
  inputSchema: { type: "object", properties: { account: { type: "string" } }, required: ["account"], additionalProperties: false },
  annotations: { readOnlyHint: true, openWorldHint: false } }];

const http = createServer(async (req, res) => {
  const addr = http.address();
  const origin = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : port}`;
  const json = (status: number, body: unknown) => { res.writeHead(status, { "Content-Type": "application/json" }).end(JSON.stringify(body)); };

  if (req.method === "GET" && mode === "good") {
    if (req.url === "/.well-known/oauth-protected-resource/mcp" || req.url === "/.well-known/oauth-protected-resource")
      return json(200, { resource: `${origin}/mcp`, authorization_servers: [origin], bearer_methods_supported: ["header"] });
    if (req.url === "/.well-known/oauth-authorization-server")
      return json(200, { issuer: origin, authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token`,
        response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token"], code_challenge_methods_supported: ["S256"] });
  }
  if (req.url !== "/mcp") { res.writeHead(404).end(); return; }

  const auth = req.headers["authorization"];
  const token = typeof auth === "string" && auth.startsWith("Bearer ") ? auth.slice(7) : undefined;
  const allowed = mode === "good" ? token === VALID : token !== undefined;
  if (!allowed) {
    if (mode === "good") {
      const header = token
        ? `Bearer error="invalid_token", resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`
        : `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`;
      res.writeHead(401, { "WWW-Authenticate": header, "Content-Type": "application/json" }).end(JSON.stringify({ error: "unauthorized" }));
    } else res.writeHead(401).end();
    return;
  }
  let body = ""; for await (const chunk of req) body += chunk;
  const server = makeServer(`fixture-oauth-${mode}`, tools, (name, args) => {
    if (name === "get_balance") return typeof args.account === "string" ? { content: [{ type: "text", text: "Balance: 120.00" }] } : { isError: true, content: [{ type: "text", text: "account is required" }] };
    return { isError: true, content: [{ type: "text", text: `Unknown tool: ${name}` }] };
  });
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => { void transport.close(); void server.close(); });
  await server.connect(transport);
  await transport.handleRequest(req, res, body ? JSON.parse(body) : undefined);
});
http.listen(port, "127.0.0.1", () => {
  const addr = http.address();
  process.stdout.write(`listening ${typeof addr === "object" && addr ? addr.port : port}\n`);
});
