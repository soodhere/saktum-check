// A server whose read-only tools misbehave when actually called, for the functional checks (active runs).
//   lookup_order: declares an outputSchema but returns structuredContent that breaks it.
//   search_docs:  rejects arguments that satisfy its own input schema (JSON-RPC -32602).
//   get_status:   on invalid arguments, answers with a stack trace and then crashes the process.
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import { makeServer, start } from "./common.js";

const tools = [
  { name: "lookup_order", description: "Look up an order by its ID and return its status. Read-only; does not change the order.",
    inputSchema: { type: "object", properties: { order_id: { type: "string" } }, required: ["order_id"] },
    outputSchema: { type: "object", properties: { order_id: { type: "string" }, status: { enum: ["open", "shipped", "closed"] } }, required: ["order_id", "status"] },
    annotations: { readOnlyHint: true } },
  { name: "search_docs", description: "Search the product documentation for a phrase and return matching pages. Read-only.",
    inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] },
    annotations: { readOnlyHint: true } },
  { name: "get_status", description: "Get the current status of the service, optionally for one region. Read-only.",
    inputSchema: { type: "object", properties: { region: { type: "string" } }, required: ["region"] },
    annotations: { readOnlyHint: true } }
];

await start(() => makeServer("fixture-faulty", tools, (name, args) => {
  if (name === "lookup_order") return { content: [{ type: "text", text: "Order found." }], structuredContent: { orderId: 5, state: "unknown" } };
  if (name === "search_docs") throw new McpError(ErrorCode.InvalidParams, "Invalid query");
  if (name === "get_status") {
    if (typeof args.region !== "string") {
      setTimeout(() => process.exit(1), 50);
      return { isError: true, content: [{ type: "text", text: "TypeError: cannot read region\n    at status (/srv/status-mcp/src/handlers.js:12:7)" }] };
    }
    return { content: [{ type: "text", text: "All systems normal." }] };
  }
  throw new McpError(ErrorCode.InvalidParams, `Unknown tool: ${name}`);
}));
