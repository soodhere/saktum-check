import { makeServer, start } from "./common.js";

// Common real-world mistakes seen in the field test: invalid schema, bad and duplicate names,
// terse descriptions, no annotations, and success for unknown tools.
const tools = [
  { name: "search", description: "Search.", inputSchema: { type: "string" } },
  { name: "search", description: "Search again.", inputSchema: { type: "object", properties: {} } },
  { name: "delete item", description: "Delete", inputSchema: { type: "object", properties: { id: { type: "string" } } } }
];

await start(() => makeServer("fixture-broken", tools, () => ({ content: [{ type: "text", text: "ok" }] })));
