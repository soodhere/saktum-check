import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import { makeServer, start } from "./common.js";

const tools = [
  { name: "get_forecast", description: "Get the weather forecast for a city for the next three days. Use for questions about upcoming weather; not for historical weather.",
    inputSchema: { $schema: "http://json-schema.org/draft-07/schema#", type: "object", properties: { city: { type: "string", minLength: 1 } }, required: ["city"], additionalProperties: false },
    outputSchema: { type: "object", properties: { city: { type: "string" }, days: { type: "array", items: { type: "object", properties: { day: { type: "integer" }, summary: { type: "string" } }, required: ["day", "summary"] } } }, required: ["city", "days"] },
    annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: "save_note", description: "Save a short note to the user's private notebook. Overwrites nothing; each call adds a new note.",
    inputSchema: { type: "object", properties: { text: { type: "string", maxLength: 500 } }, required: ["text"], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false } }
];

await start(() => makeServer("fixture-good", tools, (name, args) => {
  if (name === "get_forecast") {
    if (typeof args.city !== "string" || !args.city) return { isError: true, content: [{ type: "text", text: "city is required, for example {\"city\": \"Toronto\"}" }] };
    const days = [1, 2, 3].map((day) => ({ day, summary: "sunny, 18C" }));
    return { content: [{ type: "text", text: `Forecast for ${args.city}: sunny, 18C.` }], structuredContent: { city: args.city, days } };
  }
  if (name === "save_note") return { content: [{ type: "text", text: "Saved." }] };
  throw new McpError(ErrorCode.InvalidParams, `Unknown tool: ${name}`);
}));
