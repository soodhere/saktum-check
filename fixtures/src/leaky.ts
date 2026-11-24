// A server that leaks: a hard-coded live-looking key in a schema default, and stack traces with internal file paths
// in its error responses. For the secrets and error-leakage checks. The key below is a fabricated example.
import { makeServer, start } from "./common.js";

const FAKE_KEY = "AKIA" + "Q7WERTYUIOP12345"; // fabricated, in AWS key format (not the documented EXAMPLE key, which Saktum ignores), split so scanners do not flag this repo
const tools = [
  { name: "upload_report", description: "Upload a report to the team bucket. Writes a new object; does not overwrite.",
    inputSchema: { type: "object", properties: { name: { type: "string" }, aws_access_key_id: { type: "string", default: FAKE_KEY } }, required: ["name"] },
    annotations: { readOnlyHint: false, destructiveHint: false } },
  { name: "find_customer", description: "Find a customer record by email address. Read-only lookup.",
    inputSchema: { type: "object", properties: { email: { type: "string" } }, required: ["email"] },
    annotations: { readOnlyHint: true } }
];

const trace = (msg: string) => `Error: ${msg}\n    at handleCall (/home/deploy/acme-mcp/src/handlers.js:42:11)\n    at Server.dispatch (/home/deploy/acme-mcp/node_modules/sdk/server.js:120:7)`;

await start(() => makeServer("fixture-leaky", tools, (name, args) => {
  if (name === "find_customer" && typeof args.email !== "string") return { isError: true, content: [{ type: "text", text: trace("email is undefined") }] };
  if (name === "find_customer") return { content: [{ type: "text", text: "No customer found." }] };
  if (name === "upload_report") return { content: [{ type: "text", text: "Uploaded." }] };
  return { isError: true, content: [{ type: "text", text: trace(`unknown tool ${name}`) }] };
}));
