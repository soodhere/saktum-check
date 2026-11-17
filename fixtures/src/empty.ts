// A server that declares the tools capability but lists no tools (as some servers do without valid credentials).
import { makeServer, start } from "./common.js";
await start(() => makeServer("fixture-empty", [], () => ({ isError: true, content: [{ type: "text", text: "Unknown tool" }] })));
