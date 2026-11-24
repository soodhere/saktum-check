// `saktum init`: start an MCP server that is trustworthy by default. Every template ships one example tool with
// annotations, a usable description and an output schema; test cases; CI with Saktum Check (SARIF to code scanning);
// and AGENTS.md so coding agents extending the server follow the same practices.
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** Rules for coding agents building MCP servers (also published as a Claude Code skill and Cursor rules). */
export const AGENT_RULES = `## Building this MCP server (rules for coding agents)

Follow these whenever you add or change a tool. They are what Saktum Check tests.

1. **Annotate every tool**: \`readOnlyHint\` (true if it only reads), \`destructiveHint\` (true if it deletes or overwrites),
   \`idempotentHint\` and \`openWorldHint\` (true if it reaches outside systems). Clients use them to ask before risky actions.
2. **Describe every tool in one or two plain sentences**: what it does and when to use it. Never put instructions to the
   agent in descriptions (no "ignore", "do not tell the user", hidden or invisible text).
3. **Name tools** with 1 to 64 letters, digits, underscores or hyphens, starting with a verb (\`get_order\`, \`create_invoice\`).
4. **Declare an output schema** and return matching \`structuredContent\` as well as text content.
5. **Validate inputs** against the input schema and return a short error result for bad input; never crash, hang, or put
   stack traces, file paths or secrets in errors.
6. **Keep tool definitions short**: every token is paid on every agent turn.
7. **Test**: add a happy-path and an error-path case to \`saktum.tests.yaml\` for each tool (\`npx saktum call <tool> --args '{...}' --save-test <id>\`
   records one from a real call), then run \`npx saktum test -- <start command>\` and \`npx saktum lint\` before committing.
8. **Before releasing a change**, run \`npx saktum diff saktum.lock.json -- <start command>\` and bump the version it suggests;
   then refresh the lock with \`npx saktum snapshot -- <start command>\`.
`;

const ciWorkflow = (start: string, setup: string) => `name: saktum
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
${setup}      - uses: soodhere/saktum-check@v0.4.0
        with:
          target: "-- ${start}"
          args: "--active --tests saktum.tests.yaml"
          sarif: "true"
          fail-on: high
`;

const testsFile = (tool: string) => `# Test cases for this server (guide: https://github.com/soodhere/saktum-check/blob/main/docs/TESTS.md)
testsFormat: "0.1"
tests:
  - id: greet-ada
    tool: ${tool}
    input: { name: Ada }
    expect: { isError: false, textContains: "Hello, Ada", structured: { greeting: "Hello, Ada" }, outputSchema: true, latencyMs: { lt: 2000 } }
  - id: greet-needs-name
    tool: ${tool}
    input: {}
    expect: { isError: true }
`;

const readme = (name: string, start: string, config: string) => `# ${name}

An MCP server started with \`saktum init\`: annotated tools, output schemas, test cases and CI with Saktum Check from the first commit.

## Run and test

\`\`\`
${start}                                 # start the server (stdio)
npx saktum check -- ${start}             # trust and agent-readiness grades
npx saktum test -- ${start}              # run saktum.tests.yaml with every check
npx saktum lint                          # static checks on your tool definitions
\`\`\`

## Use it

\`\`\`json
${config}
\`\`\`

## Rules for contributors and coding agents

See [AGENTS.md](AGENTS.md).
`;

export function initProject(dir: string, lang: "ts" | "py", name: string): string[] {
  if (existsSync(join(dir, "package.json")) || existsSync(join(dir, "pyproject.toml")) || existsSync(join(dir, "server.py"))) throw new Error(`${dir} already contains a project; choose an empty folder.`);
  const id = name.replace(/[^a-z0-9-]/gi, "-").toLowerCase() || "my-mcp-server";
  const files: Record<string, string> = {};
  if (lang === "ts") {
    const start = "npx tsx src/index.ts";
    files["package.json"] = JSON.stringify({ name: id, version: "0.1.0", type: "module", private: true, bin: { [id]: "src/index.ts" },
      scripts: { start: "tsx src/index.ts", "test:mcp": `npx -y saktum test -- ${start}`, lint: "npx -y saktum lint src" },
      dependencies: { "@modelcontextprotocol/sdk": "^1.32.2", zod: "^4.0.0", tsx: "^4.19.0" }, devDependencies: { typescript: "^5.6.0" } }, null, 2) + "\n";
    files["tsconfig.json"] = JSON.stringify({ compilerOptions: { target: "ES2022", module: "NodeNext", moduleResolution: "NodeNext", strict: true, skipLibCheck: true, noEmit: true }, include: ["src"] }, null, 2) + "\n";
    files["src/index.ts"] = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "${id}", version: "0.1.0" });

server.registerTool(
  "get_greeting",
  {
    title: "Get a greeting",
    description: "Return a friendly greeting for a person, by name. Use it to welcome someone.",
    inputSchema: { name: z.string().min(1).max(100).describe("The person's name") },
    outputSchema: { greeting: z.string() },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  async ({ name }) => {
    const result = { greeting: \`Hello, \${name}\` };
    return { content: [{ type: "text", text: result.greeting }], structuredContent: result };
  }
);

await server.connect(new StdioServerTransport());
`;
    files[".github/workflows/saktum.yml"] = ciWorkflow(start, `      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm install
`);
    files[".gitignore"] = "node_modules/\nsaktum-report.*\n*.sarif\n";
    files["README.md"] = readme(id, start, JSON.stringify({ mcpServers: { [id]: { command: "npx", args: ["tsx", "src/index.ts"] } } }, null, 2));
  } else {
    const start = "uv run server.py";
    files["pyproject.toml"] = `[project]\nname = "${id}"\nversion = "0.1.0"\nrequires-python = ">=3.10"\ndependencies = ["mcp>=1.10,<2"]  # v1 API (FastMCP); the v2 SDK renamed FastMCP to MCPServer\n`;
    files["server.py"] = `from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import BaseModel

mcp = FastMCP("${id}")


class Greeting(BaseModel):
    greeting: str


@mcp.tool(
    title="Get a greeting",
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False),
)
def get_greeting(name: str) -> Greeting:
    """Return a friendly greeting for a person, by name. Use it to welcome someone."""
    return Greeting(greeting=f"Hello, {name}")


if __name__ == "__main__":
    mcp.run()
`;
    files[".github/workflows/saktum.yml"] = ciWorkflow(start, `      - uses: astral-sh/setup-uv@v5
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
`);
    files[".gitignore"] = ".venv/\n__pycache__/\nsaktum-report.*\n*.sarif\n";
    files["README.md"] = readme(id, start, JSON.stringify({ mcpServers: { [id]: { command: "uv", args: ["run", "server.py"] } } }, null, 2));
  }
  files["saktum.tests.yaml"] = testsFile("get_greeting");
  files["AGENTS.md"] = `# ${id}\n\n${AGENT_RULES}`;
  for (const [p, text] of Object.entries(files)) { const f = join(dir, p); mkdirSync(join(f, ".."), { recursive: true }); writeFileSync(f, text); }
  return Object.keys(files);
}
