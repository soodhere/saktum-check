// `saktum mcp`: Saktum Check as an MCP server (stdio), so coding agents can test, fix, diff and document MCP servers.
// Same rules as the command line: passive by default; --active behaviour only when the agent asks for it explicitly
// (and only against servers the user owns); the user's environment is never passed to a target server.
import { readFileSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { connect, parseTarget, type Target } from "@saktum/transports";
import { checksTable, scopeOfRun, trustCard } from "@saktum/report";
import { diffLocks, docsFor, ENGINE_VERSION, renderFix, runTrustCheck, sanitizeText, type LoadedPack, type ToolsLock } from "@saktum/testkit-core";

/** Split "npx -y some-server --flag 'a b'" into parts, honouring simple quotes. URLs stay whole. */
export function splitTarget(target: string): string[] {
  const t = target.trim();
  if (/^https?:\/\//i.test(t)) return [t];
  const parts: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(t))) parts.push(m[1] ?? m[2] ?? m[3]!);
  return parts;
}

const targetOf = (s: unknown): Target => {
  if (typeof s !== "string" || !s.trim()) throw new Error("target is required: an https URL, or the command that starts a local server (for example: npx -y @scope/server)");
  return parseTarget(splitTarget(s.slice(0, 1000)));
};
const TARGET = { type: "string", description: "An https URL of a remote MCP server, or the command that starts a local one (for example: npx -y @modelcontextprotocol/server-memory). Local commands run on this machine.", maxLength: 1000 };
const RO = (openWorld: boolean) => ({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: openWorld });

export const SAKTUM_TOOLS = [
  { name: "check_server", title: "Check an MCP server",
    description: "Test an MCP server for trust (conformance, sign-in, security mapped to the OWASP MCP Top 10), agent readiness, capabilities and performance; returns grades, a trust card, failed checks with fixes, and the scope of the run. Starts local servers on this machine. Passive by default: no tool of the target is called unless active is true, which is only for servers the user owns.",
    inputSchema: { type: "object", properties: { target: TARGET, active: { type: "boolean", default: false, description: "Also call the target's read-only tools and measure load. Only for servers the user owns." } }, required: ["target"], additionalProperties: false },
    outputSchema: { type: "object", properties: {
      trustGrade: { type: ["string", "null"] }, readinessGrade: { type: ["string", "null"] }, summary: { type: "array", items: { type: "string" } },
      trustCard: { type: "array", items: { type: "object", properties: { dimension: { type: "string" }, mark: { type: "string" }, text: { type: "string" } }, required: ["dimension", "mark", "text"] } },
      failedChecks: { type: "array", items: { type: "object", properties: { check: { type: "string" }, severity: { type: "string" }, message: { type: "string" }, fix: { type: "string" } }, required: ["check", "severity", "message"] } },
      scope: { type: "array", items: { type: "string" } } }, required: ["trustGrade", "readinessGrade", "summary", "trustCard", "failedChecks", "scope"] },
    annotations: RO(true) },
  { name: "suggest_annotations", title: "Suggest tool annotations",
    description: "List a server's tools and suggest danger annotations (readOnlyHint, destructiveHint, idempotentHint, openWorldHint) for each, as code for the TypeScript or Python MCP SDK, flagging annotations that contradict a tool's name. Suggestions to review, not decisions.",
    inputSchema: { type: "object", properties: { target: TARGET, format: { type: "string", enum: ["ts", "py", "json"], default: "ts" } }, required: ["target"], additionalProperties: false },
    annotations: RO(true) },
  { name: "diff_against_lock", title: "Find breaking or silent tool changes",
    description: "Compare a server's current tools with a saktum.lock.json file (from saktum snapshot): breaking changes, changes to review (descriptions, annotations), additions, and the version bump they need.",
    inputSchema: { type: "object", properties: { lock_path: { type: "string", description: "Path to the lock file", maxLength: 500 }, target: TARGET }, required: ["lock_path", "target"], additionalProperties: false },
    outputSchema: { type: "object", properties: { semver: { type: "string", enum: ["major", "minor", "patch", "none"] }, summary: { type: "string" },
      changes: { type: "array", items: { type: "object", properties: { tool: { type: "string" }, kind: { type: "string" }, detail: { type: "string" } }, required: ["tool", "kind", "detail"] } } }, required: ["semver", "summary", "changes"] },
    annotations: RO(true) },
  { name: "generate_docs", title: "Generate tool documentation",
    description: "Write a Markdown tools table and ready-to-paste configuration for Claude Desktop, Cursor and VS Code for a server.",
    inputSchema: { type: "object", properties: { target: TARGET, name: { type: "string", maxLength: 80 } }, required: ["target"], additionalProperties: false },
    annotations: RO(true) },
  { name: "explain_check", title: "Explain a check",
    description: "Explain one Saktum check: what it tests, why it matters, how to fix a failure, the standard behind it and when it runs.",
    inputSchema: { type: "object", properties: { check_id: { type: "string", description: "For example sec.description.hidden-instructions", maxLength: 100 } }, required: ["check_id"], additionalProperties: false },
    annotations: RO(false) },
  { name: "list_checks", title: "List all checks",
    description: "List every Saktum check with its area, severity and when it runs.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: RO(false) }
];

type Out = { content: { type: "text"; text: string }[]; structuredContent?: Record<string, unknown>; isError?: boolean };
const text = (t: string, structured?: Record<string, unknown>): Out => ({ content: [{ type: "text", text: t }], ...(structured ? { structuredContent: structured } : {}) });
const listTools = async (target: Target) => { const s = await connect(target); try { return { tools: await s.listTools(), server: s.serverInfo as Record<string, unknown> | undefined }; } finally { await s.close(); } };

export async function handleSaktumTool(name: string, args: Record<string, unknown>, packs: LoadedPack[]): Promise<Out> {
  try {
    switch (name) {
      case "check_server": {
        const r = await runTrustCheck(targetOf(args.target), { packs, mode: args.active === true ? "active" : "passive" });
        const failedChecks = r.findings.filter((f) => f.status === "fail" && !f.suppressed).map((f) => ({ check: f.check, severity: f.severity, message: sanitizeText(f.message ?? "", 400), ...(f.fix ? { fix: sanitizeText(f.fix, 300) } : {}) }));
        const card = trustCard(r);
        const s = { trustGrade: r.grade ?? null, readinessGrade: r.readiness?.grade ?? null, summary: r.summary ?? [], trustCard: card, failedChecks, scope: scopeOfRun(r) };
        const lines = [`Trust ${s.trustGrade ?? "-"} \u00b7 agent readiness ${s.readinessGrade ?? "-"}`, ...s.summary, "", ...card.map((c) => `${c.dimension}: ${c.mark} ${c.text}`),
          ...(failedChecks.length ? ["", "Failed checks:", ...failedChecks.map((f) => `- [${f.severity}] ${f.check}: ${f.message}${f.fix ? ` Fix: ${f.fix}` : ""}`)] : [])];
        return text(lines.join("\n"), s);
      }
      case "suggest_annotations": {
        const fmt = args.format === "py" || args.format === "json" ? args.format : "ts";
        return text(renderFix((await listTools(targetOf(args.target))).tools, fmt));
      }
      case "diff_against_lock": {
        if (typeof args.lock_path !== "string") throw new Error("lock_path is required");
        const before = JSON.parse(readFileSync(args.lock_path, "utf8")) as ToolsLock;
        const d = diffLocks(before, { tools: (await listTools(targetOf(args.target))).tools });
        return text([...d.changes.map((c) => `${c.kind}: ${c.tool}: ${c.detail}`), d.summary].join("\n"), { semver: d.semver, summary: d.summary, changes: d.changes });
      }
      case "generate_docs": {
        const target = targetOf(args.target);
        const { tools, server } = await listTools(target);
        const nm = typeof args.name === "string" && args.name ? args.name : String(server?.["name"] ?? "server");
        return text(docsFor(tools, nm, target.kind === "stdio" ? { command: target.command, args: target.args } : { url: target.url }));
      }
      case "explain_check": {
        const id = String(args.check_id ?? "");
        for (const { pack } of packs) {
          const c = pack.checks.find((x) => x.id === id);
          if (c) return text([`${c.id}: ${c.title}`, `Area: ${pack.category}. Severity: ${c.severity}. Runs: ${c.safety === "active" ? "with --active only" : "every run"}${c.appliesTo?.transports ? ` (${c.appliesTo.transports.join(", ")} servers)` : ""}.`,
            `Fix: ${c.fix}`, ...(c.references?.length ? [`References: ${c.references.join("; ")}`] : []), ...(c.normative?.length ? [`Standard: ${c.normative.map((n) => `${n.source}${n.clause ? `, ${n.clause}` : ""} (${n.level})`).join("; ")}`] : [])].join("\n"));
        }
        return { ...text(`No check named ${sanitizeText(id, 100)}. Use list_checks to see them all.`), isError: true };
      }
      case "list_checks": return text(checksTable(packs));
      default: return { ...text(`Unknown tool: ${sanitizeText(name, 60)}`), isError: true };
    }
  } catch (e) {
    return { ...text(`Saktum could not complete ${sanitizeText(name, 60)}: ${sanitizeText((e as Error).message, 400)}`), isError: true };
  }
}

export async function startMcpServer(packs: LoadedPack[]): Promise<void> {
  const server = new Server({ name: "saktum-check", version: ENGINE_VERSION }, { capabilities: { tools: {} },
    instructions: "Saktum Check tests MCP servers. Use check_server to grade a server, suggest_annotations to fix missing annotations, diff_against_lock before releasing changes, and explain_check for any finding. Local targets are started on this machine; use active only for servers the user owns." });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: SAKTUM_TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    if (!SAKTUM_TOOLS.some((t) => t.name === req.params.name)) {
      const { McpError, ErrorCode } = await import("@modelcontextprotocol/sdk/types.js");
      throw new McpError(ErrorCode.InvalidParams, `Unknown tool: ${sanitizeText(req.params.name, 60)}`);
    }
    return handleSaktumTool(req.params.name, (req.params.arguments ?? {}) as Record<string, unknown>, packs) as never;
  });
  // Stay alive until the client disconnects: the CLI exits when a command's action returns.
  const closed = new Promise<void>((resolve) => { server.onclose = () => resolve(); process.stdin.on("end", () => resolve()); });
  await server.connect(new StdioServerTransport());
  await closed;
}
