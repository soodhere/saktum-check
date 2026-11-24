// saktum lint (v0.4): static checks on tool registrations in source code, before the server ever runs.
// Only files that import an MCP SDK are examined, so unrelated `.tool(` calls are never flagged.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { extname, join, relative } from "node:path";

export interface LintFinding { file: string; line: number; tool: string; check: string; severity: "error" | "warning"; message: string; fix: string }
const SKIP = new Set(["node_modules", ".git", "dist", "build", ".venv", "venv", "__pycache__", ".next", "coverage"]);
const NAME_OK = /^[a-zA-Z0-9_-]{1,64}$/;

export function sourceFiles(root: string, max = 2000): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    if (out.length >= max) return;
    let entries: string[] = [];
    try { entries = readdirSync(d); } catch { return; }
    for (const e of entries) {
      if (SKIP.has(e) || e.startsWith(".")) continue;
      const p = join(d, e);
      let s; try { s = statSync(p); } catch { continue; }
      if (s.isDirectory()) walk(p);
      else if ([".ts", ".mts", ".js", ".mjs", ".cjs", ".py"].includes(extname(p)) && !p.endsWith(".d.ts") && s.size < 2_000_000) out.push(p);
    }
  };
  statSync(root).isFile() ? out.push(root) : walk(root);
  return out;
}

const lineOf = (text: string, index: number) => text.slice(0, index).split("\n").length;

export function lintSource(text: string, file: string): LintFinding[] {
  const out: LintFinding[] = [];
  const add = (index: number, tool: string, check: string, severity: LintFinding["severity"], message: string, fix: string) => out.push({ file, line: lineOf(text, index), tool, check, severity, message, fix });
  const checkName = (i: number, name: string) => { if (!NAME_OK.test(name)) add(i, name, "lint.name", "error", `Tool name "${name.slice(0, 80)}" is not 1 to 64 letters, digits, underscores or hyphens; many model providers reject it.`, "Rename the tool, for example get_order."); };
  if (file.endsWith(".py")) {
    if (!/\b(FastMCP|from mcp\b|import mcp\b|fastmcp)/.test(text)) return out;
    const re = /^[ \t]*@\w+\.tool\b(\(([\s\S]*?)\))?\s*\n(?:[ \t]*@[^\n]*\n)*[ \t]*(?:async\s+)?def\s+(\w+)\s*\(/gm;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) {
      const args = m[2] ?? "", fn = m[3]!;
      const name = /\bname\s*=\s*["']([^"']+)["']/.exec(args)?.[1] ?? fn;
      checkName(m.index, name);
      if (!/\bannotations\s*=/.test(args)) add(m.index, name, "lint.annotations", "warning", `Tool ${name} declares no annotations, so clients cannot warn before risky actions.`, "Add annotations=ToolAnnotations(readOnlyHint=..., destructiveHint=...) (saktum fix --format py writes them).");
      const after = text.slice(m.index + m[0].length);
      const doc = /^[^)]*\)[^:]*:\s*\n\s*(?:"""([\s\S]*?)"""|'''([\s\S]*?)''')/.exec(after);
      const desc = /\bdescription\s*=\s*["']([^"']*)["']/.exec(args)?.[1] ?? doc?.[1] ?? doc?.[2] ?? "";
      if (desc.trim().length < 20) add(m.index, name, "lint.description", "warning", `Tool ${name} has ${desc.trim() ? "a very short" : "no"} description, so agents may not know when to use it.`, "Add a one- or two-sentence docstring: what it does and when to use it.");
    }
  } else {
    if (!/@modelcontextprotocol\/sdk|fastmcp|McpServer|mcp-framework/.test(text)) return out;
    const re = /\.(registerTool|tool)\(\s*(["'`])([^"'`]+)\2\s*,/g;
    let m: RegExpExecArray | null;
    const starts: { i: number; kind: string; name: string; end: number }[] = [];
    while ((m = re.exec(text))) starts.push({ i: m.index, kind: m[1]!, name: m[3]!, end: m.index + m[0].length });
    starts.forEach((s, k) => {
      const block = text.slice(s.end, Math.min(starts[k + 1]?.i ?? text.length, s.end + 3000));
      checkName(s.i, s.name);
      if (!/\bannotations\b|readOnlyHint|destructiveHint/.test(block)) add(s.i, s.name, "lint.annotations", "warning", `Tool ${s.name} declares no annotations, so clients cannot warn before risky actions.`, "Add annotations: { readOnlyHint, destructiveHint, idempotentHint, openWorldHint } (saktum fix writes them).");
      const desc = s.kind === "registerTool" ? /\bdescription\s*:\s*(["'`])([\s\S]*?)\1/.exec(block)?.[2] : /^\s*(["'`])([\s\S]*?)\1\s*,/.exec(block)?.[2];
      if ((desc ?? "").trim().length < 20) add(s.i, s.name, "lint.description", "warning", `Tool ${s.name} has ${desc?.trim() ? "a very short" : "no"} description, so agents may not know when to use it.`, "Add a one- or two-sentence description: what it does and when to use it.");
    });
  }
  return out;
}

export function lintPaths(paths: string[], cwd: string): LintFinding[] {
  return paths.flatMap((p) => sourceFiles(p)).flatMap((f) => lintSource(readFileSync(f, "utf8"), relative(cwd, f) || f));
}

export function lintSarif(findings: LintFinding[], version: string): Record<string, unknown> {
  const rules = [...new Set(findings.map((f) => f.check))];
  return { $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0", runs: [{
    tool: { driver: { name: "Saktum lint", version, informationUri: "https://github.com/soodhere/saktum-check", rules: rules.map((id) => ({ id, shortDescription: { text: findings.find((f) => f.check === id)!.fix } })) } },
    results: findings.map((f) => ({ ruleId: f.check, level: f.severity, message: { text: `${f.message} ${f.fix}` }, locations: [{ physicalLocation: { artifactLocation: { uri: f.file.replace(/\\/g, "/") }, region: { startLine: f.line } } }] })) }] };
}
