// saktum scan-config (v0.4): look at an agent set-up as a whole. Which servers a client loads, what they cost in
// context every turn, which tools overlap across servers, and which servers are not on an allowlist.
// Pure functions here; the CLI handles files, consent and running the checks. Secrets in configuration are never output.
import type { ToolDef } from "@saktum/transports";
import { contextCost } from "./analysers.js";
import { sanitizeText } from "./safe.js";

export interface ConfiguredServer { client: string; file: string; name: string; command?: string; args?: string[]; env?: Record<string, string>; url?: string; headers?: Record<string, string>; disabled?: boolean }

/** Parse a client configuration: mcpServers (Claude Desktop, Claude Code, Cursor) or servers (VS Code). */
export function parseClientConfig(text: string, client: string, file: string): ConfiguredServer[] {
  let j: Record<string, unknown>;
  try { j = JSON.parse(text.replace(/^\uFEFF/, "")) as Record<string, unknown>; } catch { return []; }
  const block = (j.mcpServers ?? j.servers ?? (j.mcp as Record<string, unknown> | undefined)?.servers) as Record<string, Record<string, unknown>> | undefined;
  if (!block || typeof block !== "object") return [];
  return Object.entries(block).flatMap(([name, v]) => {
    if (!v || typeof v !== "object") return [];
    const str = (x: unknown) => (typeof x === "string" ? x : undefined);
    const rec = (x: unknown) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.entries(x as Record<string, unknown>).filter(([, y]) => typeof y === "string")) as Record<string, string> : undefined);
    const url = str(v.url) ?? str(v.serverUrl);
    const command = str(v.command);
    if (!url && !command) return [];
    return [{ client, file, name: sanitizeText(name, 80), command, args: Array.isArray(v.args) ? v.args.filter((a): a is string => typeof a === "string") : [], env: rec(v.env), url, headers: rec(v.headers), disabled: v.disabled === true || v.enabled === false }];
  });
}

/** Known configuration locations, per client and operating system (verify against each client's documentation). */
export function configLocations(home: string, cwd: string, platform: string, appData?: string): { client: string; file: string }[] {
  const claudeDesktop = platform === "win32" ? `${appData ?? `${home}\\AppData\\Roaming`}\\Claude\\claude_desktop_config.json`
    : platform === "darwin" ? `${home}/Library/Application Support/Claude/claude_desktop_config.json` : `${home}/.config/Claude/claude_desktop_config.json`;
  const sep = platform === "win32" ? "\\" : "/";
  return [
    { client: "Claude Desktop", file: claudeDesktop },
    { client: "Claude Code", file: `${home}${sep}.claude.json` },
    { client: "Claude Code (project)", file: `${cwd}${sep}.mcp.json` },
    { client: "Cursor", file: `${home}${sep}.cursor${sep}mcp.json` },
    { client: "Cursor (project)", file: `${cwd}${sep}.cursor${sep}mcp.json` },
    { client: "VS Code (workspace)", file: `${cwd}${sep}.vscode${sep}mcp.json` }
  ];
}

const words = (s: string) => new Set(s.toLowerCase().replace(/[^a-z0-9 ]/g, " ").split(/\s+/).filter((w) => w.length > 3));
const jaccard = (a: Set<string>, b: Set<string>) => { const i = [...a].filter((x) => b.has(x)).length; return i / Math.max(1, a.size + b.size - i); };

export interface ServerScan { name: string; client: string; trustGrade: string | null; readinessGrade: string | null; tools: ToolDef[]; tokens: number; fingerprint?: string; error?: string; target?: string; capabilities?: string[]; lethalTrifecta?: boolean; failedSeverities?: string[] }
export interface SetupReport {
  machine?: string;
  servers: { name: string; client: string; trustGrade: string | null; readinessGrade: string | null; toolCount: number; tokens: number; error?: string; onAllowlist?: boolean; target?: string; fingerprint?: string; capabilities?: string[]; lethalTrifecta?: boolean; failedSeverities?: string[] }[];
  totalTokens: number; monthlyCostUsd: number; assumptions: { turnsPerDay: number; pricePerMTokUsd: number };
  duplicates: { tool: string; servers: string[] }[]; overlaps: { a: string; b: string; similarity: number }[];
  unvetted: string[]; recommendations: string[];
}

export function analyseSetup(scans: ServerScan[], o: { turnsPerDay: number; pricePerMTokUsd: number; allowlistFingerprints?: Set<string> }): SetupReport {
  const ok = scans.filter((s) => !s.error);
  const totalTokens = ok.reduce((a, s) => a + s.tokens, 0);
  const monthlyCostUsd = Math.round(((totalTokens * o.turnsPerDay * 30 * o.pricePerMTokUsd) / 1e6) * 100) / 100;
  const byName = new Map<string, string[]>();
  for (const s of ok) for (const t of s.tools) byName.set(t.name, [...(byName.get(t.name) ?? []), s.name]);
  const duplicates = [...byName].filter(([, v]) => new Set(v).size > 1).map(([tool, servers]) => ({ tool, servers: [...new Set(servers)] }));
  const overlaps: SetupReport["overlaps"] = [];
  for (let i = 0; i < ok.length; i++) for (let j = i + 1; j < ok.length; j++) for (const ta of ok[i]!.tools) for (const tb of ok[j]!.tools) {
    if (ta.name === tb.name) continue;
    const wa = words(`${ta.name.replace(/[_-]/g, " ")} ${ta.description ?? ""}`), wb = words(`${tb.name.replace(/[_-]/g, " ")} ${tb.description ?? ""}`);
    if (wa.size < 4 || wb.size < 4) continue;
    const sim = jaccard(wa, wb);
    if (sim >= 0.6) overlaps.push({ a: `${ok[i]!.name}/${ta.name}`, b: `${ok[j]!.name}/${tb.name}`, similarity: Math.round(sim * 100) / 100 });
  }
  const unvetted = o.allowlistFingerprints ? ok.filter((s) => !s.fingerprint || !o.allowlistFingerprints!.has(s.fingerprint)).map((s) => s.name) : [];
  const rec: string[] = [];
  const heavy = [...ok].sort((a, b) => b.tokens - a.tokens).filter((s) => s.tokens > 10_000);
  for (const s of heavy.slice(0, 3)) rec.push(`${s.name} costs ${s.tokens.toLocaleString("en-US")} tokens every turn: disable it when you do not need it, or ask its maintainer to trim tool definitions.`);
  if (duplicates.length) rec.push(`${duplicates.length} tool name(s) appear in more than one server (for example ${duplicates[0]!.tool}): keep one server for each job; duplicates waste context and make tool choice ambiguous.`);
  if (overlaps.length) rec.push(`${overlaps.length} pair(s) of tools in different servers look like they do the same job (for example ${overlaps[0]!.a} and ${overlaps[0]!.b}).`);
  for (const s of ok.filter((x) => x.trustGrade && "CDF".includes(x.trustGrade))) rec.push(`${s.name} earns trust ${s.trustGrade}: review its findings before letting an agent use it (saktum check).`);
  if (unvetted.length) rec.push(`${unvetted.length} server(s) are not on your allowlist: ${unvetted.slice(0, 5).join(", ")}.`);
  return {
    servers: scans.map((s) => ({ name: s.name, client: s.client, trustGrade: s.trustGrade, readinessGrade: s.readinessGrade, toolCount: s.tools.length, tokens: s.tokens, target: s.target, fingerprint: s.fingerprint, capabilities: s.capabilities, lethalTrifecta: s.lethalTrifecta, failedSeverities: s.failedSeverities, ...(s.error ? { error: s.error } : {}), ...(o.allowlistFingerprints ? { onAllowlist: !unvetted.includes(s.name) && !s.error } : {}) })),
    totalTokens, monthlyCostUsd, assumptions: { turnsPerDay: o.turnsPerDay, pricePerMTokUsd: o.pricePerMTokUsd }, duplicates, overlaps: overlaps.slice(0, 20), unvetted, recommendations: rec
  };
}

export function renderSetup(r: SetupReport): string {
  const L: string[] = ["Saktum scan-config: your agent set-up as a whole", ""];
  L.push(`  ${r.servers.length} servers \u00b7 ${r.totalTokens.toLocaleString("en-US")} tokens of tool definitions every turn \u00b7 about $${r.monthlyCostUsd.toLocaleString("en-US")} a month at ${r.assumptions.turnsPerDay} turns a day and $${r.assumptions.pricePerMTokUsd} per million input tokens`, "");
  for (const s of r.servers) L.push(`  ${s.name.padEnd(28)} ${s.client.padEnd(22)} ${s.error ? `could not check: ${s.error}` : `trust ${s.trustGrade ?? "-"} \u00b7 readiness ${s.readinessGrade ?? "-"} \u00b7 ${s.toolCount} tools \u00b7 ${s.tokens.toLocaleString("en-US")} tokens${s.onAllowlist === false ? " \u00b7 not on allowlist" : ""}`}`);
  if (r.duplicates.length) { L.push("", "DUPLICATE TOOLS"); for (const d of r.duplicates.slice(0, 10)) L.push(`  ${d.tool}: ${d.servers.join(", ")}`); }
  if (r.overlaps.length) { L.push("", "TOOLS THAT LOOK ALIKE"); for (const o of r.overlaps.slice(0, 10)) L.push(`  ${o.a} \u2248 ${o.b} (${Math.round(o.similarity * 100)}% similar)`); }
  if (r.recommendations.length) { L.push("", "RECOMMENDATIONS"); for (const x of r.recommendations) L.push(`  - ${x}`); }
  return L.join("\n") + "\n";
}

export { contextCost as toolsContextCost };
