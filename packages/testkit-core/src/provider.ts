// The provider toolkit (v0.3): help MCP server providers fix, protect compatibility, document and publish.
// Suggestions are always labelled as suggestions: Saktum proposes, the provider decides.
import { canonicalize, sha256Tag } from "@saktum/sign";
import type { ToolDef } from "@saktum/transports";
import { capabilityProfile } from "./capabilities.js";
import { contextCost } from "./analysers.js";
import { sanitizeText } from "./safe.js";

// ---------- saktum fix: annotation suggestions ----------

const words = (name: string) => name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
const READ = new Set(["get", "list", "read", "search", "find", "fetch", "query", "describe", "show", "view", "lookup", "count", "check", "status", "retrieve", "browse", "inspect", "resolve", "validate", "analyze", "analyse", "summarize", "summarise", "explain", "compare", "preview", "info", "stats", "download", "export", "diff", "log", "history", "whoami", "ping", "health", "extract", "crawl", "scrape", "research", "map", "summary", "lookup", "tail", "watch"]);
const DESTROY = new Set(["delete", "remove", "drop", "purge", "destroy", "reset", "revoke", "cancel", "terminate", "kill", "wipe", "truncate", "overwrite", "uninstall", "unpublish", "archive"]);
const WRITE = new Set(["create", "add", "insert", "update", "set", "put", "patch", "edit", "write", "save", "upload", "send", "post", "publish", "deploy", "run", "execute", "exec", "start", "stop", "restart", "move", "rename", "merge", "commit", "push", "install", "enable", "disable", "assign", "invite", "approve", "pay", "charge", "refund", "transfer", "book", "order", "replace", "import", "sync", "trigger", "schedule", "close", "open", "submit", "apply", "generate", "upsert"]);
/** Verbs whose effect depends on context (open_file reads; open_pull_request creates): never used for suggestions or
 *  conflicts, so a correct annotation is never second-guessed. Found on a reference server (open_nodes). */
const AMBIGUOUS = new Set(["open", "close", "run", "start", "stop", "restart", "generate", "apply", "import", "sync", "trigger", "schedule", "submit", "execute", "exec", "export", "download", "log", "watch", "tail", "map"]);
const IDEMPOTENT_WRITE = new Set(["set", "put", "update", "upsert", "enable", "disable", "replace"]);

export interface AnnotationSuggestion {
  tool: string;
  current?: Record<string, unknown>;
  suggested?: { readOnlyHint: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean };
  reason: string;
  confidence: "likely" | "review";
  conflict?: string;
}

export function suggestAnnotations(tools: ToolDef[]): AnnotationSuggestion[] {
  const caps = capabilityProfile(tools).capabilities;
  const hasCap = (tool: string, c: string) => caps.some((x) => x.capability === c && x.tools.includes(sanitizeText(tool, 60)));
  return tools.map((t) => {
    const w = words(t.name);
    const verb = w.find((x) => !AMBIGUOUS.has(x) && (READ.has(x) || DESTROY.has(x) || WRITE.has(x)));
    const current = t.annotations && Object.keys(t.annotations).length ? (t.annotations as Record<string, unknown>) : undefined;
    const openWorld = hasCap(t.name, "network") || hasCap(t.name, "untrusted-content") || hasCap(t.name, "sends-messages") ? true : undefined;
    let suggested: AnnotationSuggestion["suggested"];
    let reason: string;
    if (verb && DESTROY.has(verb)) { suggested = { readOnlyHint: false, destructiveHint: true, idempotentHint: verb === "delete" || verb === "remove" ? true : undefined, openWorldHint: openWorld }; reason = `"${verb}" usually deletes or overwrites data`; }
    else if (verb && WRITE.has(verb)) { suggested = { readOnlyHint: false, destructiveHint: false, idempotentHint: IDEMPOTENT_WRITE.has(verb) ? true : undefined, openWorldHint: openWorld }; reason = `"${verb}" usually changes data without destroying it`; }
    else if (verb && READ.has(verb)) { suggested = { readOnlyHint: true, openWorldHint: openWorld }; reason = `"${verb}" usually only reads`; }
    else { reason = "the name does not say whether it reads or changes data: decide and annotate it"; }
    const clean = suggested ? (Object.fromEntries(Object.entries(suggested).filter(([, v]) => v !== undefined)) as AnnotationSuggestion["suggested"]) : undefined;
    let conflict: string | undefined;
    if (current?.readOnlyHint === true && verb && (DESTROY.has(verb) || WRITE.has(verb))) conflict = `declared read-only, but "${verb}" suggests it changes data`;
    if (current?.destructiveHint === false && verb && DESTROY.has(verb)) conflict = `declared non-destructive, but "${verb}" suggests it deletes or overwrites`;
    return { tool: t.name, current, suggested: clean, reason, confidence: verb ? "likely" : "review", conflict };
  });
}

const tsValue = (o: Record<string, unknown>) => `{ ${Object.entries(o).map(([k, v]) => `${k}: ${v}`).join(", ")} }`;
const pyValue = (o: Record<string, unknown>) => `ToolAnnotations(${Object.entries(o).map(([k, v]) => `${k}=${v === true ? "True" : v === false ? "False" : v}`).join(", ")})`;

export function renderFix(tools: ToolDef[], format: "ts" | "py" | "json" = "ts"): string {
  const s = suggestAnnotations(tools);
  if (format === "json") return JSON.stringify(s, null, 2) + "\n";
  const todo = s.filter((x) => !x.current && x.suggested);
  const review = s.filter((x) => !x.current && !x.suggested);
  const conflicts = s.filter((x) => x.conflict);
  const lines: string[] = [];
  lines.push(`Saktum fix: annotation suggestions for ${tools.length} tools (review each before applying; Saktum suggests, you decide).`);
  lines.push(`${todo.length} to add, ${review.length} need your judgement, ${conflicts.length} possible conflict${conflicts.length === 1 ? "" : "s"}, ${s.filter((x) => x.current && !x.conflict).length} already annotated.`);
  lines.push("");
  if (format === "py") lines.push("# For the MCP Python SDK v1 (FastMCP); in v2, FastMCP was renamed MCPServer.", "from mcp.types import ToolAnnotations", "");
  for (const x of todo) {
    lines.push(format === "py"
      ? `# ${sanitizeText(x.tool, 60)}: ${x.reason}\n@mcp.tool(annotations=${pyValue(x.suggested!)})`
      : `// ${sanitizeText(x.tool, 60)}: ${x.reason}\nannotations: ${tsValue(x.suggested!)},`);
    lines.push("");
  }
  if (review.length) { lines.push(format === "py" ? "# Decide for these tools:" : "// Decide for these tools:"); for (const x of review) lines.push(`${format === "py" ? "#" : "//"}   ${sanitizeText(x.tool, 60)}: ${x.reason}`); lines.push(""); }
  if (conflicts.length) { lines.push(format === "py" ? "# Possible conflicts with your current annotations:" : "// Possible conflicts with your current annotations:"); for (const x of conflicts) lines.push(`${format === "py" ? "#" : "//"}   ${sanitizeText(x.tool, 60)}: ${x.conflict}`); lines.push(""); }
  const short = tools.filter((t) => (t.description ?? "").trim().length < 20);
  if (short.length) lines.push(`${format === "py" ? "#" : "//"} Also write a one-sentence description (what it does, when to use it) for: ${short.map((t) => sanitizeText(t.name, 40)).join(", ")}`);
  const cost = contextCost(tools);
  if (cost.contextCostTokens > 10_000) lines.push(`${format === "py" ? "#" : "//"} Context cost is ${cost.contextCostTokens.toLocaleString("en-US")} tokens per turn; the largest tools are ${cost.largestTools.slice(0, 3).map((x) => `${x.tool} (${x.tokens})`).join(", ")}: shorten their descriptions and schemas first.`);
  return lines.join("\n").trimEnd() + "\n";
}

// ---------- saktum snapshot / diff: tool lock file and breaking changes ----------

export interface ToolsLock { lockFormat: "0.1"; server?: Record<string, unknown>; createdAt: string; tools: (ToolDef & { hash: string })[] }

export function toolsLock(tools: ToolDef[], server?: Record<string, unknown>): ToolsLock {
  const sorted = [...tools].sort((a, b) => a.name.localeCompare(b.name));
  return { lockFormat: "0.1", server, createdAt: new Date().toISOString(), tools: sorted.map((t) => ({ ...t, hash: sha256Tag(canonicalize(t)) })) };
}

export interface ToolChange { tool: string; kind: "breaking" | "risky" | "addition" | "change"; detail: string }
type Obj = { type?: unknown; properties?: Record<string, Obj>; required?: string[]; enum?: unknown[]; additionalProperties?: unknown };
const typeOf = (s?: Obj) => JSON.stringify(s?.type ?? null);

function schemaChanges(tool: string, label: string, a: Obj | undefined, b: Obj | undefined, out: ToolChange[], forInput: boolean): void {
  if (!a && !b) return;
  if (a && !b) { out.push({ tool, kind: forInput ? "change" : "breaking", detail: `${label} schema removed` }); return; }
  if (!a && b) { out.push({ tool, kind: "addition", detail: `${label} schema added` }); return; }
  const pa = a!.properties ?? {}, pb = b!.properties ?? {};
  const ra = new Set(a!.required ?? []), rb = new Set(b!.required ?? []);
  for (const k of Object.keys(pa)) {
    if (!(k in pb)) { out.push({ tool, kind: "breaking", detail: `${label} field "${k}" removed` }); continue; }
    if (typeOf(pa[k]) !== typeOf(pb[k])) out.push({ tool, kind: "breaking", detail: `${label} field "${k}" changed type from ${typeOf(pa[k])} to ${typeOf(pb[k])}` });
    const ea = pa[k]!.enum, eb = pb[k]!.enum;
    if (Array.isArray(ea) && Array.isArray(eb)) {
      const removed = ea.filter((v) => !eb.some((w) => JSON.stringify(w) === JSON.stringify(v)));
      const added = eb.filter((v) => !ea.some((w) => JSON.stringify(w) === JSON.stringify(v)));
      if (removed.length) out.push({ tool, kind: forInput ? "breaking" : "change", detail: `${label} field "${k}" no longer allows ${removed.map((v) => JSON.stringify(v)).join(", ")}` });
      if (added.length) out.push({ tool, kind: forInput ? "addition" : "breaking", detail: `${label} field "${k}" now allows ${added.map((v) => JSON.stringify(v)).join(", ")}` });
    }
  }
  for (const k of Object.keys(pb)) if (!(k in pa)) out.push({ tool, kind: forInput && rb.has(k) ? "breaking" : "addition", detail: `${label} field "${k}" added${forInput && rb.has(k) ? " as required" : ""}` });
  if (forInput) for (const k of rb) if (!ra.has(k) && k in pa) out.push({ tool, kind: "breaking", detail: `input field "${k}" is now required` });
  if (!forInput) for (const k of ra) if (!rb.has(k) && k in pb) out.push({ tool, kind: "breaking", detail: `output field "${k}" is no longer guaranteed` });
  if (forInput && a!.additionalProperties !== false && b!.additionalProperties === false) out.push({ tool, kind: "breaking", detail: "input no longer accepts extra fields" });
}

export function diffLocks(a: { tools: ToolDef[] }, b: { tools: ToolDef[] }): { changes: ToolChange[]; semver: "major" | "minor" | "patch" | "none"; summary: string } {
  const out: ToolChange[] = [];
  const ma = new Map(a.tools.map((t) => [t.name, t])), mb = new Map(b.tools.map((t) => [t.name, t]));
  for (const [n] of ma) if (!mb.has(n)) out.push({ tool: n, kind: "breaking", detail: "tool removed" });
  for (const [n] of mb) if (!ma.has(n)) out.push({ tool: n, kind: "addition", detail: "tool added" });
  for (const [n, ta] of ma) {
    const tb = mb.get(n);
    if (!tb) continue;
    schemaChanges(n, "input", ta.inputSchema as Obj, tb.inputSchema as Obj, out, true);
    schemaChanges(n, "output", (ta as { outputSchema?: Obj }).outputSchema, (tb as { outputSchema?: Obj }).outputSchema, out, false);
    const aa = (ta.annotations ?? {}) as Record<string, unknown>, ab = (tb.annotations ?? {}) as Record<string, unknown>;
    if (aa.readOnlyHint === true && ab.readOnlyHint !== true) out.push({ tool: n, kind: "risky", detail: "no longer declared read-only: re-review before agents use it" });
    if (aa.destructiveHint !== true && ab.destructiveHint === true) out.push({ tool: n, kind: "risky", detail: "now declared destructive" });
    if (aa.openWorldHint !== true && ab.openWorldHint === true) out.push({ tool: n, kind: "risky", detail: "now reaches outside systems (openWorldHint)" });
    if ((ta.description ?? "") !== (tb.description ?? "")) out.push({ tool: n, kind: "risky", detail: "description changed: review it for new instructions to agents (silent tool changes, OWASP MCP03)" });
  }
  const has = (k: ToolChange["kind"]) => out.some((c) => c.kind === k);
  const semver = has("breaking") ? "major" : has("addition") ? "minor" : out.length ? "patch" : "none";
  const n = (k: ToolChange["kind"]) => out.filter((c) => c.kind === k).length;
  return { changes: out, semver, summary: out.length ? `${n("breaking")} breaking, ${n("risky")} to review, ${n("addition")} additions, ${n("change")} other changes; suggested version bump: ${semver}.` : "No changes to tools." };
}

// ---------- saktum docs: tools table and client configuration ----------

export function docsFor(tools: ToolDef[], name: string, launch: { command?: string; args?: string[]; url?: string }): string {
  const kind = (t: ToolDef) => { const a = (t.annotations ?? {}) as Record<string, unknown>; return a.readOnlyHint === true ? "reads only" : a.destructiveHint === true ? "can delete or overwrite" : a.readOnlyHint === false ? "changes data" : "not declared"; };
  const firstSentence = (d?: string) => sanitizeText((d ?? "").trim().split(/(?<=[.!?])\s/)[0] ?? "", 160).replace(/\|/g, "/");
  const req = (t: ToolDef) => (((t.inputSchema ?? {}) as Obj).required ?? []).join(", ") || "none";
  const id = name.replace(/[^a-zA-Z0-9_-]/g, "-").replace(/^-+|-+$/g, "") || "server";
  const local = launch.url ? undefined : { command: launch.command, args: launch.args ?? [] };
  const lines = [`## Tools`, "", "| Tool | What it does | Effect | Required arguments |", "| --- | --- | --- | --- |",
    ...tools.map((t) => `| \`${sanitizeText(t.name, 60)}\` | ${firstSentence(t.description)} | ${kind(t)} | ${req(t)} |`), "",
    `## Use it`, "", "**Claude Desktop** (`claude_desktop_config.json`) and **Cursor** (`.cursor/mcp.json`):", "", "```json",
    JSON.stringify({ mcpServers: { [id]: local ?? { url: launch.url } } }, null, 2), "```", "", "**VS Code** (`.vscode/mcp.json`):", "", "```json",
    JSON.stringify({ servers: { [id]: local ? { type: "stdio", ...local } : { type: "http", url: launch.url } } }, null, 2), "```", "",
    `_Generated by Saktum Check. Check the exact configuration format in each client's documentation._`];
  return lines.join("\n") + "\n";
}

// ---------- client compatibility (informational) ----------

/** Constraints common to model providers' function calling (tool names of 1 to 64 letters, digits, underscores and
 *  hyphens), which clients apply when they pass MCP tools to a model, often after adding a server prefix. */
export function clientCompatibility(tools: ToolDef[]): string[] {
  const issues: string[] = [];
  const bad = tools.filter((t) => !/^[a-zA-Z0-9_-]{1,64}$/.test(t.name));
  if (bad.length) issues.push(`${bad.length} tool name(s) use characters or a length that many model providers reject in function names (allowed: 1 to 64 letters, digits, underscores and hyphens): ${bad.slice(0, 5).map((t) => sanitizeText(t.name, 60)).join(", ")}`);
  const long = tools.filter((t) => t.name.length > 40 && t.name.length <= 64);
  if (long.length) issues.push(`${long.length} tool name(s) are over 40 characters; clients that prefix the server name may exceed the 64-character limit: ${long.slice(0, 3).map((t) => sanitizeText(t.name, 60)).join(", ")}`);
  if (tools.length > 40) issues.push(`${tools.length} tools: some clients limit how many tools they load or show; check your target clients and consider grouping or splitting the server`);
  return issues;
}

// ---------- saktum allowlist: evidence-based allowlists for MCP firewalls and gateways ----------

const GRADES = ["A", "B", "C", "D", "F"];
const atLeast = (g: string | null | undefined, min: string) => g != null && GRADES.indexOf(g) <= GRADES.indexOf(min);

export interface AllowlistEntry { server: string; version?: string; transport: string; target: string; toolsFingerprint?: string; toolCount?: number; trustGrade: string | null; readinessGrade: string | null; checkedAt: string; checkedWith: string; signedBy?: string }
export interface Allowlist { allowlistFormat: "0.1"; generatedAt: string; criteria: { minTrust: string; minReadiness: string; noFailedCritical: boolean }; allowed: AllowlistEntry[]; excluded: { server: string; reason: string }[]; note: string }

/** Keep the checked servers that meet the criteria, pinned to the exact tool fingerprint that was checked. */
export function buildAllowlist(results: { result: { target: { description: string; transport: string; serverInfo?: Record<string, unknown>; toolsFingerprint?: string; toolCount?: number }; grade?: string | null; readiness?: { grade: string | null } | null; findings: { severity: string; status: string; suppressed?: unknown }[]; run: { startedAt: string }; tool: { version: string } }; signedBy?: string }[], criteria: Allowlist["criteria"]): Allowlist {
  const allowed: AllowlistEntry[] = [], excluded: Allowlist["excluded"] = [];
  for (const { result: r, signedBy } of results) {
    const server = String(r.target.serverInfo?.["name"] ?? r.target.description);
    const why: string[] = [];
    if (!atLeast(r.grade, criteria.minTrust)) why.push(`trust ${r.grade ?? "not graded"} is below ${criteria.minTrust}`);
    if (!atLeast(r.readiness?.grade, criteria.minReadiness)) why.push(`agent readiness ${r.readiness?.grade ?? "not graded"} is below ${criteria.minReadiness}`);
    if (criteria.noFailedCritical && r.findings.some((f) => f.severity === "critical" && f.status === "fail" && !f.suppressed)) why.push("a critical check failed");
    if (!r.target.toolsFingerprint) why.push("no tool fingerprint to pin");
    if (why.length) { excluded.push({ server, reason: why.join("; ") }); continue; }
    allowed.push({ server, version: r.target.serverInfo?.["version"] as string | undefined, transport: r.target.transport, target: r.target.description, toolsFingerprint: r.target.toolsFingerprint,
      toolCount: r.target.toolCount, trustGrade: r.grade ?? null, readinessGrade: r.readiness?.grade ?? null, checkedAt: r.run.startedAt, checkedWith: `Saktum Check ${r.tool.version}`, signedBy });
  }
  return { allowlistFormat: "0.1", generatedAt: new Date().toISOString(), criteria, allowed, excluded,
    note: "Allow each server only while its tools match toolsFingerprint; re-check after any change (saktum diff). Self-tested evidence (assurance L1) unless stated otherwise." };
}

// ---------- saktum attest: a compact attestation for READMEs and registry listings ----------

export interface Attestation {
  attestationFormat: "0.1";
  subject: { server: string; version?: string; transport: string; target: string; toolsFingerprint?: string; toolCount?: number };
  claims: { trustGrade: string | null; readinessGrade: string | null; trustScore: number | null; readinessScore: number | null;
    evidence: { responds: boolean; conformant: boolean; safeByDefault: boolean; agentReady: boolean }; assuranceLevel: string };
  checkedAt: string; checkedWith: string; resultDigest: string; note: string;
}

/** Build an attestation from a verified signed result. Maturity evidence L1 to L4 is measured from the run itself;
 *  L5 also needs supply-chain evidence (provenance, install scripts), which the census adds from registry metadata. */
export function buildAttestation(r: { target: { description: string; transport: string; serverInfo?: Record<string, unknown>; toolsFingerprint?: string; toolCount?: number };
  grade?: string | null; scores: { overall: number | null }; readiness?: { grade: string | null; score: number } | null; assuranceLevel?: string;
  findings: { pack: string; status: string; scored: boolean; suppressed?: unknown }[]; run: { startedAt: string }; tool: { version: string } }): Attestation {
  const failedIn = (pack: string) => r.findings.some((f) => f.pack === pack && f.status === "fail" && f.scored && !f.suppressed);
  const responds = r.grade !== null && r.grade !== undefined && (r.target.toolCount ?? 0) > 0;
  const conformant = responds && !failedIn("conformance");
  const safeByDefault = conformant && !failedIn("security");
  return {
    attestationFormat: "0.1",
    subject: { server: String(r.target.serverInfo?.["name"] ?? r.target.description), version: r.target.serverInfo?.["version"] as string | undefined, transport: r.target.transport, target: r.target.description, toolsFingerprint: r.target.toolsFingerprint, toolCount: r.target.toolCount },
    claims: { trustGrade: r.grade ?? null, readinessGrade: r.readiness?.grade ?? null, trustScore: r.scores.overall, readinessScore: r.readiness?.score ?? null,
      evidence: { responds, conformant, safeByDefault, agentReady: safeByDefault && (r.readiness?.score ?? 0) >= 90 }, assuranceLevel: r.assuranceLevel ?? "L1" },
    checkedAt: r.run.startedAt, checkedWith: `Saktum Check ${r.tool.version}`, resultDigest: sha256Tag(canonicalize(r)),
    note: "Self-tested (L1) unless stated otherwise: the signature proves the attestation was not changed, not that the run was independent. Valid for the tools matching toolsFingerprint."
  };
}
