// Named analysers: the only place check logic lives. Packs reference them by name; they are versioned with the engine.
// Each returns a verdict for one check, with a sanitised excerpt as evidence. They must never throw on hostile input.
import type { CallOutcome, HttpProbe, Session, Target, ToolDef } from "@saktum/transports";
import { sha256Tag } from "@saktum/sign";
import { compileUntrustedSchema } from "./contracts.js";
import { INVISIBLE, sanitizeText } from "./safe.js";
import { clientCompatibility } from "./provider.js";
import { authAnalysers, AUTH_NEEDS } from "./auth.js";
import { leakageAnalysers, LEAKAGE_NEEDS } from "./leakage.js";
import { perfAnalysers, PERF_NEEDS } from "./perf.js";
import { functionalAnalysers, FUNCTIONAL_NEEDS } from "./functional-checks.js";
import type { FunctionalReport } from "./functional.js";
import type { LoadProfile } from "./load.js";

export interface Verdict { status: "pass" | "fail" | "info" | "inconclusive" | "skipped"; message: string; subject?: string; evidence?: { hash?: string; excerpt?: string } }

/** Everything a check may look at. The session is absent when a remote server requires sign-in and no token was given. */
export interface AnalyserContext {
  session?: Session;
  tools: ToolDef[];
  target?: Target;
  mode?: "passive" | "active";
  /** Raw HTTP answers to initialize: without credentials, and with a deliberately invalid bearer token. */
  http?: { unauthenticated?: HttpProbe; invalidToken?: HttpProbe; foreignOrigin?: HttpProbe; userSuppliedAuth: boolean };
  /** Responses to safe probe calls, shared by several checks. */
  probes?: { unknownTool?: CallOutcome; invalidArgs?: { tool: string; outcome: CallOutcome } };
  perf?: { initMs?: number; listMs?: number; listBytes?: number; rssMb?: number; cpuPct?: number; burst?: { requests: number; ok: number; rateLimited: number; errors: number; p95Ms: number } };
  /** User-set price per million input tokens, for the cost estimate (reported only). */
  pricePerMTokUsd?: number;
  /** v0.2: smoke calls and invalid-argument probes (active runs only). */
  functional?: FunctionalReport;
  /** v0.2: latency percentiles and concurrency levels (active runs only). */
  load?: LoadProfile;
}
export type Analyser = (ctx: AnalyserContext) => Verdict | Promise<Verdict>;
/** What an analyser needs: nothing beyond the target, an MCP session, or the tool list. Default: tools. */
export type AnalyserNeeds = "none" | "session" | "tools";

const textOf = (t: ToolDef): string => `${t.name ?? ""}\n${t.description ?? ""}\n${JSON.stringify(t.inputSchema ?? {})}`;
const listNames = (tools: ToolDef[], max = 5): string => {
  const names = tools.map((t) => sanitizeText(t.name, 60));
  return names.slice(0, max).join(", ") + (names.length > max ? ` and ${names.length - max} more` : "");
};
const evidenceFor = (tool: ToolDef | undefined, text?: string) => tool ? { hash: sha256Tag(JSON.stringify(tool)), excerpt: sanitizeText(text ?? tool.description ?? tool.name, 200) } : undefined;

/** Escape sequences and control characters (terminal attacks) anywhere in a tool's name, description or schema. */
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/;

/** Conservative patterns of instructions aimed at the agent; tuned for few false positives (see corpus results). */
const HIDDEN_INSTRUCTION = [
  /ignore (all |any )?(previous|prior|above) (instructions|messages)/i,
  // Concealment, not guidance: honest advice such as "do not tell the user it is in their account" must not match.
  /\b(do not|don['’]t|never) tell the user\s*[.!]/i,
  /\bwithout (telling|informing|alerting|notifying) the user\b/i,
  /\b(do not|don['’]t|never) (mention|reveal|disclose) (this|these) (instructions?|steps?|tool|call)\b/i,
  /\bhide (this|it|the (action|request|call|upload)) from the user\b/i,
  /<\s*important\s*>/i,
  // Manipulating the agent's instructions, not merely mentioning a system prompt (for example a parameter that appends to one).
  /\b(ignore|disregard|override|forget|replace) (the |your |all )?(system prompt|developer message|previous instructions)\b/i,
  /\b(reveal|print|output|leak|show) (the |your )?(system prompt|developer message)\b/i,
  /before using this tool,? (you must |first )?(read|send|call|fetch|upload)/i,
  /(send|upload|post|forward) (the |all |any )?(conversation|chat history|credentials|api keys?|secrets?|tokens?) to/i
];

const coreAnalysers: Record<string, Analyser> = {
  "client-compat": ({ tools }) => {
    const issues = clientCompatibility(tools);
    return issues.length ? { status: "info", message: issues.join(" ") } : { status: "pass", message: "Tool names and count fit the constraints common to model providers and clients." };
  },
  "unknown-tool-code": ({ probes }) => {
    const o = probes?.unknownTool;
    if (!o) return { status: "inconclusive", message: "The unknown-tool probe did not run." };
    if (o.kind === "protocol-error" && (o.code === -32602 || o.code === -32601)) return { status: "pass", message: `Unknown tools get JSON-RPC error ${o.code} (${o.code === -32602 ? "invalid params, as in the specification's example" : "method not found, understood by most clients"}).` };
    if (o.kind === "result" && o.isError) return { status: "pass", message: "Unknown tools get an error result." };
    if (o.kind === "protocol-error") return { status: "info", message: `Unknown tools get JSON-RPC error ${o.code}. The MCP specification's example uses -32602 (invalid params); -32601 is also widely understood.` };
    return { status: "info", message: "See the unknown-tool success check for how this server answers unknown tools." };
  },
  handshake: ({ session }) => {
    if (!session) return { status: "inconclusive", message: "No MCP session (the server requires sign-in)." };
    const missing = [!session.serverInfo?.name && "serverInfo.name", !session.capabilities && "capabilities"].filter(Boolean);
    return missing.length ? { status: "fail", message: `Initialize response is missing ${missing.join(" and ")}.` }
      : { status: "pass", message: `Initialized ${sanitizeText(session.serverInfo?.name, 60)} ${sanitizeText(session.serverInfo?.version ?? "", 30)} in ${session.initMs} ms.` };
  },
  "tool-input-schemas": ({ tools }) => {
    const reasonFor = (t: ToolDef): string | undefined => {
      const s = t.inputSchema as { type?: unknown } | undefined;
      if (!s || typeof s !== "object") return "no input schema";
      if (s.type !== "object") return s.type === undefined ? "the schema has no \"type\": \"object\" (MCP requires an object schema)" : `the schema type is ${JSON.stringify(s.type).slice(0, 30)}, not "object"`;
      const c = compileUntrustedSchema(s);
      return c.ok ? undefined : `the schema is not valid JSON Schema (${c.error.slice(0, 120)})`;
    };
    const bad = tools.map((t) => ({ t, why: reasonFor(t) })).filter((x) => x.why);
    return bad.length ? { status: "fail", subject: "tools", message: `${bad.length} tool(s) have a missing or invalid input schema: ${listNames(bad.map((b) => b.t))}. For ${sanitizeText(bad[0]!.t.name, 60)}: ${bad[0]!.why}.`, evidence: evidenceFor(bad[0]!.t, JSON.stringify(bad[0]!.t.inputSchema ?? null)) }
      : { status: "pass", message: `All ${tools.length} input schemas are valid JSON Schema objects.` };
  },
  "tool-names": ({ tools }) => {
    const seen = new Set<string>(); const dup: ToolDef[] = []; const bad: ToolDef[] = [];
    for (const t of tools) {
      if (typeof t.name !== "string" || !/^[A-Za-z0-9_.-]{1,128}$/.test(t.name)) bad.push(t);
      if (seen.has(t.name)) dup.push(t); seen.add(t.name);
    }
    if (!bad.length && !dup.length) return { status: "pass", message: "Tool names are unique and use allowed characters." };
    return { status: "fail", subject: "tools", message: [bad.length && `${bad.length} name(s) use characters outside A-Z, a-z, 0-9, _ . - or exceed 128 characters: ${listNames(bad)}`, dup.length && `duplicate names: ${listNames(dup)}`].filter(Boolean).join("; ") + ".", evidence: evidenceFor(bad[0] ?? dup[0], String((bad[0] ?? dup[0])?.name)) };
  },
  "invisible-text": ({ tools }) => {
    const hit = tools.filter((t) => { INVISIBLE.lastIndex = 0; return INVISIBLE.test(textOf(t)); });
    INVISIBLE.lastIndex = 0;
    return hit.length ? { status: "fail", subject: "tools", message: `${hit.length} tool(s) contain invisible or bidirectional control characters: ${listNames(hit)}.`, evidence: evidenceFor(hit[0]) }
      : { status: "pass", message: "No invisible or bidirectional control characters." };
  },
  "control-characters": ({ tools }) => {
    const hit = tools.filter((t) => CONTROL.test(textOf(t)));
    return hit.length ? { status: "fail", subject: "tools", message: `${hit.length} tool(s) contain escape sequences or control characters, which can rewrite a user's terminal: ${listNames(hit)}.`, evidence: evidenceFor(hit[0]) }
      : { status: "pass", message: "No escape sequences or control characters." };
  },
  "hidden-instructions": ({ tools }) => {
    const hit: { tool: ToolDef; match: string }[] = [];
    for (const t of tools) { const txt = textOf(t); for (const re of HIDDEN_INSTRUCTION) { const m = txt.match(re); if (m) { hit.push({ tool: t, match: m[0] }); break; } } }
    return hit.length ? { status: "fail", subject: "tools", message: `${hit.length} tool(s) contain text that instructs the agent: ${listNames(hit.map((h) => h.tool))}.`, evidence: evidenceFor(hit[0]!.tool, `\u2026${hit[0]!.match}\u2026`) }
      : { status: "pass", message: "No instructions to the agent found in tool descriptions or schemas." };
  },
  "annotations-present": ({ tools }) => {
    const missing = tools.filter((t) => !t.annotations || Object.keys(t.annotations).length === 0);
    return missing.length ? { status: "fail", subject: "tools", message: `${missing.length} of ${tools.length} tool(s) declare no annotations (read-only, destructive, idempotent, open-world hints): ${listNames(missing)}.` }
      : { status: "pass", message: "Every tool declares annotations." };
  },
  "short-descriptions": ({ tools }) => {
    const short = tools.filter((t) => (t.description ?? "").trim().length < 20);
    return short.length ? { status: "fail", subject: "tools", message: `${short.length} tool(s) have descriptions under 20 characters, which agents find hard to choose between: ${listNames(short)}.`, evidence: evidenceFor(short[0]) }
      : { status: "pass", message: "Every tool has a usable description." };
  },
  "context-cost": ({ tools, pricePerMTokUsd }) => {
    const { contextCostTokens, largestTools, contextCostPer1kTurnsUsd } = contextCost(tools, pricePerMTokUsd);
    const money = contextCostPer1kTurnsUsd !== undefined ? ` (about $${contextCostPer1kTurnsUsd.toFixed(2)} per 1,000 agent turns at $${pricePerMTokUsd} per million input tokens)` : "";
    return { status: "info", message: `Tool definitions cost about ${contextCostTokens.toLocaleString("en-US")} tokens of agent context per turn when loaded upfront${money}. Largest: ${largestTools.slice(0, 3).map((s) => `${s.tool} (${s.tokens})`).join(", ") || "none"}.` };
  }
};

export function contextCost(tools: ToolDef[], pricePerMTokUsd?: number): { contextCostTokens: number; largestTools: { tool: string; tokens: number }[]; contextCostPer1kTurnsUsd?: number } {
  const sized = tools.map((t) => ({ tool: sanitizeText(t.name, 60), tokens: Math.round(JSON.stringify(t).length / 4) })).sort((a, b) => b.tokens - a.tokens);
  const contextCostTokens = sized.reduce((a, b) => a + b.tokens, 0);
  const per1k = pricePerMTokUsd !== undefined && pricePerMTokUsd > 0 ? Math.round((contextCostTokens / 1e6) * pricePerMTokUsd * 1000 * 100) / 100 : undefined;
  return { contextCostTokens, largestTools: sized.slice(0, 5), ...(per1k !== undefined ? { contextCostPer1kTurnsUsd: per1k } : {}) };
}

export const analysers: Record<string, Analyser> = { ...coreAnalysers, ...authAnalysers, ...leakageAnalysers, ...perfAnalysers, ...functionalAnalysers };

/** What each analyser needs. Unlisted analysers need the tool list. */
export const ANALYSER_NEEDS: Record<string, AnalyserNeeds> = { handshake: "session", "unknown-tool-code": "session", ...AUTH_NEEDS, ...LEAKAGE_NEEDS, ...PERF_NEEDS, ...FUNCTIONAL_NEEDS };
export const needsOf = (name: string): AnalyserNeeds => ANALYSER_NEEDS[name] ?? "tools";
