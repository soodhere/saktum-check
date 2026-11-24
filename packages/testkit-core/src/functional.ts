// Functional testing (v0.2). Does each tool actually work, return what it promises, and fail gracefully?
// Safety rules: Saktum calls tools only with --active, and only tools annotated readOnlyHint: true, unless the provider
// names tools explicitly (--call, or a test case). It never calls destructive or unannotated tools on its own.
import type { CallOutcome, Session, ToolDef } from "@saktum/transports";
import { compileUntrustedSchemaValidator } from "./contracts.js";
import { LEAK_PATTERNS, outcomeText } from "./leakage.js";
import { sanitizeText } from "./safe.js";

export const FUNCTIONAL_LIMITS = { maxSmokeTools: 8, perCallTimeoutMs: 15_000, survivalWaitMs: 500 };

type Schema = Record<string, unknown>;
const obj = (v: unknown): Schema => (v && typeof v === "object" && !Array.isArray(v) ? (v as Schema) : {});

/** A minimal valid value for a JSON Schema, preferring the schema's own examples, defaults and enums. */
export function exampleFor(schema: unknown, depth = 0): unknown {
  const s = obj(schema);
  if (depth > 6) return null;
  if ("const" in s) return s.const;
  if (Array.isArray(s.examples) && s.examples.length) return s.examples[0];
  if ("default" in s) return s.default;
  if (Array.isArray(s.enum) && s.enum.length) return s.enum[0];
  for (const k of ["oneOf", "anyOf"]) if (Array.isArray(s[k]) && (s[k] as unknown[]).length) return exampleFor((s[k] as unknown[])[0], depth + 1);
  if (Array.isArray(s.allOf) && s.allOf.length) return exampleFor(Object.assign({}, ...(s.allOf as unknown[]).map(obj)), depth + 1);
  const type = Array.isArray(s.type) ? (s.type as string[]).find((t) => t !== "null") : (s.type as string | undefined);
  switch (type ?? (s.properties ? "object" : undefined)) {
    case "object": {
      const out: Record<string, unknown> = {};
      const props = obj(s.properties);
      for (const key of (Array.isArray(s.required) ? s.required : []) as string[]) out[key] = exampleFor(props[key], depth + 1);
      return out;
    }
    case "array": {
      const n = typeof s.minItems === "number" ? Math.min(s.minItems, 3) : 0;
      return Array.from({ length: n }, () => exampleFor(s.items, depth + 1));
    }
    case "integer": case "number": {
      let v = typeof s.minimum === "number" ? s.minimum : typeof s.exclusiveMinimum === "number" ? s.exclusiveMinimum + 1 : 1;
      if (typeof s.maximum === "number" && v > s.maximum) v = s.maximum;
      return type === "integer" ? Math.ceil(v) : v;
    }
    case "boolean": return false;
    case "null": return null;
    case "string": {
      const fmt: Record<string, string> = { uri: "https://example.com", url: "https://example.com", email: "user@example.com", date: "2026-01-15", "date-time": "2026-01-15T09:00:00Z", uuid: "123e4567-e89b-42d3-a456-426614174000", hostname: "example.com", ipv4: "192.0.2.1" };
      let v = fmt[String(s.format)] ?? "example";
      if (typeof s.minLength === "number" && v.length < s.minLength) v = v.padEnd(s.minLength, "x");
      if (typeof s.maxLength === "number" && v.length > s.maxLength) v = v.slice(0, Math.max(1, s.maxLength));
      return v;
    }
    default: return "example";
  }
}

/** Arguments that violate the schema in the most ordinary way: required fields missing, or a wrong type. */
export function invalidArgsFor(schema: unknown): Record<string, unknown> | undefined {
  const s = obj(schema);
  const required = (Array.isArray(s.required) ? s.required : []) as string[];
  if (required.length) return {};
  const first = Object.entries(obj(s.properties))[0];
  if (!first) return undefined;
  const t = obj(first[1]).type;
  return { [first[0]]: t === "string" ? 12345 : "not-the-right-type" };
}

export interface CallRecord { tool: string; purpose: "smoke" | "invalid-args" | "test"; args: Record<string, unknown>; outcome: CallOutcome; problems: string[] }

export interface FunctionalReport {
  ran: boolean;
  reason?: string;
  calledTools: string[];
  notCalled: { tool: string; why: string }[];
  calls: CallRecord[];
  survived?: boolean;
}

const isReadOnly = (t: ToolDef) => (t.annotations as { readOnlyHint?: boolean } | undefined)?.readOnlyHint === true;

/** Problems with a successful call's result: content shape, and structuredContent against the declared outputSchema. */
export function resultProblems(tool: ToolDef, o: CallOutcome): string[] {
  if (o.kind !== "result" || o.isError) return [];
  const p: string[] = [];
  if (!Array.isArray(o.content)) p.push("content is not an array");
  else for (const c of o.content as unknown[]) {
    const it = obj(c);
    if (typeof it.type !== "string") { p.push("a content item has no type"); break; }
    if (it.type === "text" && typeof it.text !== "string") { p.push("a text content item has no text"); break; }
  }
  const outSchema = (tool as { outputSchema?: unknown }).outputSchema;
  if (outSchema) {
    if (o.structuredContent === undefined) p.push("the tool declares an outputSchema but returned no structuredContent");
    else {
      const v = compileUntrustedSchemaValidator(outSchema);
      if (!v.ok) p.push(`its outputSchema is not valid JSON Schema (${v.error.slice(0, 80)})`);
      else if (!v.validate(o.structuredContent)) p.push(`structuredContent does not match its outputSchema (${v.errors().slice(0, 120)})`);
    }
  }
  return p;
}

/** Problems with how a tool handled invalid arguments: it must refuse gracefully, without crashing or leaking internals. */
export function invalidArgProblems(o: CallOutcome): string[] {
  const p: string[] = [];
  if (o.kind === "timeout") p.push("timed out instead of rejecting the invalid arguments");
  else if (o.kind === "transport-error") p.push("the connection failed (the server may have crashed)");
  else if (o.kind === "result" && !o.isError) p.push("accepted arguments that violate its input schema and reported success");
  const text = outcomeText(o);
  const leak = LEAK_PATTERNS.find((l) => l.re.test(text));
  if (leak) p.push(`its error exposes ${/^[aeiou]/i.test(leak.name) ? "an" : "a"} ${leak.name}`);
  return p;
}

/** Smoke calls and invalid-argument probes. Only read-only tools, plus any the provider names explicitly. */
export async function runFunctional(session: Session, tools: ToolDef[], opts: { active: boolean; allowTools?: string[] }): Promise<FunctionalReport> {
  if (!opts.active) return { ran: false, reason: "Tools are called only with --active, against servers you own.", calledTools: [], notCalled: [], calls: [] };
  const allow = new Set(opts.allowTools ?? []);
  const notCalled: FunctionalReport["notCalled"] = [];
  const eligible: ToolDef[] = [];
  for (const t of tools) {
    if (allow.has(t.name) || isReadOnly(t)) eligible.push(t);
    else notCalled.push({ tool: t.name, why: (t.annotations as { destructiveHint?: boolean } | undefined)?.destructiveHint ? "destructive (never called automatically)" : "not annotated read-only (name it with --call to include it)" });
  }
  const chosen = eligible.slice(0, FUNCTIONAL_LIMITS.maxSmokeTools);
  for (const t of eligible.slice(FUNCTIONAL_LIMITS.maxSmokeTools)) notCalled.push({ tool: t.name, why: `limit of ${FUNCTIONAL_LIMITS.maxSmokeTools} tools per run` });
  const calls: CallRecord[] = [];
  for (const t of chosen) {
    const args = exampleFor(t.inputSchema) as Record<string, unknown>;
    const inCheck = compileUntrustedSchemaValidator(t.inputSchema);
    if (inCheck.ok && !inCheck.validate(args)) { notCalled.push({ tool: t.name, why: "could not generate arguments that satisfy its input schema (add a test case for it)" }); continue; }
    const outcome = await session.callTool(t.name, args);
    const problems = outcome.kind === "result" ? resultProblems(t, outcome)
      : outcome.kind === "protocol-error" && outcome.code === -32602 ? ["rejected arguments that satisfy its own input schema"]
      : outcome.kind === "protocol-error" ? [] : [`${outcome.kind === "timeout" ? "timed out" : "the call failed"}`];
    calls.push({ tool: t.name, purpose: "smoke", args, outcome, problems });
    const bad = invalidArgsFor(t.inputSchema);
    if (bad) {
      const o2 = await session.callTool(t.name, bad);
      calls.push({ tool: t.name, purpose: "invalid-args", args: bad, outcome: o2, problems: invalidArgProblems(o2) });
    }
  }
  let survived: boolean | undefined;
  // Crashes are often asynchronous (a process exits just after answering), so wait briefly before checking survival.
  if (calls.length) { await new Promise((r) => setTimeout(r, FUNCTIONAL_LIMITS.survivalWaitMs)); try { await session.listTools(); survived = true; } catch { survived = false; } }
  return { ran: true, calledTools: [...new Set(calls.map((c) => c.tool))], notCalled, calls, survived };
}

// ---------- Provider test cases (saktum.tests.yaml, contract test-cases.schema.json) ----------

export interface TestCase { id: string; tool: string; input: Record<string, unknown>; sideEffects?: boolean; expect: { isError?: boolean; textContains?: string; structured?: Record<string, unknown>; outputSchema?: boolean; latencyMs?: { lt?: number } } }
export interface TestResult { id: string; tool: string; status: "pass" | "fail" | "skipped"; problems: string[]; latencyMs?: number }

/** True when every key in `expected` is present in `actual` with an equal value (recursively). */
export function subsetMatch(expected: unknown, actual: unknown): boolean {
  if (expected === null || typeof expected !== "object") return expected === actual;
  if (Array.isArray(expected)) return Array.isArray(actual) && expected.length === actual.length && expected.every((e, i) => subsetMatch(e, actual[i]));
  if (!actual || typeof actual !== "object") return false;
  return Object.entries(expected).every(([k, v]) => subsetMatch(v, (actual as Record<string, unknown>)[k]));
}

export async function runTestCases(session: Session, tools: ToolDef[], cases: TestCase[], opts: { active: boolean }): Promise<TestResult[]> {
  const out: TestResult[] = [];
  for (const tc of cases) {
    const tool = tools.find((t) => t.name === tc.tool);
    if (!tool) { out.push({ id: tc.id, tool: tc.tool, status: "fail", problems: [`the server does not list a tool named ${sanitizeText(tc.tool, 60)}`] }); continue; }
    if (tc.sideEffects && !opts.active) { out.push({ id: tc.id, tool: tc.tool, status: "skipped", problems: ["has side effects: runs only with --active against a server you own"] }); continue; }
    const o = await session.callTool(tc.tool, tc.input);
    const p: string[] = [];
    const e = tc.expect;
    const isError = o.kind === "result" ? o.isError : true;
    if (o.kind !== "result" && e.isError !== true) p.push(o.kind === "protocol-error" ? `protocol error ${o.code}: ${sanitizeText(o.message, 120)}` : o.kind === "timeout" ? "timed out" : "the call failed");
    if (e.isError !== undefined && isError !== e.isError) p.push(e.isError ? "expected an error result but the call succeeded" : "expected success but got an error result");
    const text = outcomeText(o);
    if (e.textContains !== undefined && !text.includes(e.textContains)) p.push(`the result does not contain "${sanitizeText(e.textContains, 60)}"`);
    if (e.structured !== undefined && !(o.kind === "result" && subsetMatch(e.structured, o.structuredContent))) p.push("structuredContent does not match the expected values");
    if (e.outputSchema) p.push(...resultProblems(tool, o).filter((x) => /outputSchema|structuredContent/.test(x)));
    if (e.latencyMs?.lt !== undefined && o.latencyMs >= e.latencyMs.lt) p.push(`took ${o.latencyMs} ms (expected under ${e.latencyMs.lt} ms)`);
    out.push({ id: tc.id, tool: tc.tool, status: p.length ? "fail" : "pass", problems: p, latencyMs: o.latencyMs });
  }
  return out;
}

/** Load provider test cases from YAML or JSON text, validated against the test-cases contract. */
export async function parseTestCases(text: string): Promise<TestCase[]> {
  const { parse } = await import("yaml");
  const { compileContract } = await import("./contracts.js");
  const data = parse(text) as unknown;
  const validate = compileContract("test-cases.schema.json");
  if (!validate(data)) throw new Error(`Invalid test cases: ${(validate.errors ?? []).map((e) => `${e.instancePath || "/"} ${e.message}`).join("; ")}`);
  return (data as { tests: TestCase[] }).tests;
}

/** Append a test case to saktum.tests.yaml text (or start a new file), keeping existing comments and formatting. */
export async function appendTestCase(existing: string | undefined, tc: TestCase): Promise<string> {
  const { parseDocument, stringify } = await import("yaml");
  if (!existing || !existing.trim()) return `# Test cases (guide: docs/TESTS.md)\n${stringify({ testsFormat: "0.1", tests: [tc] })}`;
  const doc = parseDocument(existing);
  const tests = doc.get("tests") as { items?: unknown[]; add: (n: unknown) => void } | undefined;
  if (!tests || typeof tests.add !== "function") throw new Error("The test file has no tests list.");
  if (((doc.toJS() as { tests: { id: string }[] }).tests ?? []).some((t) => t.id === tc.id)) throw new Error(`A test case with id ${tc.id} already exists.`);
  tests.add(doc.createNode(tc));
  return String(doc);
}
