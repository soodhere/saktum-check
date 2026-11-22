import { canonicalize, sha256Tag } from "@saktum/sign";
import { connect, describeTarget, probeInitialize, processUsage, ShapeError, type CallOutcome, type Session, type Target, type ToolDef } from "@saktum/transports";
import { contextCost, needsOf, type AnalyserContext } from "./analysers.js";
import { gradeFor, summarise } from "./grade.js";
import { checkNeedsSession, runCheck, SIGN_IN_HINT } from "./runner.js";
import { sanitizeText } from "./safe.js";
import { score } from "./scoring.js";
import type { Finding, LoadedPack, Result } from "./types.js";

export const ENGINE_VERSION = "0.1.2";
export const UNKNOWN_TOOL = "saktum_trust_check_no_such_tool";
const INVALID_TOKEN = "saktum-check-deliberately-invalid-token";
const BURST_REQUESTS = 20;

export type NoGrade = { kind: "sign-in" } | { kind: "no-tools"; toolsCapability: boolean } | { kind: "list-failed"; error: string } | { kind: "too-few" };

export interface RunOptions {
  packs: LoadedPack[];
  mode?: "passive" | "active";
  session?: Session;
  /** Price per million input tokens for the cost estimate (reported only). Default 3. */
  pricePerMTokUsd?: number;
}

/** Connection problems (nothing answered) are not findings; protocol problems (something answered wrongly) are. */
function isProtocolFailure(e: unknown): boolean {
  const m = String((e as Error)?.message ?? e);
  return !/ENOENT|EACCES|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|fetch failed|timed out|spawn|Connection closed|socket hang up/i.test(m);
}

const baseOf = (pack: LoadedPack["pack"], check: LoadedPack["pack"]["checks"][number]) => ({
  check: check.id, pack: pack.id, severity: check.severity, scored: check.scored !== false && check.severity !== "info",
  title: check.title, fix: check.fix, references: check.references
});

/** Minimum number of scored checks that must actually run (pass or fail) before a grade is given. */
export const MIN_GRADED_CHECKS = 5;

function finish(target: Target, opts: RunOptions, startedAt: Date, findings: Finding[], extra: Partial<Result["target"]>, metrics: Result["metrics"], sandbox: "none" | "docker", noGrade: NoGrade | undefined): Result {
  const categoryOf = (id: string) => opts.packs.find((p) => p.pack.id === id)?.pack.category ?? "other";
  const scores = score(findings, categoryOf);
  // A grade must never overstate what was examined: withhold it when the tools could not be assessed.
  const ran = findings.filter((f) => f.scored && (f.status === "pass" || f.status === "fail")).length;
  const reason: NoGrade | undefined = noGrade ?? (ran < MIN_GRADED_CHECKS ? { kind: "too-few" } : undefined);
  const grade = reason ? null : gradeFor(scores.overall, scores.capped);
  const r: Result = {
    resultFormat: "0.1",
    tool: { name: "saktum-trust-check", version: ENGINE_VERSION },
    target: { transport: target.kind, description: describeTarget(target), ...extra },
    packs: opts.packs.map((p) => ({ id: p.pack.id, version: p.pack.version, hash: p.hash })),
    findings, scores, grade, assuranceLevel: "L1", metrics,
    run: { startedAt: startedAt.toISOString(), durationMs: Date.now() - startedAt.getTime(), mode: opts.mode ?? "passive", runner: "self", sandbox }
  };
  r.summary = summarise(r, reason);
  return r;
}

async function burst(session: Session): Promise<NonNullable<NonNullable<AnalyserContext["perf"]>["burst"]>> {
  const times: number[] = [];
  let ok = 0, rateLimited = 0, errors = 0;
  await Promise.all(Array.from({ length: BURST_REQUESTS }, async () => {
    const t = Date.now();
    try { await session.listTools(); ok++; }
    catch (e) { if (/\b429\b|rate.?limit/i.test(String((e as Error).message))) rateLimited++; else errors++; }
    times.push(Date.now() - t);
  }));
  times.sort((a, b) => a - b);
  return { requests: BURST_REQUESTS, ok, rateLimited, errors, p95Ms: times[Math.min(times.length - 1, Math.floor(times.length * 0.95))] ?? 0 };
}

export async function runTrustCheck(target: Target, opts: RunOptions): Promise<Result> {
  const startedAt = new Date();
  const mode = opts.mode ?? "passive";
  const price = opts.pricePerMTokUsd ?? 3;
  const ctx: AnalyserContext = { tools: [], target, mode, pricePerMTokUsd: price, probes: {}, perf: {} };

  // 1. Remote servers: observe the sign-in behaviour directly, before (and independently of) an MCP session.
  if (target.kind === "streamable-http") {
    const userSuppliedAuth = Object.keys(target.headers ?? {}).some((k) => k.toLowerCase() === "authorization");
    const unauthenticated = await probeInitialize(target.url);
    const invalidToken = await probeInitialize(target.url, { Authorization: `Bearer ${INVALID_TOKEN}` });
    ctx.http = { unauthenticated, invalidToken, userSuppliedAuth };
    if (unauthenticated.status === null && !userSuppliedAuth) throw new Error(`Could not reach ${target.url}: ${unauthenticated.error}`);
  }

  // 2. Connect. A server that requires sign-in (and no token was given) is still assessed: sign-in checks run, the rest wait for a token.
  let session: Session | undefined;
  let signInRequired = false;
  try { session = opts.session ?? (await connect(target)); }
  catch (e) {
    if (ctx.http?.unauthenticated?.status === 401 && !ctx.http.userSuppliedAuth) signInRequired = true;
    else if (!isProtocolFailure(e)) throw e;
    else {
      const findings: Finding[] = [];
      for (const { pack } of opts.packs) for (const check of pack.checks) {
        const base = baseOf(pack, check);
        findings.push(check.steps.some((s) => s.analyser === "handshake")
          ? { ...base, status: "fail", message: `Initialize failed: ${sanitizeText((e as Error).message, 200)}` }
          : { ...base, status: "inconclusive", message: "Not run: initialize failed.", fix: undefined });
      }
      return finish(target, { ...opts, mode }, startedAt, findings, { toolCount: 0 }, {}, "none", { kind: "too-few" });
    }
  }
  ctx.session = session;

  try {
    // 3. Tools, safe probes and measurements.
    let listError: string | undefined;
    let listShape = false;
    if (session) {
      ctx.perf!.initMs = session.initMs;
      const t0 = Date.now();
      try { ctx.tools = await session.listTools(); } catch (e) { listError = (e as Error).message; listShape = e instanceof ShapeError; }
      ctx.perf!.listMs = Date.now() - t0;
      ctx.perf!.listBytes = JSON.stringify(ctx.tools).length;
      ctx.probes!.unknownTool = await session.callTool(UNKNOWN_TOOL, {});
      // Only read-only tools are probed with empty arguments, so a server that ignores validation cannot be made to act.
      const readOnly = ctx.tools.find((t) => (t.annotations as { readOnlyHint?: boolean } | undefined)?.readOnlyHint === true && Array.isArray((t.inputSchema as { required?: unknown[] } | undefined)?.required) && ((t.inputSchema as { required: unknown[] }).required.length > 0));
      if (readOnly) ctx.probes!.invalidArgs = { tool: readOnly.name, outcome: (await session.callTool(readOnly.name, {})) as CallOutcome };
      if (session.pid) { const u = await processUsage(session.pid); if (u) { ctx.perf!.rssMb = u.rssMb; ctx.perf!.cpuPct = u.cpuPct; } }
      if (mode === "active") ctx.perf!.burst = await burst(session);
    }
    const tools = ctx.tools;
    const fingerprint = sha256Tag(canonicalize([...tools].sort((a: ToolDef, b: ToolDef) => String(a.name).localeCompare(String(b.name)))));

    // 4. Checks.
    const findings: Finding[] = [];
    for (const { pack } of opts.packs) {
      for (const check of pack.checks) {
        const base = baseOf(pack, check);
        const skip = (why: string) => findings.push({ ...base, status: "skipped", message: why, fix: undefined });
        if (check.safety === "active" && mode !== "active") { skip("Active check: runs only with --active against a server you own."); continue; }
        if (check.appliesTo?.transports && !check.appliesTo.transports.includes(target.kind)) { skip(`Applies only to ${check.appliesTo.transports.join(", ")} servers.`); continue; }
        if (!session && checkNeedsSession(check)) { findings.push({ ...base, status: "inconclusive", message: SIGN_IN_HINT, fix: undefined }); continue; }
        if (listError && check.steps.some((s) => s.action === "mcp.listTools" || (s.action === "analyse" && needsOf(s.analyser ?? "") === "tools"))) {
          const listsDirectly = check.steps.some((s) => s.action === "mcp.listTools");
          const why = sanitizeText(listError, 200);
          findings.push({ ...base, status: listsDirectly && listShape ? "fail" : "inconclusive", message: listsDirectly ? (listShape ? why : `The tool list could not be read: ${why}`) : "Not run: the tool list could not be read.", fix: listsDirectly && listShape ? base.fix : undefined });
          continue;
        }
        const v = await runCheck(check, ctx);
        findings.push({ ...base, status: v.status, message: v.message, subject: v.subject, evidence: v.evidence, ...(v.status === "pass" || v.status === "skipped" || v.status === "info" ? { fix: undefined } : {}) });
      }
    }

    const cost = contextCost(tools, price);
    const metrics: Result["metrics"] = { ...cost, pricePerMTokUsd: price, performance: { ...ctx.perf } };
    if (!session || listError) { delete metrics.contextCostTokens; delete metrics.largestTools; delete metrics.contextCostPer1kTurnsUsd; }
    const noGrade: NoGrade | undefined = signInRequired ? { kind: "sign-in" }
      : listError ? { kind: "list-failed", error: sanitizeText(listError, 160) }
      : tools.length === 0 ? { kind: "no-tools", toolsCapability: Boolean((session?.capabilities as { tools?: unknown } | undefined)?.tools) }
      : undefined;
    return finish(target, { ...opts, mode }, startedAt, findings,
      session ? { protocolVersion: session.protocolVersion, serverInfo: session.serverInfo, toolsFingerprint: fingerprint, toolCount: tools.length } : { toolCount: 0 },
      metrics, session?.sandbox ?? "none", noGrade);
  } finally {
    if (session && !opts.session) await session.close();
  }
}
