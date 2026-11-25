// Policy as code (v0.4, enterprise): an organisation's own rules for which MCP servers may be used, evaluated against
// Saktum results. Exceptions need a reason, and may name an approver and an expiry date; expired exceptions stop applying.
import { sanitizeText } from "./safe.js";

export interface Policy {
  policyFormat: "0.1"; name?: string; minTrust?: string; minReadiness?: string; forbidCapabilities?: string[]; forbidLethalTrifecta?: boolean;
  maxContextTokens?: number; noFailedSeverity?: string; requireAllowlist?: boolean; allowlist?: string; maxRiskTier?: string;
  exceptions?: { server: string; rules?: string[]; reason: string; approvedBy?: string; until?: string }[];
}
export interface PolicySubject { server: string; trustGrade: string | null; readinessGrade: string | null; capabilities: string[]; lethalTrifecta: boolean; contextTokens: number | null; failedSeverities: string[]; toolsFingerprint?: string; riskTier?: string }
export interface Violation { rule: string; message: string; excepted?: { reason: string; approvedBy?: string; until?: string } }
export interface PolicyVerdict { server: string; compliant: boolean; violations: Violation[] }

const GRADES = ["A", "B", "C", "D", "F"];
const SEV = ["critical", "high", "medium", "low", "info"];
const below = (g: string | null, min: string) => g === null || GRADES.indexOf(g) > GRADES.indexOf(min);

export async function parsePolicy(text: string): Promise<Policy> {
  const { parse } = await import("yaml");
  const { compileContract } = await import("./contracts.js");
  const data = parse(text) as unknown;
  const v = compileContract("policy.schema.json");
  if (!v(data)) throw new Error(`Invalid policy: ${(v.errors ?? []).map((e) => `${e.instancePath || "/"} ${e.message}`).join("; ")}`);
  return data as Policy;
}

export function evaluatePolicy(s: PolicySubject, p: Policy, allowlistFingerprints?: Set<string>, today = new Date().toISOString().slice(0, 10)): PolicyVerdict {
  const v: Violation[] = [];
  if (p.minTrust && below(s.trustGrade, p.minTrust)) v.push({ rule: "minTrust", message: `trust ${s.trustGrade ?? "not graded"} is below the required ${p.minTrust}` });
  if (p.minReadiness && below(s.readinessGrade, p.minReadiness)) v.push({ rule: "minReadiness", message: `agent readiness ${s.readinessGrade ?? "not graded"} is below the required ${p.minReadiness}` });
  for (const c of p.forbidCapabilities ?? []) if (s.capabilities.includes(c)) v.push({ rule: "forbidCapabilities", message: `has a forbidden capability: ${c}` });
  if (p.forbidLethalTrifecta && s.lethalTrifecta) v.push({ rule: "forbidLethalTrifecta", message: "combines private data, untrusted content and an outbound channel" });
  if (p.maxContextTokens !== undefined && (s.contextTokens ?? 0) > p.maxContextTokens) v.push({ rule: "maxContextTokens", message: `costs ${(s.contextTokens ?? 0).toLocaleString("en-US")} tokens per turn (limit ${p.maxContextTokens.toLocaleString("en-US")})` });
  if (p.noFailedSeverity) { const lim = SEV.indexOf(p.noFailedSeverity); const bad = s.failedSeverities.filter((x) => SEV.indexOf(x) <= lim); if (bad.length) v.push({ rule: "noFailedSeverity", message: `${bad.length} failed check(s) at ${p.noFailedSeverity} or above` }); }
  if (p.maxRiskTier && s.riskTier && s.riskTier > p.maxRiskTier) v.push({ rule: "maxRiskTier", message: `risk tier ${s.riskTier} is above the allowed ${p.maxRiskTier}` });
  if (p.requireAllowlist && !(s.toolsFingerprint && allowlistFingerprints?.has(s.toolsFingerprint))) v.push({ rule: "requireAllowlist", message: "is not on the organisation's allowlist (or its tools changed since it was approved)" });
  for (const x of v) {
    const e = (p.exceptions ?? []).find((ex) => ex.server === s.server && (!ex.rules || ex.rules.includes(x.rule)) && (!ex.until || ex.until >= today));
    if (e) x.excepted = { reason: sanitizeText(e.reason, 300), approvedBy: e.approvedBy, until: e.until };
  }
  return { server: s.server, compliant: v.every((x) => x.excepted), violations: v };
}

/** Build a policy subject from a Saktum result. */
export function subjectFromResult(r: { target: { description: string; serverInfo?: Record<string, unknown>; toolsFingerprint?: string }; grade?: string | null; readiness?: { grade: string | null; contextTokens: number } | null;
  capabilities?: { capabilities: { capability: string }[]; lethalTrifecta: boolean }; riskTier?: { tier: string }; findings: { status: string; severity: string; suppressed?: unknown }[] }, name?: string): PolicySubject {
  return { server: name ?? String(r.target.serverInfo?.["name"] ?? r.target.description), trustGrade: r.grade ?? null, readinessGrade: r.readiness?.grade ?? null,
    capabilities: (r.capabilities?.capabilities ?? []).map((c) => c.capability), lethalTrifecta: Boolean(r.capabilities?.lethalTrifecta), contextTokens: r.readiness?.contextTokens ?? null,
    failedSeverities: r.findings.filter((f) => f.status === "fail" && !f.suppressed).map((f) => f.severity), toolsFingerprint: r.target.toolsFingerprint, riskTier: r.riskTier?.tier };
}

export function renderVerdict(v: PolicyVerdict): string {
  if (!v.violations.length) return `\u2713 ${v.server}: complies with policy`;
  return [`${v.compliant ? "\u2713" : "\u2717"} ${v.server}: ${v.compliant ? "complies (with approved exceptions)" : "violates policy"}`,
    ...v.violations.map((x) => `    ${x.excepted ? "~" : "\u2717"} ${x.rule}: ${x.message}${x.excepted ? ` (exception: ${x.excepted.reason}${x.excepted.approvedBy ? `, approved by ${x.excepted.approvedBy}` : ""}${x.excepted.until ? `, until ${x.excepted.until}` : ""})` : ""}`)].join("\n");
}
