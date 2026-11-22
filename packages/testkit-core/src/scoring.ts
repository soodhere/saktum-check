import type { Finding, Severity } from "./types.js";

export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 5, high: 3, medium: 2, low: 1, info: 0 };
/** The trust score covers conformance, sign-in and security only (Baseline 1.1 decision). Other categories are reported, not scored. */
export const TRUST_WEIGHTS: Record<string, number> = { conformance: 0.3, auth: 0.3, security: 0.4 };
export const CRITICAL_CAP = 49;

export function score(findings: Finding[], categoryOf: (pack: string) => string) {
  const totals: Record<string, { pass: number; all: number }> = {};
  let criticalFail = false;
  for (const f of findings) {
    if (!f.scored || (f.status !== "pass" && f.status !== "fail")) continue;
    const w = SEVERITY_WEIGHT[f.severity];
    if (w === 0) continue;
    const c = categoryOf(f.pack);
    const t = (totals[c] ??= { pass: 0, all: 0 });
    t.all += w; if (f.status === "pass") t.pass += w;
    if (f.status === "fail" && f.severity === "critical" && c in TRUST_WEIGHTS) criticalFail = true;
  }
  const categories: Record<string, number | null> = {};
  for (const [c, t] of Object.entries(totals)) categories[c] = t.all ? Math.round((100 * t.pass) / t.all) : null;
  const present = Object.keys(TRUST_WEIGHTS).filter((c) => categories[c] !== undefined && categories[c] !== null);
  const wsum = present.reduce((a, c) => a + TRUST_WEIGHTS[c]!, 0);
  let overall: number | null = wsum ? Math.round(present.reduce((a, c) => a + TRUST_WEIGHTS[c]! * (categories[c] as number), 0) / wsum) : null;
  const capped = criticalFail && overall !== null && overall > CRITICAL_CAP;
  if (capped) overall = CRITICAL_CAP;
  return { overall, capped, categories };
}
