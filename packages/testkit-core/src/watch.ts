// saktum watch (v0.6): continuous monitoring of the MCP servers an organisation depends on. Re-checks every server on an
// allowlist (passive) and compares with what was approved: changed tools (fingerprint), grade drops, unreachable servers.
import { runTrustCheck } from "./engine.js";
import type { LoadedPack } from "./types.js";

const GRADES = ["A", "B", "C", "D", "F"];
const worse = (now: string | null | undefined, then: string | null | undefined) => then != null && (now == null || GRADES.indexOf(now) > GRADES.indexOf(then));
export function splitCommand(s: string): string[] { const out: string[] = []; const re = /"([^"]*)"|'([^']*)'|(\S+)/g; let m; while ((m = re.exec(s))) out.push(m[1] ?? m[2] ?? m[3]!); return out; }

export interface WatchEntry { server: string; target: string; transport: string; toolsFingerprint?: string; trustGrade: string | null; readinessGrade: string | null }
export interface WatchFinding { server: string; status: "unchanged" | "changed" | "degraded" | "unreachable"; details: string[]; trustGrade?: string | null; readinessGrade?: string | null; toolsFingerprint?: string }

export async function watchAllowlist(entries: WatchEntry[], packs: LoadedPack[]): Promise<{ checkedAt: string; findings: WatchFinding[]; alerts: number }> {
  const findings: WatchFinding[] = [];
  for (const e of entries) {
    try {
      const parts = splitCommand(e.target);
      const target = e.transport === "streamable-http" ? { kind: "streamable-http" as const, url: e.target } : { kind: "stdio" as const, command: parts[0]!, args: parts.slice(1) };
      const r = await runTrustCheck(target, { packs });
      const d: string[] = [];
      if (e.toolsFingerprint && r.target.toolsFingerprint !== e.toolsFingerprint) d.push("tools changed since approval (fingerprint differs): re-review before agents keep using it");
      if (worse(r.grade, e.trustGrade)) d.push(`trust grade dropped from ${e.trustGrade} to ${r.grade ?? "not graded"}`);
      if (worse(r.readiness?.grade, e.readinessGrade)) d.push(`agent readiness dropped from ${e.readinessGrade} to ${r.readiness?.grade ?? "not graded"}`);
      const status = d.some((x) => x.startsWith("tools changed")) ? "changed" : d.length ? "degraded" : "unchanged";
      findings.push({ server: e.server, status, details: d, trustGrade: r.grade ?? null, readinessGrade: r.readiness?.grade ?? null, toolsFingerprint: r.target.toolsFingerprint });
    } catch (err) { findings.push({ server: e.server, status: "unreachable", details: [`could not connect: ${String((err as Error).message).slice(0, 160)}`] }); }
  }
  return { checkedAt: new Date().toISOString(), findings, alerts: findings.filter((f) => f.status !== "unchanged").length };
}
