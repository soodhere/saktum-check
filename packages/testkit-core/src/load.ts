// Performance and scalability (v0.2, --active only). Measured with safe operations: tools/list, and a read-only tool the
// functional step already called successfully. Numbers come with a plain interpretation; they are never scored.
import type { Session } from "@saktum/transports";

export const LOAD = { latencySamples: 10, levels: [1, 5, 20], perLevelRequests: 20 };

export interface LoadProfile {
  operation: string;
  latency: { p50: number; p95: number; samples: number };
  levels: { concurrency: number; requests: number; ok: number; rateLimited: number; errors: number; p95: number; throughput: number }[];
  memoryGrowthMb?: number;
  verdicts: string[];
}

export function percentile(values: number[], p: number): number {
  if (!values.length) return 0;
  const s = [...values].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.max(0, Math.ceil((p / 100) * s.length) - 1))]!;
}

export async function measureLoad(session: Session, op?: { tool: string; args: Record<string, unknown> }): Promise<LoadProfile> {
  const operation = op ? `calling ${op.tool}` : "listing tools";
  const once = async (): Promise<{ ms: number; ok: boolean; limited: boolean }> => {
    const t = Date.now();
    try {
      if (op) {
        const o = await session.callTool(op.tool, op.args);
        const limited = o.kind === "protocol-error" && /429|rate.?limit/i.test(o.message);
        return { ms: Date.now() - t, ok: o.kind === "result" && !o.isError, limited };
      }
      await session.listTools();
      return { ms: Date.now() - t, ok: true, limited: false };
    } catch (e) { return { ms: Date.now() - t, ok: false, limited: /429|rate.?limit/i.test(String((e as Error).message)) }; }
  };
  const lat: number[] = [];
  for (let i = 0; i < LOAD.latencySamples; i++) lat.push((await once()).ms);
  const levels: LoadProfile["levels"] = [];
  for (const c of LOAD.levels) {
    const results: { ms: number; ok: boolean; limited: boolean }[] = [];
    const t0 = Date.now();
    let next = 0;
    await Promise.all(Array.from({ length: c }, async () => { while (next < LOAD.perLevelRequests) { next++; results.push(await once()); } }));
    const secs = Math.max(0.001, (Date.now() - t0) / 1000);
    levels.push({ concurrency: c, requests: results.length, ok: results.filter((r) => r.ok).length, rateLimited: results.filter((r) => r.limited).length,
      errors: results.filter((r) => !r.ok && !r.limited).length, p95: percentile(results.map((r) => r.ms), 95), throughput: Math.round((results.length / secs) * 10) / 10 });
  }
  const p50 = percentile(lat, 50), p95 = percentile(lat, 95);
  const verdicts: string[] = [];
  verdicts.push(p95 < 300 ? `Fast: ${operation} takes ${p95} ms at p95, fine for interactive agents.` : p95 < 1000 ? `Acceptable: ${p95} ms at p95 for ${operation}; agents will notice delays in long tool chains.` : `Slow: ${p95} ms at p95 for ${operation}; agents and clients may time out.`);
  const top = levels[levels.length - 1]!;
  const base = levels[0]!;
  if (top.errors > 0) verdicts.push(`Under ${top.concurrency} concurrent callers, ${top.errors} of ${top.requests} requests failed: check limits and connection handling.`);
  else if (top.rateLimited > 0) verdicts.push(`Under ${top.concurrency} concurrent callers it rate-limited ${top.rateLimited} requests, which is healthy behaviour.`);
  else verdicts.push(`Handled ${top.concurrency} concurrent callers with no errors (${top.throughput} requests per second; p95 ${top.p95} ms against ${base.p95} ms with one caller).`);
  return { operation, latency: { p50, p95, samples: lat.length }, levels, verdicts };
}
