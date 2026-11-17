// Performance and resource use. Reported as information, never part of the trust score: numbers depend on the
// machine and network, so they guide fixes rather than grade servers. The burst test runs only with --active.
import type { Analyser } from "./analysers.js";

export const PERF_THRESHOLDS = { startupMs: 10_000, listMs: 2_000, listBytes: 200_000, rssMb: 500 };

const kb = (n: number) => `${Math.round(n / 1024)} KB`;

export const perfAnalysers: Record<string, Analyser> = {
  "perf-startup": ({ perf, target }) => {
    if (perf?.initMs === undefined) return { status: "inconclusive", message: "Start-up time was not measured." };
    const what = target?.kind === "stdio" ? "Started and completed the handshake" : "Completed the handshake";
    const slow = perf.initMs > PERF_THRESHOLDS.startupMs;
    return { status: "info", message: `${what} in ${perf.initMs} ms.${slow ? " That is slow: agents and clients may time out." : ""}` };
  },
  "perf-latency": ({ perf }) => {
    if (perf?.listMs === undefined) return { status: "inconclusive", message: "Tool-list latency was not measured." };
    const notes: string[] = [];
    if (perf.listMs > PERF_THRESHOLDS.listMs) notes.push("slow to list tools");
    if ((perf.listBytes ?? 0) > PERF_THRESHOLDS.listBytes) notes.push("a large tool list");
    return { status: "info", message: `Listed tools in ${perf.listMs} ms (${kb(perf.listBytes ?? 0)}).${notes.length ? ` Watch for ${notes.join(" and ")}.` : ""}` };
  },
  "perf-memory": ({ perf, target }) => {
    if (target?.kind !== "stdio") return { status: "skipped", message: "Memory and CPU are measured for local servers only." };
    if (perf?.rssMb === undefined) return { status: "inconclusive", message: "Memory and CPU could not be measured on this platform." };
    // CPU from ps is an average over the process's life, so a just-started server always looks busy: report it, never judge it.
    const heavy = perf.rssMb > PERF_THRESHOLDS.rssMb;
    return { status: "info", message: `Uses ${perf.rssMb} MB of memory (including any launcher such as npx); averaged ${perf.cpuPct}% CPU since start-up.${heavy ? " That is a lot of memory for a tool server." : ""}` };
  },
  "perf-burst": ({ perf }) => {
    const b = perf?.burst;
    if (!b) return { status: "inconclusive", message: "The burst test did not run." };
    const parts = [`${b.ok} of ${b.requests} concurrent requests succeeded (p95 ${b.p95Ms} ms)`];
    if (b.rateLimited) parts.push(`${b.rateLimited} were rate-limited, which is healthy behaviour`);
    if (b.errors) parts.push(`${b.errors} failed with errors under light load`);
    return { status: "info", message: `${parts.join("; ")}.` };
  }
};

export const PERF_NEEDS = { "perf-startup": "session" as const, "perf-latency": "session" as const, "perf-memory": "session" as const, "perf-burst": "session" as const };
