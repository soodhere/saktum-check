export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Status = "pass" | "fail" | "skipped" | "inconclusive" | "info";
export type Category = "conformance" | "auth" | "security" | "agent-experience" | "performance" | "functional";

export interface Expectation { exists?: string[]; isError?: boolean; errorCodeIn?: number[]; failed?: boolean; anyOf?: Expectation[] }
export interface Step { action: "mcp.initialize" | "mcp.listTools" | "mcp.callTool" | "analyse"; tool?: string; arguments?: Record<string, unknown>; analyser?: string; expect?: Expectation }
export interface Check {
  id: string; title: string; severity: Severity; safety: "passive" | "active"; scored?: boolean;
  appliesTo?: { transports?: ("stdio" | "streamable-http")[]; protocol?: string };
  steps: Step[]; fix: string; references?: string[];
  normative?: { source: string; version?: string; clause?: string; level: "MUST" | "SHOULD" | "MAY" | "best-practice" }[];
}
export interface Pack { packFormat: "0.1"; id: string; version: string; category: Category; description?: string; checks: Check[]; signature?: { alg: "EdDSA"; kid: string; jws: string } }
export interface LoadedPack { pack: Pack; hash: string; signedBy?: string }

export interface Finding {
  check: string; pack: string; status: Status; severity: Severity; scored: boolean; title: string;
  subject?: string; message?: string; fix?: string; references?: string[]; evidence?: { hash?: string; excerpt?: string };
  /** Set when the provider chose to ignore this check (--ignore); suppressed findings are not scored. */
  suppressed?: { reason: string };
}

export interface Result {
  resultFormat: "0.1";
  tool: { name: "saktum-trust-check"; version: string };
  target: { transport: "stdio" | "streamable-http"; description: string; protocolVersion?: string; serverInfo?: Record<string, unknown>; toolsFingerprint?: string; toolCount?: number };
  packs: { id: string; version: string; hash: string }[];
  findings: Finding[];
  scores: { overall: number | null; capped: boolean; categories: Record<string, number | null> };
  grade?: "A" | "B" | "C" | "D" | "F" | null;
  /** Agent readiness (v0.1.4): a second grade, never mixed into trust. Null when no tools could be examined. */
  readiness?: { score: number; grade: "A" | "B" | "C" | "D" | "F" | null; toolsAnnotated: number; toolsDescribed: number; toolCount: number; contextTokens: number; topImprovement?: string } | null;
  /** How many scored trust checks (conformance, sign-in, security) actually ran in this run. */
  coverage?: { trustChecksRun: number };
  /** v0.2: what the tools appear able to do (inferred, never scored). */
  capabilities?: { capabilities: { capability: string; label: string; tools: string[]; basis: "declared" | "inferred" }[]; lethalTrifecta: boolean; note: string };
  /** v0.2: which tools were called and how they behaved (active runs). */
  functional?: { ran: boolean; reason?: string; calledTools: string[]; notCalled: { tool: string; why: string }[]; calls: { tool: string; purpose: string; outcome: string; latencyMs: number; problems: string[] }[]; survived?: boolean };
  /** v0.2: latency percentiles and concurrency (active runs). */
  load?: { operation: string; latency: { p50: number; p95: number; samples: number }; levels: { concurrency: number; requests: number; ok: number; rateLimited: number; errors: number; p95: number; throughput: number }[]; memoryGrowthMb?: number; verdicts: string[] };
  /** v0.2: provider test cases (saktum.tests.yaml). */
  tests?: { id: string; tool: string; status: "pass" | "fail" | "skipped"; problems: string[]; latencyMs?: number }[];
  /** v0.2: checks the provider chose to ignore, with reasons (shown in every report). */
  suppressions?: { check: string; reason: string }[];
  summary?: string[];
  assuranceLevel?: "L1";
  metrics: {
    contextCostTokens?: number;
    largestTools?: { tool: string; tokens: number }[];
    /** Estimated cost of loading the tool definitions on 1,000 agent turns, at the user-set price per million input tokens. Reported only. */
    contextCostPer1kTurnsUsd?: number;
    pricePerMTokUsd?: number;
    performance?: { initMs?: number; listMs?: number; listBytes?: number; rssMb?: number; cpuPct?: number; burst?: { requests: number; ok: number; rateLimited: number; errors: number; p95Ms: number } };
  };
  run: { startedAt: string; durationMs: number; mode: "passive" | "active"; runner: "self" | "hosted"; sandbox: "none" | "docker" };
  signature?: { alg: "EdDSA"; kid: string; jws: string };
}
