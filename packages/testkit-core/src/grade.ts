// The human layer: a letter grade and three plain sentences at the top of every report (Baseline 1.8 and 6.1).
import type { Result, Severity } from "./types.js";
import type { NoGrade } from "./engine.js";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function gradeFor(overall: number | null, capped: boolean): Result["grade"] {
  if (overall === null) return null;
  if (capped || overall < 50) return "F";
  if (overall >= 90) return "A";
  if (overall >= 80) return "B";
  if (overall >= 70) return "C";
  return "D";
}

export function summarise(r: Pick<Result, "findings" | "scores" | "metrics" | "grade">, noGrade?: NoGrade): string[] {
  const signInRequired = noGrade?.kind === "sign-in";
  const fails = r.findings.filter((f) => f.status === "fail" && f.scored).sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
  const passed = r.findings.filter((f) => f.status === "pass").length;
  const counts = ORDER.slice(0, 4).map((s) => [s, fails.filter((f) => f.severity === s).length] as const).filter(([, n]) => n > 0);
  const lines: string[] = [];
  if (signInRequired) lines.push(`No grade yet: the sign-in checks ran${fails.length ? ` and found ${fails.length} problem${fails.length === 1 ? "" : "s"}` : " and passed"}, but the tools need a token to be tested.`);
  else if (noGrade?.kind === "list-failed") lines.push(`No grade: the tool list could not be read (${noGrade.error}). The server may need valid credentials or configuration; try saktum doctor.`);
  else if (noGrade?.kind === "no-tools") lines.push(noGrade.toolsCapability
    ? "No grade: the server listed no tools, so there was nothing to examine. It may need valid credentials or configuration before it offers tools."
    : "No grade: this server offers no tools (only resources or prompts), which this version does not grade yet.");
  else if (r.grade === null || r.grade === undefined) lines.push("No grade: too few checks could run against this server to grade it fairly.");
  else if (fails.length === 0) lines.push(`Grade ${r.grade}: all ${passed} checks that apply passed.`);
  else lines.push(`Grade ${r.grade}: ${fails.length} problem${fails.length === 1 ? "" : "s"} found (${counts.map(([s, n]) => `${n} ${s}`).join(", ")}); ${passed} checks passed.`);
  if (fails[0]) {
    const first = (fails[0].message ?? fails[0].title).split(/(?<=\.)\s/)[0]!.replace(/\.$/, "");
    lines.push(`Fix first (${fails[0].severity}): ${first.charAt(0).toLowerCase()}${first.slice(1)}.`);
  }
  else lines.push("Nothing to fix in this run; keep running it in CI to catch regressions.");
  if (signInRequired) lines.push("Most checks need sign-in: re-run with --header \"Authorization: Bearer <token>\" to test the tools themselves.");
  else if (r.metrics.contextCostTokens !== undefined) {
    const money = r.metrics.contextCostPer1kTurnsUsd !== undefined ? `, about $${r.metrics.contextCostPer1kTurnsUsd.toFixed(2)} per 1,000 turns` : "";
    lines.push(`Agents spend about ${r.metrics.contextCostTokens.toLocaleString("en-US")} tokens reading these tools on every turn${money}.`);
  }
  return lines;
}
