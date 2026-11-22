// Agent readiness (v0.1.4): how ready a server's tools are for agents to choose and use safely and cheaply.
// A second grade beside trust, never mixed into it. Partial credit, so one gap lowers the grade proportionately:
// annotations (share of tools declaring danger hints), descriptions (share with usable descriptions), context cost.
import type { ToolDef } from "@saktum/transports";
import { contextCost } from "./analysers.js";
import { gradeFor } from "./grade.js";
import type { Result } from "./types.js";

export const READINESS = {
  weights: { annotations: 0.3, descriptions: 0.4, cost: 0.3 },
  /** Full credit for context cost up to this many tokens per turn, falling linearly to zero at zeroCreditTokens. */
  fullCreditTokens: 10_000,
  zeroCreditTokens: 60_000,
  /** Same threshold as the ax.short-descriptions check. */
  minDescriptionChars: 20
};

const hasAnnotations = (t: ToolDef) => Boolean(t.annotations && Object.keys(t.annotations).length > 0);
const usableDescription = (t: ToolDef) => (t.description ?? "").trim().length >= READINESS.minDescriptionChars;
const fmt = (n: number) => n.toLocaleString("en-US");

export function readinessFor(tools: ToolDef[]): NonNullable<Result["readiness"]> | null {
  if (tools.length === 0) return null;
  const annotated = tools.filter(hasAnnotations).length;
  const described = tools.filter(usableDescription).length;
  const tokens = contextCost(tools).contextCostTokens;
  const { fullCreditTokens: full, zeroCreditTokens: zero, weights: w } = READINESS;
  const costCredit = tokens <= full ? 1 : tokens >= zero ? 0 : 1 - (tokens - full) / (zero - full);
  const parts = { annotations: annotated / tools.length, descriptions: described / tools.length, cost: costCredit };
  const score = Math.round(100 * (w.annotations * parts.annotations + w.descriptions * parts.descriptions + w.cost * parts.cost));
  // The single most valuable improvement: the part losing the most points.
  const losses = [
    { lost: w.annotations * (1 - parts.annotations), text: `declare danger annotations (readOnlyHint, destructiveHint) on ${tools.length - annotated} of ${tools.length} tools` },
    { lost: w.descriptions * (1 - parts.descriptions), text: `write usable descriptions for ${tools.length - described} of ${tools.length} tools` },
    { lost: w.cost * (1 - parts.cost), text: `trim tool definitions: agents read ${fmt(tokens)} tokens of them on every turn` }
  ].sort((a, b) => b.lost - a.lost);
  return {
    score, grade: gradeFor(score, false) ?? null,
    toolsAnnotated: annotated, toolsDescribed: described, toolCount: tools.length, contextTokens: tokens,
    topImprovement: losses[0]!.lost > 0.005 ? losses[0]!.text : undefined
  };
}
