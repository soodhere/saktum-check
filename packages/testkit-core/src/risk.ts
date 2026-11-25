// Risk tiers (v0.6.1): grades say how well a server is built; the tier says how much care it needs.
// R0 reads public information · R1 reads private data · R2 changes data (reversible) · R3 irreversible or external
// communication · R4 moves money, runs code or makes commitments. Derived from the capability profile and annotations.
import type { ToolDef } from "@saktum/transports";
import { capabilityProfile } from "./capabilities.js";

export type RiskTier = "R0" | "R1" | "R2" | "R3" | "R4";
export const RISK_LABELS: Record<RiskTier, string> = {
  R0: "reads public information", R1: "reads private data", R2: "changes data", R3: "irreversible actions or external messages", R4: "moves money or runs code"
};
/** Default minimum maturity per tier (proportionate assurance; organisations can set their own in policy). */
export const TIER_REQUIREMENT: Record<RiskTier, string> = {
  R0: "L2 (conformant)", R1: "L3 (safe by default)", R2: "L4 (agent-ready) and a mandate", R3: "L5, a mandate, approval for irreversible actions, receipts",
  R4: "L5, an enforced mandate with value caps, approvals, receipts and monitoring"
};

export function riskTier(tools: ToolDef[]): { tier: RiskTier; label: string; reasons: string[]; requirement: string } {
  const caps = capabilityProfile(tools).capabilities;
  const has = (c: string) => caps.find((x) => x.capability === c);
  const destructive = tools.filter((t) => (t.annotations as { destructiveHint?: boolean } | undefined)?.destructiveHint === true).map((t) => t.name);
  const reasons: string[] = [];
  let tier: RiskTier = "R0";
  const bump = (t: RiskTier, why: string) => { reasons.push(why); if (t > tier) tier = t; };
  if (has("money")) bump("R4", `moves money (${has("money")!.tools.slice(0, 3).join(", ")})`);
  if (has("code-execution")) bump("R4", `runs code or commands (${has("code-execution")!.tools.slice(0, 3).join(", ")})`);
  if (destructive.length) bump("R3", `declares destructive tools (${destructive.slice(0, 3).join(", ")})`);
  if (has("sends-messages")) bump("R3", `sends messages (${has("sends-messages")!.tools.slice(0, 3).join(", ")})`);
  if (has("writes-or-deletes")) bump("R2", `changes data (${has("writes-or-deletes")!.tools.slice(0, 3).join(", ")})`);
  if (has("reads-private-data")) bump("R1", "reads private data");
  if (!reasons.length) reasons.push("only reads; no capability that changes data, moves money or runs code was found");
  return { tier, label: RISK_LABELS[tier], reasons, requirement: TIER_REQUIREMENT[tier] };
}
