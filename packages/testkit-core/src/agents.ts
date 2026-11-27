// v0.10: an inventory of agents. Finds Saktum mandates in the given folders and reports, per agent, who owns and
// operates it, what it may do, its risk tier and maturity, expiry and revocation: the "shadow agents" question.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { agentMaturity, agentRiskTier, checkMandate, checkOperator, revocationOf, type Mandate } from "./agentid.js";

export interface AgentRecord { name: string; id: string; owner: string; operator: string; purpose: string; autonomy: string; tools: number; riskTier: string; maturity: string; expires: string; valid: boolean; revoked: boolean; file: string }
export function scanAgents(dirs: string[], o: { revocationsPath?: string; depth?: number } = {}): AgentRecord[] {
  const found: AgentRecord[] = [];
  const walk = (dir: string, depth: number) => {
    let names: string[] = [];
    try { names = readdirSync(dir); } catch { return; }
    for (const n of names) {
      if (n === "node_modules" || n.startsWith(".git")) continue;
      const p = join(dir, n);
      let st; try { st = statSync(p); } catch { continue; }
      if (st.isDirectory()) { if (depth > 0) walk(p, depth - 1); continue; }
      if (!n.endsWith(".json") || st.size > 1_000_000) continue;
      let m: Mandate & { purpose?: string; actions?: unknown[] };
      try { m = JSON.parse(readFileSync(p, "utf8")); } catch { continue; }
      if (!m || typeof m !== "object" || !("mandateFormat" in m) || !m.agent?.id) continue;
      const op = checkOperator(m as never);
      found.push({ name: m.agent.name, id: m.agent.id, owner: m.owner?.name ?? m.owner?.id ?? "", operator: op.present ? (op.valid ? op.name ?? "" : "invalid countersignature") : "",
        purpose: m.purpose ?? "", autonomy: m.autonomy ?? "act", tools: m.allow?.tools?.length ?? 0, riskTier: agentRiskTier(m).tier, maturity: agentMaturity(m as never).label,
        expires: m.expires, valid: checkMandate(m).ok, revoked: Boolean(revocationOf(m, o.revocationsPath)), file: p });
    }
  };
  for (const d of dirs) walk(d, o.depth ?? 3);
  return found;
}
