import { actionClass, semanticValues, VOCABULARIES, type ActionClass } from "./vocab.js";
// Agent identity and mandates (v0.4 preview of the gateway): an agent gets its own key (did:key); its human owner signs a
// mandate saying which servers and tools it may use, whether destructive actions are allowed, and until when.
import { canonicalize, sha256Tag, signDocument, verifyDocument, type Signature, type SigningKey } from "@saktum/sign";
import { sanitizeText } from "./safe.js";

export interface Mandate {
  mandateFormat: "0.1"; agent: { id: string; name: string }; owner: { id: string; name?: string }; purpose?: string;
  allow: { servers?: string[]; tools?: string[]; destructive: boolean }; issuedAt: string; expires: string; signature: Signature;
  autonomy?: "notify" | "propose" | "act"; constraints?: { tool: string; arg: string; max?: number; oneOf?: (string | number)[] }[];
  limits?: { callsPerDay?: number; totalPerDay?: { arg: string; max: number } }; approveAbove?: { arg: string; value: number };
  disclosures?: { operator?: string; incentives?: string; dataUse?: string }; delegation?: boolean;
}

export function createMandate(o: { agentId: string; agentName: string; ownerName?: string; purpose?: string; servers?: string[]; tools?: string[]; destructive: boolean; expires: string;
  autonomy?: Mandate["autonomy"]; constraints?: Mandate["constraints"]; limits?: Mandate["limits"]; approveAbove?: Mandate["approveAbove"]; disclosures?: Mandate["disclosures"]; delegation?: boolean } & IntentMandate, ownerKey: SigningKey): Mandate & IntentMandate {
  const body = { mandateFormat: "0.1" as const, agent: { id: o.agentId, name: sanitizeText(o.agentName, 120) }, owner: { id: ownerKey.kid, ...(o.ownerName ? { name: sanitizeText(o.ownerName, 120) } : {}) },
    ...(o.purpose ? { purpose: sanitizeText(o.purpose, 300) } : {}),
    allow: { ...(o.servers?.length ? { servers: o.servers } : {}), ...(o.tools?.length ? { tools: o.tools } : {}), destructive: o.destructive }, issuedAt: new Date().toISOString(), expires: o.expires,
    ...(o.autonomy ? { autonomy: o.autonomy } : {}), ...(o.constraints?.length ? { constraints: o.constraints } : {}), ...(o.limits && Object.keys(o.limits).length ? { limits: o.limits } : {}),
    ...(o.approveAbove ? { approveAbove: o.approveAbove } : {}), ...(o.disclosures && Object.keys(o.disclosures).length ? { disclosures: o.disclosures } : {}), delegation: o.delegation === true,
    ...(o.actions?.length ? { actions: o.actions } : {}), ...(o.rules?.length ? { rules: o.rules } : {}), ...(o.preferences?.length ? { preferences: o.preferences } : {}),
    ...(o.substitution ? { substitution: o.substitution } : {}), ...(o.upsell ? { upsell: o.upsell } : {}), ...(o.approvalTriggers?.length ? { approvalTriggers: o.approvalTriggers } : {}),
    ...(o.counterparties?.length ? { counterparties: o.counterparties } : {}), ...(o.dataSharing?.length ? { dataSharing: o.dataSharing } : {}) };
  return signDocument(body, ownerKey) as Mandate & IntentMandate;
}

/** Valid when the owner's signature checks out and the mandate has not expired. */
export function checkMandate(m: Mandate, today = new Date().toISOString().slice(0, 10)): { ok: true } | { ok: false; reason: string } {
  const { operatorCountersign: _cs, ...principalPart } = m as Mandate & { operatorCountersign?: unknown };
  const v = verifyDocument(principalPart);
  if (!v.valid) return { ok: false, reason: `mandate signature not valid (${v.reason})` };
  if (v.kid !== m.owner.id) return { ok: false, reason: "mandate is not signed by its stated owner" };
  if (m.expires < today) return { ok: false, reason: `mandate expired on ${m.expires}` };
  return { ok: true };
}

export type ToolAnnotations = { readOnlyHint?: boolean; destructiveHint?: boolean } | undefined;
/** May this agent make this call under its mandate? Per MCP, a tool that is not read-only is destructive unless it says otherwise. */
export function mandateDecision(m: Mandate, server: string, tool: string, ann: ToolAnnotations): { allow: boolean; reason: string } {
  if (m.allow.servers && !m.allow.servers.includes(server)) return { allow: false, reason: `server ${server} is not in the agent's mandate` };
  if (m.allow.tools && !m.allow.tools.includes(tool)) return { allow: false, reason: `tool ${tool} is not in the agent's mandate` };
  const destructive = ann?.destructiveHint === true || (ann?.readOnlyHint === false && ann?.destructiveHint !== false);
  if (destructive && !m.allow.destructive) return { allow: false, reason: `tool ${tool} is declared destructive and the mandate does not allow destructive actions` };
  return { allow: true, reason: m.allow.tools || m.allow.servers ? "within the agent's mandate" : "mandate allows it" };
}



// ---------- v0.6.1: permissions enforced per call ----------

export type DecisionCode = "ok" | "not-in-mandate" | "notify-only" | "approval-needed" | "money-not-granted" | "destructive" | "over-cap" | "value-not-allowed" | "daily-limit";
export interface CallContext { tool: string; server: string; args: Record<string, unknown>; annotations: ToolAnnotations; isMoney: boolean; usage: { callsToday: number; totalToday: number } }

/** The full decision for one call, in a fixed order; the first rule that stops the call wins. */
export function decideCall(m: Mandate, c: CallContext): { allow: boolean; code: DecisionCode; reason: string } {
  const base = mandateDecision(m, c.server, c.tool, c.annotations);
  if (!base.allow) return { allow: false, code: base.reason.includes("destructive") ? "destructive" : "not-in-mandate", reason: base.reason };
  const isRead = c.annotations?.readOnlyHint === true;
  const autonomy = m.autonomy ?? "act";
  if (autonomy === "notify" && !isRead) return { allow: false, code: "notify-only", reason: `notify-only mandate: tell your user about ${c.tool} instead of doing it` };
  const granted = m.allow.tools?.includes(c.tool) || m.constraints?.some((k) => k.tool === c.tool);
  if (c.isMoney && !granted) return { allow: false, code: "money-not-granted", reason: `${c.tool} moves money and is not explicitly granted in the mandate` };
  for (const k of (m.constraints ?? []).filter((x) => x.tool === c.tool)) {
    const v = c.args[k.arg];
    if (k.max !== undefined && Number(v) > k.max) return { allow: false, code: "over-cap", reason: `${k.arg} ${v} is above the cap of ${k.max}` };
    if (k.oneOf && !k.oneOf.map(String).includes(String(v))) return { allow: false, code: "value-not-allowed", reason: `${k.arg} ${String(v)} is not one of ${k.oneOf.join(", ")}` };
  }
  if (!isRead && m.limits?.callsPerDay !== undefined && c.usage.callsToday >= m.limits.callsPerDay) return { allow: false, code: "daily-limit", reason: `daily limit of ${m.limits.callsPerDay} actions reached` };
  const tot = m.limits?.totalPerDay;
  if (tot && c.args[tot.arg] !== undefined && c.usage.totalToday + Number(c.args[tot.arg]) > tot.max) return { allow: false, code: "daily-limit", reason: `daily total for ${tot.arg} would reach ${c.usage.totalToday + Number(c.args[tot.arg])}, above ${tot.max}` };
  const ap = m.approveAbove;
  if (ap && c.args[ap.arg] !== undefined && Number(c.args[ap.arg]) > ap.value) return { allow: false, code: "approval-needed", reason: `${ap.arg} ${c.args[ap.arg]} is above the approval threshold of ${ap.value}: ask your user to approve` };
  if (autonomy === "propose" && !isRead) return { allow: false, code: "approval-needed", reason: `propose mandate: ask your user to approve ${c.tool} before it runs` };
  return { allow: true, code: "ok", reason: autonomy === "act" ? "within the mandate's limits" : "read allowed" };
}

/** The agent's risk tier from what its mandate grants (names only when tools are listed), adjusted for autonomy. */
export function agentRiskTier(m: Mandate): { tier: string; note: string } {
  if (!m.allow.tools?.length && !m.constraints?.length) return { tier: m.autonomy === "notify" ? "R1" : "depends on servers", note: "no tool list: the tier follows the servers it connects to" };
  const names = [...new Set([...(m.allow.tools ?? []), ...(m.constraints ?? []).map((k) => k.tool)])];
  const money = names.some((n) => /(^|[_-])(pay|payment|charge|refund|checkout|purchase|buy|order|transfer|invoice)([_-]|$)/i.test(n));
  const exec = names.some((n) => /(^|[_-])(exec|execute|run_command|shell|bash)([_-]|$)/i.test(n));
  const writes = names.some((n) => /(^|[_-])(create|update|delete|add|write|send|post|set|remove|cart)([_-]|$)/i.test(n));
  let tier = money || exec ? "R4" : m.allow.destructive ? "R3" : writes ? "R2" : "R0";
  let note = money ? "can spend money" : exec ? "can run code" : writes ? "can change data" : "reads only";
  if (m.autonomy === "notify") { tier = "R0"; note += ", but notify-only: it cannot act"; }
  else if (m.autonomy === "propose" && tier > "R1") note += ", but every action needs approval";
  else if (tier === "R4" && m.constraints?.some((k) => k.max !== undefined)) note += `, capped (${m.constraints.filter((k) => k.max !== undefined).map((k) => `${k.arg} \u2264 ${k.max}`).join(", ")})`;
  return { tier, note };
}

// ---------- v0.7: mandate v0.3 (intent, rules, preferences, substitution, upsell, triggers) with rationale ----------

export interface IntentMandate {
  purpose?: string; actions?: { cls: ActionClass; autonomy: "notify" | "propose" | "act" }[];
  rules?: { field: string; op: "max" | "min" | "eq" | "in" | "notIn"; value: unknown; label?: string }[];
  preferences?: { field: string; prefer: string | number | boolean; label?: string }[];
  substitution?: { allowed: boolean; maxPriceChangePct?: number; neverFor?: string[] };
  upsell?: "never" | "ask" | "allowed"; approvalTriggers?: ("substitution" | "fee" | "upsell" | "sponsored" | "new-counterparty")[];
  counterparties?: string[]; dataSharing?: { data: string; to: string }[];
}
export interface Rationale { evaluated: { rule: string; ok: boolean }[]; preferences: string[]; flags: string[] }
export type IntentCode = "ok" | "notify-only" | "approval-needed" | "rule-violated" | "substitution-not-allowed" | "upsell-not-allowed" | "counterparty-not-allowed" | "data-not-permitted";

const FIELD_LABEL = (f: string) => VOCABULARIES[f.split(".")[0]!]?.fields.find((x) => x.path === f)?.description.toLowerCase() ?? f;
const ruleText = (r: NonNullable<IntentMandate["rules"]>[number]) => r.label ?? (r.op === "max" ? `${FIELD_LABEL(r.field)} at most ${r.value}` : r.op === "min" ? `${FIELD_LABEL(r.field)} at least ${r.value}`
  : r.op === "eq" ? `${FIELD_LABEL(r.field)}: ${r.value === true ? "yes" : r.value === false ? "no" : String(r.value)}` : r.op === "in" ? `${FIELD_LABEL(r.field)} only ${(r.value as unknown[]).join(", ")}` : `never ${(r.value as unknown[]).join(", ")} (${FIELD_LABEL(r.field)})`);

export function hasIntent(m: Mandate & IntentMandate): boolean { return Boolean(m.purpose && (m.actions || m.rules || m.preferences || m.substitution || m.upsell || m.approvalTriggers || m.counterparties)); }

/** Decide one call against the mandate's intent, in domain terms, and explain why. */
export function decideIntent(m: Mandate & IntentMandate, tool: { name: string; description?: string; inputSchema?: unknown; _meta?: Record<string, unknown> }, args: Record<string, unknown>, ctx: { server?: string } = {}):
  { allow: boolean; code: IntentCode; reason: string; rationale: Rationale; values: Record<string, unknown> } {
  const v = semanticValues(tool, args);
  const r: Rationale = { evaluated: [], preferences: [], flags: [] };
  const stop = (code: IntentCode, reason: string) => ({ allow: false, code, reason, rationale: r, values: v });
  const cls = actionClass(tool).cls;
  const auto = m.actions?.find((a) => a.cls === cls)?.autonomy;
  if (auto === "notify" && cls !== "search") return stop("notify-only", `only alerts for ${cls}: tell your user instead`);
  for (const rule of m.rules ?? []) {
    if (!(rule.field in v)) continue;
    const x = v[rule.field];
    const ok = rule.op === "max" ? Number(x) <= Number(rule.value) : rule.op === "min" ? Number(x) >= Number(rule.value) : rule.op === "eq" ? x === rule.value
      : rule.op === "in" ? (rule.value as unknown[]).map(String).includes(String(x)) : !(rule.value as unknown[]).map((s) => String(s).toLowerCase()).includes(String(x).toLowerCase());
    r.evaluated.push({ rule: ruleText(rule), ok });
    if (!ok) return stop("rule-violated", `${ruleText(rule)} (got ${String(x)})`);
  }
  const cp = v["commerce.counterparty"];
  if (m.counterparties && cp !== undefined && !m.counterparties.includes(String(cp))) {
    if (m.approvalTriggers?.includes("new-counterparty")) return stop("approval-needed", `new counterparty ${String(cp)}: ask your user`);
    return stop("counterparty-not-allowed", `${String(cp)} is not an allowed counterparty`);
  }
  const personal: string[] = Object.keys(v).filter((k) => k.startsWith("personal."));
  const dclass = v["enterprise.data_class"] !== undefined ? String(v["enterprise.data_class"]).toLowerCase() : undefined;
  if (dclass && dclass !== "public") personal.push(`class.${dclass}`);
  if (personal.length) {
    const recipient = String(v["party.recipient"] ?? v["commerce.counterparty"] ?? v["travel.carrier"] ?? v["enterprise.vendor"] ?? ctx.server ?? "the service");
    const norm = (x: string) => x.toLowerCase().replace(/^the /, "").trim();
    for (const f of personal) {
      const kind = f.startsWith("class.") ? `${f.slice(6)} data` : f.split(".")[1]!;
      const key = kind.replace(/ data$/, "");
      const ok = (m.dataSharing ?? []).some((d) => norm(d.data).includes(key) && (norm(recipient).includes(norm(d.to)) || norm(d.to).includes(norm(recipient))));
      if (m.dataSharing) {
        r.evaluated.push({ rule: `share ${kind} only as permitted (to ${recipient})`, ok });
        if (!ok) return stop("data-not-permitted", `${kind} may not be shared with ${recipient}`);
      } else r.flags.push(`personal data shared: ${kind} with ${recipient}`);
    }
  }
  const subFor = v["commerce.item.substitute_for"];
  if (subFor !== undefined || cls === "substitute") {
    const s = m.substitution;
    if (!s?.allowed) return stop("substitution-not-allowed", "substitutions are not allowed");
    const cat = String(v["commerce.item.category"] ?? "").toLowerCase();
    if (s.neverFor?.some((c) => c.toLowerCase() === cat)) return stop("substitution-not-allowed", `never substitute ${cat}`);
    const p = Number(v["commerce.item.unit_price"]), ref = Number(v["commerce.item.reference_price"]);
    if (s.maxPriceChangePct !== undefined && p > 0 && ref > 0) {
      const pct = Math.round(((p - ref) / ref) * 1000) / 10;
      const ok = Math.abs(pct) <= s.maxPriceChangePct;
      r.evaluated.push({ rule: `substitute within ${s.maxPriceChangePct}% of the price (${pct > 0 ? "+" : ""}${pct}%)`, ok });
      if (!ok) return stop("substitution-not-allowed", `substitute is ${pct > 0 ? "+" : ""}${pct}% in price, above ${s.maxPriceChangePct}%`);
    }
    if (m.approvalTriggers?.includes("substitution")) return stop("approval-needed", `substitution for ${String(subFor)}: ask your user`);
    r.flags.push(`substitution for ${String(subFor ?? "an item")}, within policy`);
  }
  if (v["commerce.item.upgrade"] === true || v["travel.upgrade"] === true) {
    if (m.upsell === "never") return stop("upsell-not-allowed", "upgrades and upsells are not allowed");
    if (m.upsell === "ask" || m.approvalTriggers?.includes("upsell")) return stop("approval-needed", "this is an upgrade: ask your user first");
    r.flags.push("upgrade chosen, allowed by the mandate");
  }
  const fee = Number(v["travel.fee"] ?? 0);
  if (fee > 0 && m.approvalTriggers?.includes("fee")) return stop("approval-needed", `there is a fee of ${fee}: ask your user first`);
  if (v["commerce.item.sponsored"] === true) {
    if (m.approvalTriggers?.includes("sponsored")) return stop("approval-needed", "this option is sponsored: ask your user first");
    r.flags.push("sponsored option chosen");
  }
  for (const p of m.preferences ?? []) if (p.field in v) {
    const matched = String(v[p.field]).toLowerCase() === String(p.prefer).toLowerCase();
    r.preferences.push(matched ? `matches preference: ${p.label ?? `${FIELD_LABEL(p.field)} ${p.prefer}`}` : `differs from preference: wanted ${p.prefer}, chose ${String(v[p.field])}`);
    if (!matched) r.flags.push(`differs from the stated preference (${FIELD_LABEL(p.field)})`);
  }
  if (auto === "propose" && cls !== "search") return stop("approval-needed", `asks before ${cls}: ask your user to approve`);
  return { allow: true, code: "ok", reason: r.evaluated.length ? `within the mandate: ${r.evaluated.map((e) => e.rule).join("; ")}` : "within the mandate", rationale: r, values: v };
}

/** The mandate in plain words, as a person would give the instructions. */
export function describeMandate(m: Mandate & IntentMandate): string[] {
  const out: string[] = [];
  if (m.purpose) out.push(m.purpose + ".");
  const verbs: Record<string, string> = { notify: "only alerts you about", propose: "asks you before", act: "does on its own:" };
  for (const level of ["act", "propose", "notify"] as const) { const cl = (m.actions ?? []).filter((a) => a.autonomy === level).map((a) => a.cls); if (cl.length) out.push(`It ${verbs[level]} ${cl.join(", ")}.`); }
  if (m.rules?.length) out.push(`Always: ${m.rules.map(ruleText).join("; ")}.`);
  if (m.substitution) out.push(m.substitution.allowed ? `Substitutes${m.substitution.maxPriceChangePct !== undefined ? ` within ${m.substitution.maxPriceChangePct}% of the price` : ""}${m.substitution.neverFor?.length ? `, never for ${m.substitution.neverFor.join(", ")}` : ""}.` : "Never substitutes.");
  if (m.upsell) out.push(m.upsell === "never" ? "Never upsells." : m.upsell === "ask" ? "Asks before any upgrade." : "May choose upgrades.");
  if (m.approvalTriggers?.length) out.push(`Asks you first for: ${m.approvalTriggers.join(", ")}.`);
  if (m.preferences?.length) out.push(`Prefers: ${m.preferences.map((p) => p.label ?? `${FIELD_LABEL(p.field)} ${p.prefer}`).join("; ")}.`);
  if (m.counterparties?.length) out.push(`Only with: ${m.counterparties.join(", ")}.`);
  if (m.dataSharing?.length) out.push(`Shares: ${m.dataSharing.map((d) => `${d.data} with ${d.to} only`).join("; ")}.`);
  if (m.disclosures?.operator) out.push(`Operated by ${m.disclosures.operator}${m.disclosures.incentives ? ` (incentives: ${m.disclosures.incentives})` : ""}.`);
  return out;
}


// ---------- v0.7: parties (operator countersignature), revocation, track record ----------
import { argumentsHash, type ReceiptLogEntry } from "./receipts.js";
import { homedir as _home } from "node:os";
import { existsSync as _exists, readFileSync as _read, writeFileSync as _write, mkdirSync as _mkdir } from "node:fs";
import { dirname as _dirname, join as _join } from "node:path";

/** A digest of the mandate as the principal signed it (without the operator's countersignature). */
export function mandateDigest(m: Mandate): string { const { operatorCountersign: _x, ...rest } = m as Mandate & { operatorCountersign?: unknown }; return argumentsHash(JSON.parse(JSON.stringify(rest))); }

/** The operator (who runs the agent and is accountable) countersigns the principal's mandate. */
export function cosignMandate(m: Mandate, key: SigningKey, name: string): Mandate & { operatorCountersign: unknown } {
  return { ...m, operatorCountersign: signDocument({ role: "operator", name, mandate: mandateDigest(m), at: new Date().toISOString() }, key) };
}
export function checkOperator(m: Mandate & { operatorCountersign?: { name?: string; mandate?: string } }): { present: false } | { present: true; valid: boolean; id?: string; name?: string; reason?: string } {
  const cs = m.operatorCountersign;
  if (!cs) return { present: false };
  const v = verifyDocument(cs as never);
  if (!v.valid) return { present: true, valid: false, reason: "operator signature not valid" };
  if (cs.mandate !== mandateDigest(m)) return { present: true, valid: false, reason: "operator signed a different mandate" };
  return { present: true, valid: true, id: v.kid, name: cs.name };
}

export const DEFAULT_REVOCATIONS = () => _join(_home(), ".saktum", "revocations.json");
type Revocations = { revoked: { mandate: string; agent: string; at: string; reason?: string }[] };
const readRevocations = (path: string): Revocations => { try { return _exists(path) ? (JSON.parse(_read(path, "utf8")) as Revocations) : { revoked: [] }; } catch { return { revoked: [] }; } };
/** Stop an agent now: record the mandate as revoked; every proxy using that revocation list refuses its calls. */
export function revokeMandate(m: Mandate, reason: string | undefined, path = DEFAULT_REVOCATIONS(), key?: SigningKey) {
  const r = readRevocations(path), d = mandateDigest(m);
  const entry = { revocationFormat: "0.1", mandate: d, agent: m.agent.id, at: new Date().toISOString(), ...(reason ? { reason } : {}) };
  if (!r.revoked.some((x) => x.mandate === d)) r.revoked.push((key ? signDocument(entry, key) : entry) as never);
  _mkdir(_dirname(path), { recursive: true }); _write(path, JSON.stringify(r, null, 2) + "\n");
  return r.revoked.find((x) => x.mandate === d)!;
}
export function revocationOf(m: Mandate, path = DEFAULT_REVOCATIONS()) {
  const d = mandateDigest(m);
  const op = (m as Mandate & { operatorCountersign?: { signature?: { kid?: string } } }).operatorCountersign?.signature?.kid;
  return readRevocations(path).revoked.find((x) => { if (x.mandate !== d) return false; const sx = x as { signature?: unknown }; if (!sx.signature) return true; const v = verifyDocument(x as never); return v.valid && (v.kid === m.owner.id || (Boolean(op) && v.kid === op)); });
}

/** How well the agent followed its instructions, from its receipts: a statement, never a score. */
export function trustStatement(entries: ReceiptLogEntry[], verified: boolean): { lines: string[]; facts: Record<string, number> } {
  const allowed = entries.filter((e) => e.receipt.outcome === "allow" && e.result.status === "ok").length;
  const blocked = entries.filter((e) => e.receipt.outcome === "deny");
  const observed = entries.filter((e) => String(e.result.code ?? "").startsWith("observed-")).length;
  const prefs = entries.flatMap((e) => e.result.rationale?.preferences ?? []);
  const matched = prefs.filter((p) => p.startsWith("matches")).length;
  const flags = entries.flatMap((e) => e.result.rationale?.flags ?? []);
  const sponsored = flags.filter((f) => /sponsored/.test(f)).length, subs = flags.filter((f) => /^substitution/.test(f)).length, personal = flags.filter((f) => /^personal data/.test(f)).length;
  const byCode = new Map<string, number>(); for (const b of blocked) { const c = b.result.code ?? "denied"; byCode.set(c, (byCode.get(c) ?? 0) + 1); }
  const approved = entries.filter((e) => /^approved by /.test(String(e.receipt.reason ?? "").replace(/^\[[^\]]+\] /, ""))).length;
  const lines = [
    `${allowed} action(s) within its instructions${approved ? ` (${approved} after your signed approval)` : ""}${observed ? `; ${observed} outside them (observed, not blocked)` : "; none outside them"}.`,
    blocked.length ? `${blocked.length} attempt(s) stopped before reaching the service: ${[...byCode].map(([c, n]) => `${n} ${c}`).join(", ")}.` : "No attempts needed stopping.",
    prefs.length ? `Preferences: matched in ${matched} of ${prefs.length} choice(s).` : "No preference-relevant choices.",
    sponsored || subs || personal ? `Disclosed: ${[sponsored ? `${sponsored} sponsored option(s)` : "", subs ? `${subs} substitution(s)` : "", personal ? `${personal} personal-data share(s)` : ""].filter(Boolean).join(", ")}.` : "Nothing sponsored, substituted or shared that needed disclosure.",
    `Receipts: ${entries.length}, ${verified ? "all signed and verified" : "NOT verified"}.`
  ];
  return { lines, facts: { allowed, approved, blocked: blocked.length, observed, preferences: prefs.length, matched, sponsored, substitutions: subs } };
}


// ---------- v0.7: signed human approvals for exactly one action ----------
/** The identity of one specific action: this mandate, this tool, these arguments. */
export function approvalRequestId(m: Mandate, tool: string, args: unknown): string {
  return "apr_" + argumentsHash({ mandate: mandateDigest(m), tool, args: argumentsHash(args) }).replace(/^sha256:/, "").slice(0, 16);
}
export const DEFAULT_APPROVALS = () => _join(_home(), ".saktum", "approvals.json");
type Approvals = { approvals: Record<string, unknown>[]; used: string[]; pending?: { id: string; tool: string; reason: string; agent: string; at: string }[] };
const readApprovals = (path: string): Approvals => { try { return _exists(path) ? (JSON.parse(_read(path, "utf8")) as Approvals) : { approvals: [], used: [] }; } catch { return { approvals: [], used: [] }; } };
/** v0.10: record an action waiting for approval (for approvals by link). */
export function recordPending(path: string, req: { id: string; tool: string; reason: string; agent: string }) {
  const a = readApprovals(path); a.pending = (a.pending ?? []).filter((p) => p.id !== req.id); a.pending.push({ ...req, at: new Date().toISOString() });
  _mkdir(_dirname(path), { recursive: true }); _write(path, JSON.stringify(a, null, 2) + "\n");
}
export function listPending(path = DEFAULT_APPROVALS()) {
  const a = readApprovals(path);
  return (a.pending ?? []).filter((p) => !a.used.includes(p.id) && !a.approvals.some((x) => (x as { approval?: string }).approval === p.id));
}
/** The principal approves exactly one pending action, for a limited time, once. */
export function approveAction(m: Mandate, requestId: string, ownerKey: SigningKey, minutes = 60, path = DEFAULT_APPROVALS()) {
  if (ownerKey.kid !== m.owner.id) throw new Error("Only the mandate's owner can approve its actions.");
  const a = readApprovals(path);
  const signed = signDocument({ approval: requestId, mandate: mandateDigest(m), approvedBy: m.owner.name ?? m.owner.id, expires: new Date(Date.now() + minutes * 60000).toISOString() }, ownerKey);
  a.approvals.push(signed as never);
  _mkdir(_dirname(path), { recursive: true }); _write(path, JSON.stringify(a, null, 2) + "\n");
  return signed as { approval: string; expires: string };
}
/** Use a valid, unexpired, unused approval signed by the mandate's owner for exactly this action (single use). */
export function consumeApproval(m: Mandate, requestId: string, path = DEFAULT_APPROVALS()): { ok: true; by: string; at: string } | { ok: false } {
  const a = readApprovals(path);
  if (a.used.includes(requestId)) return { ok: false };
  for (const x of a.approvals as ({ approval: string; mandate: string; approvedBy: string; expires: string; signature: { kid?: string } } & Record<string, unknown>)[]) {
    if (x.approval !== requestId || x.mandate !== mandateDigest(m) || x.expires < new Date().toISOString()) continue;
    const v = verifyDocument(x as never);
    if (!v.valid || v.kid !== m.owner.id) continue;
    a.used.push(requestId); _write(path, JSON.stringify(a, null, 2) + "\n");
    return { ok: true, by: x.approvedBy, at: new Date().toISOString() };
  }
  return { ok: false };
}

// ---------- v0.8.1: agent maturity (A1-A5), earned from evidence like the server levels (L1-L5) ----------
export function agentMaturity(m: Mandate & IntentMandate, o: { entries?: ReceiptLogEntry[]; verified?: boolean; chainValid?: boolean; revoked?: boolean } = {}) {
  const op = checkOperator(m as never);
  const tier = agentRiskTier(m).tier;
  const bounded = Boolean(m.allow.tools?.length || m.actions?.length) && m.delegation !== true
    && (!(tier === "R3" || tier === "R4") || Boolean(m.constraints?.length || m.approveAbove || m.rules?.length || m.approvalTriggers?.length || m.autonomy === "propose" || m.autonomy === "notify"));
  const entries = o.entries ?? [];
  const actions = entries.filter((e) => e.receipt.outcome === "allow" && e.result.status === "ok").length;
  const outside = entries.filter((e) => String(e.result.code ?? "").startsWith("observed-")).length;
  const explained = entries.length > 0 && o.verified === true && entries.every((e) => Boolean(e.result.code));
  const steps = [
    { level: 1, name: "Identified", met: checkMandate(m).ok, why: "its own identity and a valid mandate signed by its owner" },
    { level: 2, name: "Accountable", met: (op.present && op.valid) || o.chainValid === true, why: "an operator countersignature or an identity chain to an organisation" },
    { level: 3, name: "Bounded", met: bounded, why: "explicit tools or action classes, no sub-delegation, and caps or approvals when it can act irreversibly or spend" },
    { level: 4, name: "Explained", met: explained, why: "signed, verified receipts with a reason for every decision" },
    { level: 5, name: "Proven", met: actions >= 10 && outside === 0 && !o.revoked && explained, why: `a track record of at least 10 actions, none outside its mandate (${actions} so far)` }
  ];
  let level = 0; for (const st of steps) { if (!st.met) break; level = st.level; }
  return { level, label: level ? `A${level} ${steps[level - 1]!.name}` : "Not yet identified", steps };
}
