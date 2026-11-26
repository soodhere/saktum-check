// v0.8: from trust to a marketplace. Identity chains (organisation -> person or agent), agent manifests and a
// catalogue searchable by intent, two-party agreements (smart contracts as signed documents), metering in prepaid tokens
// with a double-entry wallet (no money handled), usage statements, and KPIs over receipts.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { signDocument, verifyDocument, type SigningKey } from "@saktum/sign";
import { actionClass, bindingsFor } from "./vocab.js";
import { argumentsHash, type ReceiptLogEntry } from "./receipts.js";

const short = (prefix: string, x: unknown) => prefix + argumentsHash(JSON.parse(JSON.stringify(x))).replace(/^sha256:/, "").slice(0, 16);
const nowIso = () => new Date().toISOString();
const body = <T extends Record<string, unknown>>(d: T) => { const { signature: _s, countersignature: _c, ...rest } = d as Record<string, unknown>; return rest; };

// ---------- identity chains ----------
export interface Credential { credentialFormat: "0.1"; id: string; type: "organisation" | "member" | "agent"; subject: { id: string; name: string; role?: string }; issuer: { id: string; name: string; domain?: string }; chain?: Credential[]; issuedAt: string; expires: string; signature?: { kid: string } }
/** An organisation's self-issued root credential (domain-bound when a domain is given). */
export function organisationRoot(o: { name: string; domain?: string; expires: string }, key: SigningKey): Credential {
  const c = { credentialFormat: "0.1" as const, type: "organisation" as const, subject: { id: key.kid, name: o.name }, issuer: { id: key.kid, name: o.name, ...(o.domain ? { domain: o.domain } : {}) }, issuedAt: nowIso(), expires: o.expires };
  return signDocument({ ...c, id: short("cred_", c) }, key) as Credential;
}
/** An issuer (the organisation, or a member it credentialed) issues a credential to a person or an agent. */
export function issueCredential(issuerCred: Credential, issuerKey: SigningKey, s: { type: "member" | "agent"; id: string; name: string; role?: string; expires: string }): Credential {
  if (issuerCred.subject.id !== issuerKey.kid) throw new Error("The signing key does not belong to the issuer's credential.");
  if (issuerCred.type === "agent") throw new Error("Agents cannot issue credentials.");
  const chain = [...(issuerCred.chain ?? []), { ...issuerCred, chain: undefined }].map((c) => JSON.parse(JSON.stringify(c)) as Credential);
  const c = { credentialFormat: "0.1" as const, type: s.type, subject: { id: s.id, name: s.name, ...(s.role ? { role: s.role } : {}) }, issuer: { id: issuerKey.kid, name: issuerCred.subject.name, ...(issuerCred.issuer.domain ? { domain: issuerCred.issuer.domain } : {}) }, issuedAt: nowIso(), expires: s.expires };
  // Each credential is signed without its chain; the chain (the issuers' own credentials) is attached afterwards and
  // every link is verified exactly as it was signed.
  return { ...(signDocument({ ...c, id: short("cred_", c) }, issuerKey) as Credential), chain };
}
/** Walk the chain from the subject to the organisation root: every signature, every link, every expiry, every revocation. */
export function verifyChain(c: Credential, o: { revoked?: string[]; today?: string } = {}): { valid: boolean; path: string[]; organisation?: string; reason?: string } {
  const today = o.today ?? nowIso();
  const links = [...(c.chain ?? []), { ...c, chain: undefined }];
  const path: string[] = [];
  for (let i = 0; i < links.length; i++) {
    const l = links[i]!;
    const v = verifyDocument(JSON.parse(JSON.stringify({ ...l, chain: undefined })) as never);
    if (!v.valid) return { valid: false, path, reason: `signature not valid on ${l.subject.name}'s credential` };
    if (v.kid !== l.issuer.id) return { valid: false, path, reason: `${l.subject.name}'s credential was not signed by its stated issuer` };
    if (l.expires < today.slice(0, l.expires.length)) return { valid: false, path, reason: `${l.subject.name}'s credential expired on ${l.expires}` };
    if (o.revoked?.includes(l.id)) return { valid: false, path, reason: `${l.subject.name}'s credential was revoked` };
    if (i === 0 && (l.type !== "organisation" || l.issuer.id !== l.subject.id)) return { valid: false, path, reason: "the chain does not start at an organisation" };
    if (i > 0 && l.issuer.id !== links[i - 1]!.subject.id) return { valid: false, path, reason: `${l.subject.name}'s issuer is not the previous link in the chain` };
    path.push(`${l.subject.name}${l.subject.role ? ` (${l.subject.role})` : ""}`);
  }
  return { valid: true, path, organisation: links[0]!.subject.name + (links[0]!.issuer.domain ? ` (${links[0]!.issuer.domain})` : "") };
}
/** Agents whose accountability chain is broken: expired, revoked, or with a missing or invalid link. */
export function findOrphans(creds: Credential[], o: { revoked?: string[] } = {}) {
  return creds.filter((c) => c.type === "agent").map((c) => ({ agent: c.subject.name, id: c.subject.id, ...verifyChain(c, o) })).filter((x) => !x.valid);
}

// ---------- manifests and the catalogue ----------
type ToolLike = { name: string; description?: string; inputSchema?: unknown; annotations?: Record<string, unknown>; _meta?: Record<string, unknown> };
export interface Manifest { manifestFormat: "0.1"; id: string; publisher: { id: string; name: string; domain?: string }; server: { name: string; version: string; toolsFingerprint?: string };
  categories: string[]; intents: string[]; capabilities: { tool: string; action: string; fields: string[]; description: string }[]; rates: { perCall: number; perTool?: Record<string, number> };
  quality?: { trustGrade?: string | null; readinessGrade?: string | null; riskTier?: string }; documentation?: string; bounties?: string[]; issuedAt: string; signature?: { kid: string } }
const CAT: Record<string, string> = { commerce: "Commerce and shopping", travel: "Travel", personal: "Personal data", enterprise: "Business operations" };
/** What a server offers, signed by its publisher: capabilities with intents and categories derived from bindings. */
export function buildManifest(o: { publisher: { name: string; domain?: string }; server: { name: string; version: string; toolsFingerprint?: string }; tools: ToolLike[]; rates: Manifest["rates"]; categories?: string[]; quality?: Manifest["quality"]; documentation?: string }, key: SigningKey): Manifest {
  const caps = o.tools.map((t) => { const b = bindingsFor(t).bindings; return { tool: t.name, action: actionClass(t).cls, fields: [...new Set(Object.values(b))], description: (t.description ?? "").split(/(?<=[.!?])\s/)[0]!.slice(0, 160) }; });
  const domains = [...new Set(caps.flatMap((c) => c.fields.map((f) => f.split(".")[0]!)))].filter((d) => d !== "personal" && d !== "party");
  const intents = [...new Set(caps.flatMap((c) => (domains.length ? domains : ["general"]).map((d) => `${c.action}:${d}`)))];
  const m = { manifestFormat: "0.1" as const, publisher: { id: key.kid, ...o.publisher }, server: o.server, categories: o.categories ?? domains.map((d) => CAT[d] ?? d), intents, capabilities: caps, rates: o.rates,
    ...(o.quality ? { quality: o.quality } : {}), ...(o.documentation ? { documentation: o.documentation } : {}), issuedAt: nowIso() };
  return signDocument({ ...m, id: short("man_", { ...m, issuedAt: undefined }) }, key) as Manifest;
}
const WORDS: Record<string, string[]> = { search: ["find", "search", "look", "browse", "deal", "deals"], cart: ["buy", "shop", "shopping", "groceries", "grocery", "cart", "order"], pay: ["pay", "payment", "checkout", "invoice", "purchase"],
  book: ["book", "booking", "reserve", "flight", "flights", "trip", "travel"], change: ["change", "seat", "upgrade", "modify"], communicate: ["send", "share", "email", "report"], cancel: ["cancel", "refund"] };
/** Search the catalogue by intent and keywords; only signed, valid manifests are returned. */
export function searchCatalogue(entries: Manifest[], query: string, o: { maxRisk?: string } = {}) {
  const q = query.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 2);
  return entries.filter((m) => verifyDocument(m as never).valid && (!o.maxRisk || !m.quality?.riskTier || m.quality.riskTier <= o.maxRisk)).map((m) => {
    let score = 0; const why: string[] = [];
    for (const it of m.intents) { const [a, d] = it.split(":"); const hit = q.filter((w) => (WORDS[a!] ?? []).includes(w) || w === d || (d === "commerce" && ["groceries", "grocery", "shop", "shopping", "buy"].includes(w)) || (d === "travel" && ["flight", "flights", "trip", "travel"].includes(w)));
      if (hit.length) { score += 2 * hit.length; why.push(it); } }
    const text = `${m.server.name} ${m.categories.join(" ")} ${m.capabilities.map((c) => `${c.tool} ${c.description}`).join(" ")}`.toLowerCase();
    for (const w of q) if (text.includes(w)) score += 1;
    return { manifest: m, score, matched: [...new Set(why)] };
  }).filter((r) => r.score > 0).sort((a, b) => b.score - a.score);
}

// ---------- agreements (smart contracts as signed documents) ----------
export interface Agreement { agreementFormat: "0.1"; id: string; template: string; purpose: string; provider: { id: string; name: string; manifest: string }; invoker: { id: string; name: string };
  scope: { tools?: string[] }; rates: Manifest["rates"]; limits?: { tokensPerMonth?: number }; terms: string[]; specificTerms?: string[]; dataTerms?: string; disputeContact?: string; validFrom: string; validUntil: string;
  signature?: { kid: string }; countersignature?: { by: string; agreement: string; signature?: { kid: string } } }
export const DEFAULT_TERMS = [
  "The provider operates the service as described in its signed manifest; material changes to tools require a new manifest.",
  "The invoker's agents act only within their mandates; the provider may refuse calls outside the agreed scope.",
  "Each call is metered in prepaid tokens at the agreed rates; settlement in money happens outside Saktum.",
  "Both parties keep signed receipts; either may present them as evidence in a dispute.",
  "Personal and classified data are shared only as the invoker's mandates permit.",
  "Either party may end the agreement with notice; receipts and usage statements remain valid evidence."
];
/** The provider drafts and signs an agreement from the default template plus specific terms. */
export function draftAgreement(o: { manifest: Manifest; invoker: { id: string; name: string }; purpose: string; tools?: string[]; rates?: Manifest["rates"]; tokensPerMonth?: number; specificTerms?: string[]; dataTerms?: string; disputeContact?: string; validUntil: string }, providerKey: SigningKey): Agreement {
  if (providerKey.kid !== o.manifest.publisher.id) throw new Error("Only the manifest's publisher can offer an agreement for it.");
  const a = { agreementFormat: "0.1" as const, template: "saktum-default-0.1", purpose: o.purpose, provider: { id: providerKey.kid, name: o.manifest.publisher.name, manifest: o.manifest.id }, invoker: o.invoker,
    scope: { ...(o.tools?.length ? { tools: o.tools } : {}) }, rates: o.rates ?? o.manifest.rates, ...(o.tokensPerMonth ? { limits: { tokensPerMonth: o.tokensPerMonth } } : {}), terms: DEFAULT_TERMS,
    ...(o.specificTerms?.length ? { specificTerms: o.specificTerms } : {}), ...(o.dataTerms ? { dataTerms: o.dataTerms } : {}), ...(o.disputeContact ? { disputeContact: o.disputeContact } : {}), validFrom: nowIso().slice(0, 10), validUntil: o.validUntil };
  return signDocument({ ...a, id: short("agr_", a) }, providerKey) as Agreement;
}
/** The invoker accepts by countersigning the exact agreement. */
export function acceptAgreement(a: Agreement, invokerKey: SigningKey): Agreement {
  if (invokerKey.kid !== a.invoker.id) throw new Error("Only the named invoker can accept this agreement.");
  return { ...a, countersignature: signDocument({ by: invokerKey.kid, agreement: argumentsHash(body(a as never)) }, invokerKey) as never };
}
export function verifyAgreement(a: Agreement, today = nowIso().slice(0, 10)): { valid: boolean; reason?: string } {
  const { countersignature: cs, ...providerPart } = a;
  const p = verifyDocument(providerPart as never);
  if (!p.valid || p.kid !== a.provider.id) return { valid: false, reason: "the provider's signature is not valid" };
  if (!cs) return { valid: false, reason: "not yet accepted by the invoker" };
  const c = verifyDocument(cs as never);
  if (!c.valid || c.kid !== a.invoker.id || cs.agreement !== argumentsHash(body(a as never))) return { valid: false, reason: "the invoker's countersignature is not valid for this agreement" };
  if (a.validUntil < today) return { valid: false, reason: `expired on ${a.validUntil}` };
  return { valid: true };
}
export const tokensFor = (a: Agreement, tool: string) => a.rates.perTool?.[tool] ?? a.rates.perCall;

// ---------- the wallet: prepaid tokens, double-entry ----------
export interface WalletEntry { at: string; from: string; to: string; tokens: number; ref: string }
const readWallet = (path: string): { entries: WalletEntry[] } => { try { return existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : { entries: [] }; } catch { return { entries: [] }; } };
const writeWallet = (path: string, w: { entries: WalletEntry[] }) => { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, JSON.stringify(w, null, 2) + "\n"); };
export const PREPAID = "saktum:prepaid";
export function walletBalance(path: string, account: string): number { return readWallet(path).entries.reduce((b, e) => b + (e.to === account ? e.tokens : 0) - (e.from === account ? e.tokens : 0), 0); }
/** Add prepaid tokens to an account (bought outside Saktum; no money is handled here). */
export function topUp(path: string, account: string, tokens: number, ref = "top-up") { const w = readWallet(path); w.entries.push({ at: nowIso(), from: PREPAID, to: account, tokens, ref }); writeWallet(path, w); return walletBalance(path, account); }
/** Move tokens for one metered call: debit the invoker, credit the provider, or refuse if credit is insufficient. */
export function chargeCall(path: string, a: Agreement, tool: string, ref: string): { ok: true; tokens: number; balance: number } | { ok: false; tokens: number; balance: number } {
  const cost = tokensFor(a, tool), bal = walletBalance(path, a.invoker.id);
  if (bal < cost) return { ok: false, tokens: cost, balance: bal };
  const w = readWallet(path); w.entries.push({ at: nowIso(), from: a.invoker.id, to: a.provider.id, tokens: cost, ref }); writeWallet(path, w);
  return { ok: true, tokens: cost, balance: bal - cost };
}

// ---------- usage statements and KPIs ----------
/** A usage statement for one agreement from the receipts: calls and tokens per tool, signed by whoever produces it. */
export function usageStatement(entries: ReceiptLogEntry[], a: Agreement, key?: SigningKey) {
  const metered = entries.filter((e) => e.result.metering?.agreement === a.id);
  const byTool = new Map<string, { calls: number; tokens: number }>();
  for (const e of metered) { const t = e.receipt.envelope.tool; const x = byTool.get(t) ?? { calls: 0, tokens: 0 }; x.calls++; x.tokens += e.result.metering!.tokens; byTool.set(t, x); }
  const s = { statementFormat: "0.1", agreement: a.id, provider: a.provider.name, invoker: a.invoker.name, from: metered[0]?.receipt.issuedAt ?? null, to: metered[metered.length - 1]?.receipt.issuedAt ?? null,
    lines: [...byTool].map(([tool, v]) => ({ tool, calls: v.calls, tokens: v.tokens })), totalTokens: metered.reduce((n, e) => n + e.result.metering!.tokens, 0),
    receipts: metered.map((e) => e.entryHash), producedAt: nowIso() };
  return key ? signDocument(s, key) : s;
}
/** KPIs over receipts, with optional filters. */
export function kpis(entries: ReceiptLogEntry[], f: { tool?: string; agent?: string; since?: string } = {}) {
  const xs = entries.filter((e) => (!f.tool || e.receipt.envelope.tool === f.tool) && (!f.agent || e.receipt.envelope.caller.agent === f.agent) && (!f.since || e.receipt.issuedAt >= f.since));
  const lat = xs.map((e) => e.result.latencyMs).filter((n): n is number => typeof n === "number").sort((a, b) => a - b);
  const pct = (p: number) => (lat.length ? lat[Math.min(lat.length - 1, Math.floor((p / 100) * lat.length))] : null);
  const by = (k: (e: ReceiptLogEntry) => string) => Object.entries(xs.reduce((m, e) => { const key = k(e); m[key] = (m[key] ?? 0) + 1; return m; }, {} as Record<string, number>)).sort((a, b) => b[1] - a[1]);
  return { calls: xs.length, allowed: xs.filter((e) => e.receipt.outcome === "allow").length, blocked: xs.filter((e) => e.receipt.outcome === "deny").length,
    approvals: xs.filter((e) => /approved by/.test(String(e.receipt.reason ?? ""))).length, tokens: xs.reduce((n, e) => n + (e.result.metering?.tokens ?? 0), 0),
    latencyP50: pct(50), latencyP95: pct(95), byOutcome: by((e) => e.result.code ?? e.receipt.outcome), byTool: by((e) => e.receipt.envelope.tool) };
}
