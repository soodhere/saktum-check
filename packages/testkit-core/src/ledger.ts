// The Saktum trust ledger (v0.4): Certificate Transparency for AI agent tools. Providers publish signed attestations to
// an append-only, hash-chained public log; anyone can verify every signature and the chain; firewalls and enterprises
// can build allowlists from it. Entries are signed claims (assurance as stated in each attestation, L1 = self-tested):
// appending verifies signatures and the chain, and never runs anyone's code.
import { canonicalize, sha256Tag, verifyDocument, type Signature } from "@saktum/sign";
import type { Attestation } from "./provider.js";
import { sanitizeText } from "./safe.js";

export type SignedAttestation = Attestation & { signature: Signature };
export interface LedgerEntry {
  ledgerFormat: "0.1"; seq: number; recordedAt: string; source: { issue?: number; via?: string };
  subject: { server: string; version?: string; toolsFingerprint?: string };
  signer: string; attestation: SignedAttestation; prevHash: string; entryHash: string;
  /** v0.12: a key rotation or revocation statement instead of an attestation (attestation is then absent). */
  statement?: Statement;
}
export type Statement = { statementFormat: "0.1"; type: "key-rotation" | "revocation"; oldKey?: string; newKey?: string; newKeyProof?: unknown; target?: string; reason?: string; at: string; signature: Signature };
/** v0.12: check a key-rotation statement (signed by the old key, with proof of possession of the new key) or a revocation (signed by the key being revoked or the attestation's signer). */
export function checkStatement(s: unknown): { ok: true; st: Statement; signer: string } | { ok: false; reason: string } {
  const st = s as Statement;
  if (!st || st.statementFormat !== "0.1" || !["key-rotation", "revocation"].includes(st.type)) return { ok: false, reason: "not a Saktum statement" };
  if (JSON.stringify(st).length > MAX_ATTESTATION_BYTES) return { ok: false, reason: "statement too large" };
  const v = verifyDocument(st);
  if (!v.valid) return { ok: false, reason: `signature not valid (${v.reason})` };
  if (st.type === "key-rotation") {
    if (v.kid !== st.oldKey || !st.newKey) return { ok: false, reason: "a rotation must be signed by the old key and name the new key" };
    const pv = verifyDocument(st.newKeyProof as never);
    if (!pv.valid || pv.kid !== st.newKey || (st.newKeyProof as { rotates?: string }).rotates !== st.oldKey) return { ok: false, reason: "missing proof of possession of the new key" };
  } else if (!st.target) return { ok: false, reason: "a revocation must name its target" };
  return { ok: true, st, signer: v.kid! };
}
export function appendStatement(ledgerText: string, statement: unknown, source: LedgerEntry["source"], now = new Date()): { text: string; entry: LedgerEntry } {
  const c = checkStatement(statement);
  if (!c.ok) throw new Error(`Refused: ${c.reason}`);
  const entries = parseLedger(ledgerText);
  const check = verifyLedger(entries);
  if (!check.ok) throw new Error(`Refused: the existing ledger does not verify (${check.errors[0]})`);
  if (c.st.type === "revocation" && !entries.some((e) => e.signer === c.signer && (e.attestation?.resultDigest === c.st.target || e.signer === c.st.target)) && c.st.target !== c.signer) throw new Error("Refused: a revocation must come from the key that signed the target");
  const prev = entries[entries.length - 1];
  const base = { ledgerFormat: "0.1" as const, seq: (prev?.seq ?? 0) + 1, recordedAt: now.toISOString(), source, subject: { server: `${c.st.type}:${c.signer.slice(0, 32)}` }, signer: c.signer, statement: c.st, prevHash: prev?.entryHash ?? GENESIS };
  const entry = { ...base, entryHash: hashOf(base as never) } as unknown as LedgerEntry;
  return { text: `${ledgerText.replace(/\n*$/, ledgerText.trim() ? "\n" : "")}${JSON.stringify(entry)}\n`, entry };
}
/** Keys rotated away from or revoked, and attestations revoked, according to the ledger. */
export function ledgerStatus(entries: LedgerEntry[]) {
  const rotated = new Map<string, string>(), revoked = new Set<string>();
  for (const e of entries) { if (e.statement?.type === "key-rotation") rotated.set(e.statement.oldKey!, e.statement.newKey!); if (e.statement?.type === "revocation") revoked.add(e.statement.target!); }
  return { rotated, revoked };
}
export const GENESIS = "sha256:genesis";
export const DEFAULT_LEDGER_URL = "https://raw.githubusercontent.com/soodhere/saktum-index/main/docs/ledger/ledger.jsonl";
const MAX_ATTESTATION_BYTES = 20_000;

const hashOf = (e: Omit<LedgerEntry, "entryHash">) => sha256Tag(canonicalize(e));

export function parseLedger(text: string): LedgerEntry[] {
  return text.split("\n").map((l) => l.trim()).filter(Boolean).map((l, i) => { try { return JSON.parse(l) as LedgerEntry; } catch { throw new Error(`ledger line ${i + 1} is not valid JSON`); } });
}

/** Check a signed attestation before it may enter the ledger. */
export function checkAttestation(a: unknown): { ok: true; att: SignedAttestation; signer: string } | { ok: false; reason: string } {
  if (!a || typeof a !== "object") return { ok: false, reason: "not a JSON object" };
  if (JSON.stringify(a).length > MAX_ATTESTATION_BYTES) return { ok: false, reason: "attestation too large" };
  const att = a as SignedAttestation;
  if (att.attestationFormat !== "0.1" || !att.subject?.server || !att.claims) return { ok: false, reason: "not a Saktum attestation (make one with saktum attest)" };
  const v = verifyDocument(att);
  if (!v.valid) return { ok: false, reason: `signature not valid (${v.reason})` };
  return { ok: true, att, signer: v.kid! };
}

/** Pull the first JSON object out of text (for example a GitHub issue body with a json code block). */
export function extractJson(text: string): unknown {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/.exec(text);
  const body = fenced ? fenced[1]! : text;
  const start = body.indexOf("{"), end = body.lastIndexOf("}");
  if (start < 0 || end <= start) throw new Error("no JSON object found");
  return JSON.parse(body.slice(start, end + 1));
}

/** Append a verified attestation; returns the new ledger text and the entry. Duplicates are refused. */
export function appendToLedger(ledgerText: string, attestation: unknown, source: LedgerEntry["source"], now = new Date()): { text: string; entry: LedgerEntry } {
  const c = checkAttestation(attestation);
  if (!c.ok) throw new Error(`Refused: ${c.reason}`);
  const entries = parseLedger(ledgerText);
  const check = verifyLedger(entries);
  if (!check.ok) throw new Error(`Refused: the existing ledger does not verify (${check.errors[0]})`);
  if (entries.some((e) => e.signer === c.signer && e.attestation?.resultDigest === c.att.resultDigest)) throw new Error("Refused: this attestation is already in the ledger");
  const prev = entries[entries.length - 1];
  const base: Omit<LedgerEntry, "entryHash"> = { ledgerFormat: "0.1", seq: (prev?.seq ?? 0) + 1, recordedAt: now.toISOString(), source,
    subject: { server: sanitizeText(c.att.subject.server, 200), version: c.att.subject.version, toolsFingerprint: c.att.subject.toolsFingerprint },
    signer: c.signer, attestation: c.att, prevHash: prev?.entryHash ?? GENESIS };
  const entry = { ...base, entryHash: hashOf(base) };
  return { text: `${ledgerText.replace(/\n*$/, ledgerText.trim() ? "\n" : "")}${JSON.stringify(entry)}\n`, entry };
}

/** Verify the whole ledger: sequence, hash chain, entry hashes and every attestation signature. */
export function verifyLedger(entries: LedgerEntry[]): { ok: boolean; count: number; errors: string[] } {
  const errors: string[] = [];
  let prev = GENESIS;
  entries.forEach((e, i) => {
    if (e.seq !== i + 1) errors.push(`entry ${i + 1}: sequence ${e.seq}, expected ${i + 1}`);
    if (e.prevHash !== prev) errors.push(`entry ${e.seq}: chain broken (previous hash does not match)`);
    const { entryHash, ...base } = e;
    if (hashOf(base) !== entryHash) errors.push(`entry ${e.seq}: contents changed after it was recorded`);
    const c = e.statement ? checkStatement(e.statement) : checkAttestation(e.attestation);
    if (!c.ok) errors.push(`entry ${e.seq}: ${c.reason}`);
    else if (c.signer !== e.signer) errors.push(`entry ${e.seq}: signer does not match`);
    prev = entryHash;
  });
  return { ok: errors.length === 0, count: entries.length, errors };
}

export function findInLedger(entries: LedgerEntry[], query: string): LedgerEntry[] {
  entries = entries.filter((e) => e.attestation);
  const q = query.toLowerCase();
  return entries.filter((e) => e.subject.server.toLowerCase().includes(q) || e.subject.toolsFingerprint === query);
}

const GRADES = ["A", "B", "C", "D", "F"];
const atLeast = (g: string | null | undefined, min: string) => g != null && GRADES.indexOf(g) <= GRADES.indexOf(min);

/** An allowlist from ledger entries: the latest entry per server and tool fingerprint that meets the criteria. */
export function allowlistFromLedger(entries: LedgerEntry[], c: { minTrust: string; minReadiness: string; trustedSigners?: Set<string> }) {
  const latest = new Map<string, LedgerEntry>();
  for (const e of entries) latest.set(`${e.subject.server}|${e.subject.toolsFingerprint}`, e);
  const allowed: Record<string, unknown>[] = [], excluded: { server: string; reason: string }[] = [];
  for (const e of latest.values()) {
    if (!e.attestation) continue;
    const cl = e.attestation.claims, why: string[] = [];
    if (c.trustedSigners && !c.trustedSigners.has(e.signer)) why.push("signer is not on your trusted list");
    if (!atLeast(cl.trustGrade, c.minTrust)) why.push(`trust ${cl.trustGrade ?? "not graded"} is below ${c.minTrust}`);
    if (!atLeast(cl.readinessGrade, c.minReadiness)) why.push(`agent readiness ${cl.readinessGrade ?? "not graded"} is below ${c.minReadiness}`);
    if (!e.subject.toolsFingerprint) why.push("no tool fingerprint to pin");
    if (why.length) { excluded.push({ server: e.subject.server, reason: why.join("; ") }); continue; }
    allowed.push({ server: e.subject.server, version: e.subject.version, toolsFingerprint: e.subject.toolsFingerprint, trustGrade: cl.trustGrade, readinessGrade: cl.readinessGrade,
      assuranceLevel: cl.assuranceLevel, checkedAt: e.attestation.checkedAt, checkedWith: e.attestation.checkedWith, signedBy: e.signer, ledgerEntry: e.seq, transport: e.attestation.subject.transport, target: e.attestation.subject.target });
  }
  return { allowlistFormat: "0.1" as const, generatedAt: new Date().toISOString(), criteria: { minTrust: c.minTrust, minReadiness: c.minReadiness, noFailedCritical: true }, allowed, excluded,
    note: "Built from the Saktum trust ledger: signed claims (assurance as stated per entry; L1 = self-tested). Allow each server only while its tools match toolsFingerprint." };
}
