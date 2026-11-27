// v0.12 "Trust you can verify": hardening of Saktum's own evidence and state.
import { createHmac } from "node:crypto";
import { canonicalize, sha256Tag, signDocument, verifyDocument, type SigningKey } from "@saktum/sign";
import { mandateDigest, type Mandate } from "./agentid.js";
import type { ReceiptLogEntry } from "./receipts.js";

/** S4: keyed digest of tool arguments, so guessable values (amounts, cities) cannot be recovered from receipts. */
export const keyedDigest = (args: unknown, key: string) => "hmac-sha256:" + createHmac("sha256", key).update(canonicalize(JSON.parse(JSON.stringify(args ?? {})))).digest("hex");

/** S1: a revocation signed by the mandate's owner or operator. */
export function signRevocation(m: Mandate, key: SigningKey, reason?: string) {
  return signDocument({ revocationFormat: "0.1", mandate: mandateDigest(m), agent: m.agent.id, at: new Date().toISOString(), ...(reason ? { reason } : {}) }, key);
}
/** Valid if it names this mandate and (when signed) is signed by its owner or operator. Unsigned legacy entries are honoured: revocation only restricts. */
export function validRevocation(r: unknown, m: Mandate): boolean {
  const x = r as { mandate?: string; signature?: { kid?: string } } | null;
  if (!x || x.mandate !== mandateDigest(m)) return false;
  if (!x.signature) return true;
  const v = verifyDocument(x as never);
  const op = (m as Mandate & { operatorCountersign?: { signature?: { kid?: string } } }).operatorCountersign?.signature?.kid;
  return v.valid && (v.kid === m.owner.id || (Boolean(op) && v.kid === op));
}
/** S1: once the receipt chain shows a revoked decision, the agent stays revoked even if the revocation file is deleted. */
export const revokedInChain = (entries: ReceiptLogEntry[]) => entries.some((e) => e.result.code === "revoked");
/** S12: an approval is single use, enforced by the signed receipt chain, not only by an editable file. */
export const approvalUsedInChain = (entries: ReceiptLogEntry[], rid: string) => entries.some((e) => /approved by/.test(String(e.receipt.reason ?? "")) && String(e.receipt.reason ?? "").includes(`(${rid})`));

/** S3/S7: signed checkpoints of an append-only log (receipts or the ledger), and independent witnesses. */
export interface Checkpoint { checkpointFormat: "0.1"; log: string; seq: number; head: string; at: string; signature?: { kid: string }; witnesses?: unknown[] }
export function makeCheckpoint(entries: { seq: number; entryHash: string }[], key: SigningKey, log = "receipts"): Checkpoint {
  const last = entries[entries.length - 1];
  return signDocument({ checkpointFormat: "0.1", log, seq: last?.seq ?? 0, head: last?.entryHash ?? "sha256:genesis", at: new Date().toISOString() }, key) as Checkpoint;
}
const cpCore = (cp: Checkpoint) => { const { witnesses: _w, ...rest } = cp; return rest; };
export function verifyAgainstCheckpoint(entries: { seq: number; entryHash: string }[], cp: Checkpoint, trustedSigners?: string[]): { ok: boolean; reason?: string } {
  const v = verifyDocument(cpCore(cp) as never);
  if (!v.valid) return { ok: false, reason: "checkpoint signature not valid" };
  if (trustedSigners?.length && !trustedSigners.includes(v.kid!)) return { ok: false, reason: "checkpoint signed by an untrusted key" };
  if (entries.length < cp.seq) return { ok: false, reason: `the log has ${entries.length} entries but the checkpoint covers ${cp.seq}: entries were deleted` };
  const head = cp.seq === 0 ? "sha256:genesis" : entries[cp.seq - 1]?.entryHash;
  if (head !== cp.head) return { ok: false, reason: `entry ${cp.seq} differs from the checkpoint: the log was rewritten` };
  return { ok: true };
}
export function witnessCheckpoint(cp: Checkpoint, entries: { seq: number; entryHash: string }[], key: SigningKey): Checkpoint {
  const ok = verifyAgainstCheckpoint(entries, cp);
  if (!ok.ok) throw new Error(`Not witnessing: ${ok.reason}`);
  return { ...cp, witnesses: [...(cp.witnesses ?? []), signDocument({ witnessFormat: "0.1", checkpoint: sha256Tag(canonicalize(cpCore(cp))), at: new Date().toISOString() }, key)] };
}
export function validWitnesses(cp: Checkpoint): string[] {
  const d = sha256Tag(canonicalize(cpCore(cp)));
  return (cp.witnesses ?? []).flatMap((w) => { const x = w as { checkpoint?: string }; const v = verifyDocument(w as never); return v.valid && x.checkpoint === d ? [v.kid!] : []; });
}

/** S6: domain verification by DNS TXT record (_saktum.<domain> = "saktum-did=<did>") or https://<domain>/.well-known/saktum.json. */
export async function verifyDomain(domain: string, did: string, o: { resolveTxt?: (n: string) => Promise<string[][]>; fetchImpl?: typeof fetch } = {}): Promise<{ verified: boolean; method?: "dns" | "well-known" }> {
  if (!/^[a-z0-9.-]{3,253}$/i.test(domain)) return { verified: false };
  try { const rt = o.resolveTxt ?? (await import("node:dns/promises")).resolveTxt; const recs = await rt(`_saktum.${domain}`); if (recs.flat().some((t) => t.trim() === `saktum-did=${did}`)) return { verified: true, method: "dns" }; } catch { /* try the file */ }
  try { const r = await (o.fetchImpl ?? fetch)(`https://${domain}/.well-known/saktum.json`); if (r.ok) { const j = (await r.json()) as { did?: string; dids?: string[] }; if (j.did === did || j.dids?.includes(did)) return { verified: true, method: "well-known" }; } } catch { /* not verified */ }
  return { verified: false };
}
