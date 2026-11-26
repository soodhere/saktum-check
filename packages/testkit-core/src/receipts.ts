// Signed receipts for every agent tool call (v0.4 preview of the gateway). Each receipt is an instance of the receipt
// contract (contracts/receipt.schema.json), signed by the agent side; the log wraps receipts in a hash chain so any
// edit, deletion or reordering is detected. Bilateral receipts (co-signed by the server side) need the gateway.
import { canonicalize, sha256Tag, signDocument, verifyDocument, type Signature, type SigningKey } from "@saktum/sign";

export interface Receipt {
  receiptFormat: "0.1";
  envelope: { envelopeFormat: "0.1"; id: string; protocol: "mcp"; operation: "tools/call"; tool: string; caller: { agent?: string; onBehalfOf?: string }; target: { service: string; version?: string }; argumentsHash: string; timestamp: string; context?: Record<string, unknown> };
  outcome: "allow" | "deny" | "error"; reason?: string; issuedAt: string; signatures: Signature[];
}
export interface ReceiptLogEntry { seq: number; receipt: Receipt; result: { status: "ok" | "tool-error" | "protocol-error" | "blocked" | "no-response"; latencyMs?: number; destructive?: boolean; code?: string; values?: Record<string, string | number>;
    rationale?: { evaluated: { rule: string; ok: boolean }[]; preferences: string[]; flags: string[] }; metering?: { agreement: string; tokens: number; balance: number } }; prevHash: string; entryHash: string }
export const RECEIPTS_GENESIS = "sha256:genesis";

export const argumentsHash = (args: unknown) => sha256Tag(canonicalize(args ?? {}));

export function signReceipt(r: Omit<Receipt, "signatures">, key: SigningKey): Receipt {
  const s = signDocument(r, key) as Omit<Receipt, "signatures"> & { signature: Signature };
  const { signature, ...rest } = s;
  return { ...(rest as Omit<Receipt, "signatures">), signatures: [signature] };
}
export function verifyReceipt(r: Receipt): boolean {
  const { signatures, ...rest } = r;
  return signatures.length > 0 && signatures.every((sig) => verifyDocument({ ...rest, signature: sig }).valid);
}

const entryHashOf = (e: Omit<ReceiptLogEntry, "entryHash">) => sha256Tag(canonicalize(e));
export function chainEntry(prev: { seq: number; entryHash: string } | undefined, receipt: Receipt, result: ReceiptLogEntry["result"]): ReceiptLogEntry {
  const base = { seq: (prev?.seq ?? 0) + 1, receipt, result, prevHash: prev?.entryHash ?? RECEIPTS_GENESIS };
  return { ...base, entryHash: entryHashOf(base) };
}
export function parseReceiptLog(text: string): ReceiptLogEntry[] { return text.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l) as ReceiptLogEntry); }

export function verifyReceiptLog(entries: ReceiptLogEntry[]): { ok: boolean; count: number; errors: string[] } {
  const errors: string[] = [];
  let prev = RECEIPTS_GENESIS;
  entries.forEach((e, i) => {
    if (e.seq !== i + 1) errors.push(`receipt ${i + 1}: sequence ${e.seq}, expected ${i + 1}`);
    if (e.prevHash !== prev) errors.push(`receipt ${e.seq}: chain broken`);
    const { entryHash, ...base } = e;
    if (entryHashOf(base) !== entryHash) errors.push(`receipt ${e.seq}: contents changed after it was recorded`);
    if (!verifyReceipt(e.receipt)) errors.push(`receipt ${e.seq}: signature not valid`);
    prev = entryHash;
  });
  return { ok: errors.length === 0, count: entries.length, errors };
}

/** The path, not the answer: what the agent called, how often, in what order, and what stands out. */
export function summariseReceipts(entries: ReceiptLogEntry[]) {
  const byTool = new Map<string, number>(), repeats = new Map<string, number>();
  for (const e of entries) {
    byTool.set(e.receipt.envelope.tool, (byTool.get(e.receipt.envelope.tool) ?? 0) + 1);
    const k = `${e.receipt.envelope.target.service}/${e.receipt.envelope.tool}/${e.receipt.envelope.argumentsHash}`;
    repeats.set(k, (repeats.get(k) ?? 0) + 1);
  }
  const lat = entries.map((e) => e.result.latencyMs ?? 0).filter((x) => x > 0);
  return {
    calls: entries.length, agents: [...new Set(entries.map((e) => e.receipt.envelope.caller.agent ?? "unidentified"))],
    servers: [...new Set(entries.map((e) => e.receipt.envelope.target.service))],
    byTool: [...byTool].sort((a, b) => b[1] - a[1]).map(([tool, count]) => ({ tool, count })),
    denied: entries.filter((e) => e.receipt.outcome === "deny").length, errors: entries.filter((e) => e.result.status !== "ok" && e.result.status !== "blocked").length,
    destructiveAllowed: entries.filter((e) => e.result.destructive && e.receipt.outcome !== "deny").length,
    repeatedIdenticalCalls: [...repeats].filter(([, n]) => n >= 3).map(([k, n]) => ({ call: k.split("/").slice(0, 2).join("/"), times: n })),
    from: entries[0]?.receipt.issuedAt, to: entries[entries.length - 1]?.receipt.issuedAt,
    medianLatencyMs: lat.length ? [...lat].sort((a, b) => a - b)[Math.floor(lat.length / 2)] : undefined,
    order: entries.slice(0, 50).map((e) => e.receipt.envelope.tool),
    byCode: Object.entries(entries.reduce((a, e) => { const k = e.result.code ?? (e.receipt.outcome === "deny" ? "denied" : "ok"); a[k] = (a[k] ?? 0) + 1; return a; }, {} as Record<string, number>)).map(([code, count]) => ({ code, count }))
  };
}
