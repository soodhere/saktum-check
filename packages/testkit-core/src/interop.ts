// v0.6: Saktum's evidence in the standards enterprises already run, and the money it saves.
// - Receipts as OpenTelemetry traces (OTLP/JSON), using the GenAI semantic conventions for tool execution plus saktum.*
//   attributes, so agent calls land in existing observability and security tools.
// - Attestations as W3C Verifiable Credentials (Data Model 2.0), secured as a JWS (VC-JOSE: typ vc+jwt, EdDSA), issued
//   by the signer's did:key, so any credential verifier can check them.
// - ROI: what tool definitions cost and what Saktum saves, with every assumption explicit.
import { createHash, sign as edSign, verify as edVerify } from "node:crypto";
import { publicKeyFromDidKey, type SigningKey } from "@saktum/sign";
import type { ReceiptLogEntry } from "./receipts.js";
import type { Attestation } from "./provider.js";

const hex = (s: string, n: number) => createHash("sha256").update(s).digest("hex").slice(0, n);
const nanos = (iso: string, minusMs = 0) => String(BigInt(Date.parse(iso) - minusMs) * 1_000_000n);
const attr = (key: string, v: string | number | boolean | undefined) => v === undefined ? undefined
  : { key, value: typeof v === "number" ? (Number.isInteger(v) ? { intValue: String(v) } : { doubleValue: v }) : typeof v === "boolean" ? { boolValue: v } : { stringValue: v } };

/** OTLP/JSON traces for a receipt log: one trace per log, one CLIENT span per tool call. */
export function receiptsToOtlp(entries: ReceiptLogEntry[], o: { verified: boolean; serviceName?: string; version?: string }) {
  const traceId = hex(`saktum-trace:${entries[0]?.receipt.envelope.caller.agent ?? ""}:${entries[0]?.receipt.envelope.id ?? ""}`, 32);
  const spans = entries.map((e) => {
    const env = e.receipt.envelope, end = e.receipt.issuedAt, lat = e.result.latencyMs ?? 0;
    const error = e.receipt.outcome !== "allow" || (e.result.status !== "ok");
    return {
      traceId, spanId: hex(`span:${env.id}`, 16), name: `execute_tool ${env.tool}`, kind: 3,
      startTimeUnixNano: nanos(end, lat), endTimeUnixNano: nanos(end),
      attributes: [attr("gen_ai.operation.name", "execute_tool"), attr("gen_ai.tool.name", env.tool), attr("mcp.method.name", "tools/call"),
        attr("server.address", env.target.service), attr("saktum.server.version", env.target.version), attr("saktum.agent.id", env.caller.agent),
        attr("saktum.on_behalf_of", env.caller.onBehalfOf), attr("saktum.outcome", e.receipt.outcome), attr("saktum.reason", e.receipt.reason),
        attr("saktum.result.status", e.result.status), attr("saktum.destructive", e.result.destructive), attr("saktum.arguments.hash", env.argumentsHash),
        attr("saktum.receipt.seq", e.seq), attr("saktum.receipt.entry_hash", e.entryHash), attr("saktum.receipts.verified", o.verified)].filter(Boolean),
      status: error ? { code: 2, message: e.receipt.outcome === "deny" ? `blocked: ${e.receipt.reason ?? ""}` : e.result.status } : { code: 1 }
    };
  });
  return { resourceSpans: [{ resource: { attributes: [attr("service.name", o.serviceName ?? "saktum-proxy"), attr("service.version", o.version)].filter(Boolean) },
    scopeSpans: [{ scope: { name: "saktum", version: o.version }, spans }] }] };
}

const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");

/** A W3C Verifiable Credential (Data Model 2.0) for an attestation. */
export function attestationToCredential(a: Attestation, issuer: string) {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiableCredential", "SaktumMcpServerAttestation"],
    issuer, validFrom: a.checkedAt,
    credentialSubject: {
      id: `urn:saktum:mcp-server:${(a.subject.toolsFingerprint ?? "unknown").replace(/^sha256:/, "")}`,
      server: a.subject.server, version: a.subject.version, transport: a.subject.transport, toolsFingerprint: a.subject.toolsFingerprint,
      trustGrade: a.claims.trustGrade, readinessGrade: a.claims.readinessGrade, maturityEvidence: a.claims.evidence,
      assuranceLevel: a.claims.assuranceLevel, checkedWith: a.checkedWith, resultDigest: a.resultDigest
    }
  };
}

/** Secure a credential as a compact JWS (VC-JOSE: typ vc+jwt), EdDSA with the issuer's did:key. */
export function signCredentialJwt(vc: Record<string, unknown>, key: SigningKey): string {
  const header = { alg: "EdDSA", typ: "vc+jwt", cty: "vc", kid: `${key.kid}#${key.kid.slice("did:key:".length)}` };
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(vc))}`;
  return `${input}.${b64u(edSign(null, Buffer.from(input), key.privateKey))}`;
}

/** Verify a vc+jwt issued by a did:key: signature, header, and that the issuer matches the signing key. */
export function verifyCredentialJwt(jwt: string): { valid: true; credential: Record<string, unknown>; issuer: string } | { valid: false; reason: string } {
  try {
    const [h, p, s] = jwt.trim().split(".");
    if (!h || !p || !s) return { valid: false, reason: "not a compact JWS" };
    const header = JSON.parse(Buffer.from(h, "base64url").toString("utf8")) as { alg?: string; typ?: string; kid?: string };
    const vc = JSON.parse(Buffer.from(p, "base64url").toString("utf8")) as Record<string, unknown> & { issuer?: string };
    if (header.alg !== "EdDSA" || header.typ !== "vc+jwt") return { valid: false, reason: "unexpected header (expected EdDSA, vc+jwt)" };
    const did = String(header.kid ?? "").split("#")[0]!;
    if (!did.startsWith("did:key:")) return { valid: false, reason: "issuer key is not a did:key" };
    if (vc.issuer !== did) return { valid: false, reason: "the credential's issuer does not match the signing key" };
    const ok = edVerify(null, Buffer.from(`${h}.${p}`), publicKeyFromDidKey(did), Buffer.from(s, "base64url"));
    return ok ? { valid: true, credential: vc, issuer: did } : { valid: false, reason: "signature does not match" };
  } catch (e) { return { valid: false, reason: (e as Error).message }; }
}

export interface RoiInputs { tokensPerTurn: number; turnsPerDay: number; agents: number; pricePerMTok: number; wasteShare: number; vendorReviews: number; hoursPerReview: number; hourlyCost: number; reviewTimeSaved: number }
export const ROI_DEFAULTS: Omit<RoiInputs, "tokensPerTurn"> = { turnsPerDay: 1000, agents: 1, pricePerMTok: 3, wasteShare: 0.3, vendorReviews: 0, hoursPerReview: 20, hourlyCost: 100, reviewTimeSaved: 0.6 };

/** Annual cost of tool definitions, the share Saktum's fixes can remove, and vendor-review effort replaced by passports. */
export function roiEstimate(i: RoiInputs) {
  const annualToolCost = (i.tokensPerTurn * i.turnsPerDay * 365 * i.agents * i.pricePerMTok) / 1e6;
  const tokenSavings = annualToolCost * i.wasteShare;
  const reviewSavings = i.vendorReviews * i.hoursPerReview * i.hourlyCost * i.reviewTimeSaved;
  const r = (x: number) => Math.round(x);
  return { annualToolCost: r(annualToolCost), tokenSavings: r(tokenSavings), reviewSavings: r(reviewSavings), totalSavings: r(tokenSavings + reviewSavings),
    assumptions: `${i.tokensPerTurn.toLocaleString("en-US")} tokens of tool definitions per turn, ${i.turnsPerDay.toLocaleString("en-US")} turns a day, ${i.agents} agent(s), $${i.pricePerMTok} per million input tokens, ${Math.round(i.wasteShare * 100)}% removable (duplicates, unused servers, oversized definitions)${i.vendorReviews ? `; ${i.vendorReviews} vendor reviews a year at ${i.hoursPerReview} hours and $${i.hourlyCost} an hour, ${Math.round(i.reviewTimeSaved * 100)}% of the effort replaced by passports` : ""}` };
}
