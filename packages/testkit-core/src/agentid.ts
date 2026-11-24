// Agent identity and mandates (v0.4 preview of the gateway): an agent gets its own key (did:key); its human owner signs a
// mandate saying which servers and tools it may use, whether destructive actions are allowed, and until when.
import { canonicalize, sha256Tag, signDocument, verifyDocument, type Signature, type SigningKey } from "@saktum/sign";
import { sanitizeText } from "./safe.js";

export interface Mandate {
  mandateFormat: "0.1"; agent: { id: string; name: string }; owner: { id: string; name?: string }; purpose?: string;
  allow: { servers?: string[]; tools?: string[]; destructive: boolean }; issuedAt: string; expires: string; signature: Signature;
}

export function createMandate(o: { agentId: string; agentName: string; ownerName?: string; purpose?: string; servers?: string[]; tools?: string[]; destructive: boolean; expires: string }, ownerKey: SigningKey): Mandate {
  const body = { mandateFormat: "0.1" as const, agent: { id: o.agentId, name: sanitizeText(o.agentName, 120) }, owner: { id: ownerKey.kid, ...(o.ownerName ? { name: sanitizeText(o.ownerName, 120) } : {}) },
    ...(o.purpose ? { purpose: sanitizeText(o.purpose, 300) } : {}),
    allow: { ...(o.servers?.length ? { servers: o.servers } : {}), ...(o.tools?.length ? { tools: o.tools } : {}), destructive: o.destructive }, issuedAt: new Date().toISOString(), expires: o.expires };
  return signDocument(body, ownerKey) as Mandate;
}

/** Valid when the owner's signature checks out and the mandate has not expired. */
export function checkMandate(m: Mandate, today = new Date().toISOString().slice(0, 10)): { ok: true } | { ok: false; reason: string } {
  const v = verifyDocument(m);
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

export const mandateDigest = (m: Mandate) => sha256Tag(canonicalize(m));
