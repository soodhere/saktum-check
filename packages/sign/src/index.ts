// Signing for Trust Check results: RFC 8785 canonical JSON, Ed25519, detached JWS (RFC 7515), did:key identifiers.
// Uses Node's built-in crypto only (see docs/adr/0004-signing.md).
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

/** RFC 8785 JSON canonicalisation (keys sorted by UTF-16 code units, ES number serialisation). */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonicalize: non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map((v) => (v === undefined ? "null" : canonicalize(v))).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
  }
  throw new Error(`canonicalize: unsupported type ${typeof value}`);
}

export const sha256Hex = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");
export const sha256Tag = (data: string | Buffer): string => "sha256:" + sha256Hex(data);
const b64u = (b: Buffer): string => b.toString("base64url");

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58encode(bytes: Uint8Array): string {
  let n = BigInt("0x" + (Buffer.from(bytes).toString("hex") || "0"));
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b === 0) out = "1" + out; else break; }
  return out;
}
function base58decode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) { const i = B58.indexOf(c); if (i < 0) throw new Error("invalid base58"); n = n * 58n + BigInt(i); }
  let hex = n.toString(16); if (hex.length % 2) hex = "0" + hex;
  const lead = s.match(/^1*/)?.[0].length ?? 0;
  return Uint8Array.from([...new Array<number>(lead).fill(0), ...Buffer.from(n === 0n ? "" : hex, "hex")]);
}

const ED25519_MULTICODEC = [0xed, 0x01];

export function didKeyFromPublicKey(publicKey: KeyObject): string {
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
  return "did:key:z" + base58encode(Uint8Array.from([...ED25519_MULTICODEC, ...raw]));
}

export function publicKeyFromDidKey(did: string): KeyObject {
  if (!did.startsWith("did:key:z")) throw new Error("not a did:key with base58btc encoding");
  const bytes = base58decode(did.slice("did:key:z".length));
  if (bytes[0] !== 0xed || bytes[1] !== 0x01 || bytes.length !== 34) throw new Error("not an Ed25519 did:key");
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(bytes.slice(2)).toString("base64url") }, format: "jwk" });
}

export interface SigningKey { privateKey: KeyObject; publicKey: KeyObject; kid: string }

export function generateSigningKey(): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey, kid: didKeyFromPublicKey(publicKey) };
}

export const defaultKeyPath = (): string => join(process.env.SAKTUM_HOME ?? join(homedir(), ".config", "saktum"), "key.jwk.json");

/** Load the local signing key, creating one (readable only by the user) on first use. */
export function loadOrCreateKey(path = defaultKeyPath()): SigningKey {
  if (existsSync(path)) {
    const jwk = JSON.parse(readFileSync(path, "utf8"));
    const privateKey = createPrivateKey({ key: jwk, format: "jwk" });
    const publicKey = createPublicKey(privateKey);
    return { privateKey, publicKey, kid: didKeyFromPublicKey(publicKey) };
  }
  const key = generateSigningKey();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(key.privateKey.export({ format: "jwk" })), { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch { /* best effort on Windows */ }
  return key;
}

export interface Signature { alg: "EdDSA"; kid: string; jws: string }

/** Sign a document (any existing "signature" member is excluded) as a detached JWS over its canonical JSON. */
export function signDocument<T extends object>(doc: T, key: SigningKey): Omit<T, "signature"> & { signature: Signature } {
  const { signature: _ignored, ...body } = doc as T & { signature?: unknown };
  const header = b64u(Buffer.from(JSON.stringify({ alg: "EdDSA", kid: key.kid })));
  const payload = b64u(Buffer.from(canonicalize(body)));
  const sig = sign(null, Buffer.from(`${header}.${payload}`), key.privateKey);
  return { ...(body as Omit<T, "signature">), signature: { alg: "EdDSA", kid: key.kid, jws: `${header}..${b64u(sig)}` } };
}

export interface VerifyOutcome { valid: boolean; kid?: string; reason?: string }

export function verifyDocument(doc: object & { signature?: Signature }): VerifyOutcome {
  const s = doc.signature;
  if (!s) return { valid: false, reason: "no signature" };
  const parts = s.jws.split(".");
  if (parts.length !== 3 || parts[1] !== "") return { valid: false, reason: "malformed detached JWS" };
  let header: { alg?: string; kid?: string };
  try { header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")); } catch { return { valid: false, reason: "bad header" }; }
  if (header.alg !== "EdDSA" || header.kid !== s.kid) return { valid: false, reason: "header does not match signature metadata" };
  let publicKey: KeyObject;
  try { publicKey = publicKeyFromDidKey(s.kid); } catch (e) { return { valid: false, reason: (e as Error).message }; }
  const { signature: _s, ...body } = doc;
  const payload = b64u(Buffer.from(canonicalize(body)));
  const ok = verify(null, Buffer.from(`${parts[0]}.${payload}`), publicKey, Buffer.from(parts[2]!, "base64url"));
  return ok ? { valid: true, kid: s.kid } : { valid: false, kid: s.kid, reason: "signature does not match content" };
}
