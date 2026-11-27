// v0.12 (beta): passkey approvals. Minimal, dependency-free WebAuthn verification ("none" attestation): the owner
// registers a passkey, then approves an action with Face ID, Touch ID, Windows Hello or a security key. Checks: the
// client data type, challenge and origin; the relying-party hash; user presence; and the signature (ES256 or EdDSA).
import { createHash, createPublicKey, verify, type JsonWebKey } from "node:crypto";

type Cbor = number | string | boolean | null | Uint8Array | Cbor[] | Map<Cbor, Cbor>;
function decodeCbor(buf: Uint8Array): { value: Cbor; length: number } {
  let i = 0;
  const read = (): Cbor => {
    const ib = buf[i++]!, mt = ib >> 5, ai = ib & 31;
    let len = ai;
    if (ai === 24) len = buf[i++]!; else if (ai === 25) { len = (buf[i]! << 8) | buf[i + 1]!; i += 2; } else if (ai === 26) { len = ((buf[i]! << 24) >>> 0) + (buf[i + 1]! << 16) + (buf[i + 2]! << 8) + buf[i + 3]!; i += 4; } else if (ai > 26) throw new Error("unsupported CBOR length");
    switch (mt) {
      case 0: return len;
      case 1: return -1 - len;
      case 2: { const v = buf.slice(i, i + len); i += len; return v; }
      case 3: { const v = new TextDecoder().decode(buf.slice(i, i + len)); i += len; return v; }
      case 4: { const a: Cbor[] = []; for (let k = 0; k < len; k++) a.push(read()); return a; }
      case 5: { const m = new Map<Cbor, Cbor>(); for (let k = 0; k < len; k++) { const key = read(); m.set(key, read()); } return m; }
      case 7: return ai === 20 ? false : ai === 21 ? true : null;
      default: throw new Error("unsupported CBOR type");
    }
  };
  const value = read();
  return { value, length: i };
}
const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest();
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");

function coseToJwk(m: Map<Cbor, Cbor>): JsonWebKey {
  const kty = m.get(1), alg = m.get(3);
  if (kty === 2 && alg === -7) return { kty: "EC", crv: "P-256", x: b64u(m.get(-2) as Uint8Array), y: b64u(m.get(-3) as Uint8Array) };
  if (kty === 1 && alg === -8) return { kty: "OKP", crv: "Ed25519", x: b64u(m.get(-2) as Uint8Array) };
  throw new Error("unsupported passkey algorithm (ES256 and EdDSA are supported)");
}
function checkClientData(clientDataJSON: string, type: string, challenge: string, origin: string) {
  const c = JSON.parse(Buffer.from(clientDataJSON, "base64url").toString("utf8")) as { type?: string; challenge?: string; origin?: string };
  if (c.type !== type) throw new Error("wrong client data type");
  if (c.challenge !== b64u(Buffer.from(challenge))) throw new Error("challenge does not match");
  if (c.origin !== origin) throw new Error("origin does not match");
}

/** Verify a registration ("none" attestation) and return the credential id and public key. */
export function verifyPasskeyRegistration(r: { attestationObject: string; clientDataJSON: string }, expected: { challenge: string; origin: string; rpId: string }) {
  checkClientData(r.clientDataJSON, "webauthn.create", expected.challenge, expected.origin);
  const att = decodeCbor(Buffer.from(r.attestationObject, "base64url")).value as Map<Cbor, Cbor>;
  const ad = att.get("authData") as Uint8Array;
  if (!Buffer.from(ad.slice(0, 32)).equals(sha256(expected.rpId))) throw new Error("relying party does not match");
  const flags = ad[32]!;
  if (!(flags & 0x01)) throw new Error("user presence not confirmed");
  if (!(flags & 0x40)) throw new Error("no credential data");
  const idLen = (ad[53]! << 8) | ad[54]!;
  const credentialId = b64u(ad.slice(55, 55 + idLen));
  const jwk = coseToJwk(decodeCbor(ad.slice(55 + idLen)).value as Map<Cbor, Cbor>);
  return { credentialId, jwk };
}

/** Verify an assertion (an approval) against a registered passkey. */
export function verifyPasskeyAssertion(a: { authenticatorData: string; clientDataJSON: string; signature: string }, jwk: JsonWebKey, expected: { challenge: string; origin: string; rpId: string }): boolean {
  checkClientData(a.clientDataJSON, "webauthn.get", expected.challenge, expected.origin);
  const ad = Buffer.from(a.authenticatorData, "base64url");
  if (!ad.slice(0, 32).equals(sha256(expected.rpId))) throw new Error("relying party does not match");
  if (!(ad[32]! & 0x01)) throw new Error("user presence not confirmed");
  const data = Buffer.concat([ad, sha256(Buffer.from(a.clientDataJSON, "base64url"))]);
  const key = createPublicKey({ key: jwk, format: "jwk" });
  return jwk.kty === "OKP" ? verify(null, data, key, Buffer.from(a.signature, "base64url")) : verify("sha256", data, key, Buffer.from(a.signature, "base64url"));
}
