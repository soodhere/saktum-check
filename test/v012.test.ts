// v0.12 "Trust you can verify": every finding from the trust and security review has a test.
import { describe, expect, it } from "vitest";
import { createHash, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appendStatement, appendToLedger, approvalUsedInChain, buildAttestation, checkStatement, createMandate, keyedDigest, ledgerStatus, loadPackDir, makeCheckpoint, parseLedger,
  parseReceiptLog, revokedInChain, runTrustCheck, signRevocation, validRevocation, validWitnesses, verifyAgainstCheckpoint, verifyDomain, verifyLedger, verifyPasskeyAssertion,
  verifyPasskeyRegistration, verifyReceiptLog, verifyWallet, witnessCheckpoint, topUp, decideIntent, checkAttestation } from "@saktum/testkit-core";
import { canonicalize, generateSigningKey, loadOrCreateKey, signDocument, verifyDocument } from "@saktum/sign";
import { connect } from "@saktum/transports";
import { fixture, root } from "./helpers.js";

const owner = generateSigningKey(), agent = generateSigningKey();
const m = createMandate({ agentId: agent.kid, agentName: "B", destructive: false, expires: "2099-01-01" }, owner);
const entry = (seq: number, reason = "ok", code = "ok-action") => ({ seq, entryHash: `sha256:${seq}`, receipt: { reason, envelope: { tool: "t" } }, result: { status: "ok", code } }) as never;

describe("RFC 8785 canonical JSON (S9)", () => {
  it("matches the standard's examples", () => {
    expect(canonicalize({ numbers: [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001], string: "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"/", literals: [null, true, false] }))
      .toBe('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}');
    // Compare the canonical text itself: reading it back into an object would move the integer-like key "1" first.
    expect(canonicalize({ "\u20ac": 1, "\r": 2, "\ufb33": 3, "1": 4, "\ud83d\ude00": 5, "\u0080": 6, "\u00f6": 7 }))
      .toBe('{"\\r":2,"1":4,"\u0080":6,"\u00f6":7,"\u20ac":1,"\ud83d\ude00":5,"\ufb33":3}');
  });
});

describe("state integrity (S1, S2, S3, S12)", () => {
  it("keyed digests hide guessable values (S4)", () => {
    expect(keyedDigest({ amount: 30 }, "k1")).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    expect(keyedDigest({ amount: 30 }, "k1")).not.toBe(keyedDigest({ amount: 30 }, "k2"));
  });
  it("accepts revocations from the owner, rejects forged ones, and remembers revocation in the chain", () => {
    expect(validRevocation(signRevocation(m, owner, "stop"), m)).toBe(true);
    expect(validRevocation(signRevocation(m, generateSigningKey(), "forged"), m)).toBe(false);
    expect(revokedInChain([entry(1), entry(2, "revoked", "revoked")])).toBe(true);
    expect(approvalUsedInChain([entry(1, "[ok-action] approved by B (apr_1234), after: x")], "apr_1234")).toBe(true);
  });
  it("detects deleted and rewritten log entries with checkpoints, and counts witnesses", () => {
    const log = [1, 2, 3, 4].map((n) => ({ seq: n, entryHash: `sha256:h${n}` }));
    const cp = makeCheckpoint(log, owner);
    expect(verifyAgainstCheckpoint(log, cp).ok).toBe(true);
    expect(verifyAgainstCheckpoint(log.slice(0, 3), cp).reason).toMatch(/deleted/);
    expect(verifyAgainstCheckpoint([...log.slice(0, 3), { seq: 4, entryHash: "sha256:evil" }], cp).reason).toMatch(/rewritten/);
    expect(validWitnesses(witnessCheckpoint(cp, log, agent))).toEqual([agent.kid]);
  });
  it("detects an edited wallet (S2)", () => {
    const f = join(mkdtempSync(join(tmpdir(), "w-")), "w.json");
    topUp(f, "acme", 10, "top-up", owner); topUp(f, "acme", 5, "top-up", owner);
    expect(verifyWallet(f).ok).toBe(true);
    const w = JSON.parse(readFileSync(f, "utf8")); w.entries[0].tokens = 1000; writeFileSync(f, JSON.stringify(w));
    expect(verifyWallet(f).ok).toBe(false);
  });
});

describe("identity and the ledger (S6, S7, S13)", () => {
  it("verifies a domain by DNS record or well-known file", async () => {
    expect(await verifyDomain("acme.example", owner.kid, { resolveTxt: async () => [[`saktum-did=${owner.kid}`]], fetchImpl: (async () => ({ ok: false })) as never })).toEqual({ verified: true, method: "dns" });
    expect(await verifyDomain("acme.example", owner.kid, { resolveTxt: async () => { throw new Error("none"); }, fetchImpl: (async () => ({ ok: true, json: async () => ({ did: owner.kid }) })) as never })).toEqual({ verified: true, method: "well-known" });
    expect((await verifyDomain("acme.example", owner.kid, { resolveTxt: async () => [["other"]], fetchImpl: (async () => ({ ok: false })) as never })).verified).toBe(false);
  });
  it("records key rotations and revocations in the ledger, and refuses invalid ones", async () => {
    const att = signDocument(buildAttestation(await runTrustCheck(fixture("good"), { packs: loadPackDir(root + "packs") })), owner);
    let text = appendToLedger("", att, { issue: 1 }).text;
    const nk = generateSigningKey();
    const rot = signDocument({ statementFormat: "0.1", type: "key-rotation", oldKey: owner.kid, newKey: nk.kid, newKeyProof: signDocument({ rotates: owner.kid }, nk), at: "2026-12-01T00:00:00Z" }, owner);
    text = appendStatement(text, rot, { issue: 2 }).text;
    const rev = signDocument({ statementFormat: "0.1", type: "revocation", target: (att as { resultDigest: string }).resultDigest, at: "2026-12-01T00:00:00Z" }, owner);
    text = appendStatement(text, rev, { issue: 3 }).text;
    const entries = parseLedger(text);
    expect(verifyLedger(entries)).toMatchObject({ ok: true, count: 3 });
    expect(ledgerStatus(entries).rotated.get(owner.kid)).toBe(nk.kid);
    expect(checkStatement({ ...rot, newKeyProof: undefined })).toMatchObject({ ok: false });
    expect(() => appendStatement(text, signDocument({ statementFormat: "0.1", type: "revocation", target: (att as { resultDigest: string }).resultDigest, at: "x" }, generateSigningKey()), {})).toThrow(/key that signed/);
    expect(checkAttestation(att).ok).toBe(true);
  }, 60_000);
  it.skipIf(process.platform === "win32")("signs with an external signer; the private key never enters Saktum", () => {
    const dir = mkdtempSync(join(tmpdir(), "ext-"));
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    writeFileSync(join(dir, "k.json"), JSON.stringify({ priv: privateKey.export({ format: "jwk" }), pub: publicKey.export({ format: "jwk" }) }));
    writeFileSync(join(dir, "signer.mjs"), `import {readFileSync} from "node:fs";import {createPrivateKey,sign} from "node:crypto";const k=JSON.parse(readFileSync(${JSON.stringify(join(dir, "k.json"))},"utf8"));if(process.argv[2]==="public"){process.stdout.write(JSON.stringify(k.pub));}else{let d="";process.stdin.on("data",c=>d+=c).on("end",()=>process.stdout.write(sign(null,Buffer.from(d.trim(),"base64"),createPrivateKey({key:k.priv,format:"jwk"})).toString("base64")));}`);
    writeFileSync(join(dir, "signer"), `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(join(dir, "signer.mjs"))} "$@"\n`); chmodSync(join(dir, "signer"), 0o755);
    const k = loadOrCreateKey(`exec:${join(dir, "signer")}`);
    expect(verifyDocument(signDocument({ hello: "world" }, k))).toMatchObject({ valid: true, kid: k.kid });
  });
});

describe("passkey approvals (beta)", () => {
  const enc = (v: unknown): Buffer => { // minimal CBOR encoder for the simulated authenticator
    const head = (mt: number, n: number) => n < 24 ? Buffer.from([(mt << 5) | n]) : n < 256 ? Buffer.from([(mt << 5) | 24, n]) : Buffer.from([(mt << 5) | 25, n >> 8, n & 255]);
    if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
    if (typeof v === "string") { const b = Buffer.from(v); return Buffer.concat([head(3, b.length), b]); }
    if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
    if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [enc(k), enc(x)])]);
    throw new Error("unsupported");
  };
  it("verifies a registration and an approval from a simulated authenticator, and rejects a wrong challenge", () => {
    const origin = "http://localhost:8787", rpId = "localhost";
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
    const credId = Buffer.from("credential-1");
    const rpHash = createHash("sha256").update(rpId).digest();
    const cose = enc(new Map<unknown, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]));
    const authReg = Buffer.concat([rpHash, Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), Buffer.from([0, credId.length]), credId, cose]);
    const cd = (type: string, challenge: string) => Buffer.from(JSON.stringify({ type, challenge: Buffer.from(challenge).toString("base64url"), origin })).toString("base64url");
    const reg = verifyPasskeyRegistration({ attestationObject: enc(new Map<unknown, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authReg]])).toString("base64url"), clientDataJSON: cd("webauthn.create", "reg-1") }, { challenge: "reg-1", origin, rpId });
    expect(reg.credentialId).toBe(credId.toString("base64url"));
    const authGet = Buffer.concat([rpHash, Buffer.from([0x05]), Buffer.alloc(4)]);
    const cdj = cd("webauthn.get", "apr_1:nonce");
    const sig = nodeSign("sha256", Buffer.concat([authGet, createHash("sha256").update(Buffer.from(cdj, "base64url")).digest()]), privateKey);
    const a = { authenticatorData: authGet.toString("base64url"), clientDataJSON: cdj, signature: sig.toString("base64url") };
    expect(verifyPasskeyAssertion(a, reg.jwk, { challenge: "apr_1:nonce", origin, rpId })).toBe(true);
    expect(() => verifyPasskeyAssertion(a, reg.jwk, { challenge: "apr_2:nonce", origin, rpId })).toThrow(/challenge/);
  });
});

describe("tool pinning and fail-closed (S10, S11)", () => {
  it("refuses calls when the server's tools differ from the pinned fingerprint", async () => {
    const dir = mkdtempSync(join(tmpdir(), "pin-"));
    const o = loadOrCreateKey(join(dir, "o.json")), ag = loadOrCreateKey(join(dir, "a.json"));
    writeFileSync(join(dir, "m.json"), JSON.stringify(createMandate({ agentId: ag.kid, agentName: "P", destructive: false, expires: "2099-01-01", tools: ["get_forecast"] }, o)));
    const self = ["--import", "tsx", root + "packages/cli/src/main.ts"];
    const s = await connect({ kind: "stdio", command: process.execPath, args: [...self, "proxy", "--mandate", join(dir, "m.json"), "--agent-key", join(dir, "a.json"), "--enforce", "--receipts", join(dir, "r.jsonl"), "--pin", "sha256:not-the-real-one", "--", process.execPath, "--import", "tsx", root + "fixtures/src/good.ts"] });
    try { await s.listTools(); const r = await s.callTool("get_forecast", { city: "Toronto" }); expect(JSON.stringify(r)).toMatch(/tools-changed/); } finally { await s.close(); }
  }, 120_000);
});

describe("fuzzing the parsers of untrusted input", () => {
  const rnd = (n: number) => Array.from({ length: n }, () => String.fromCharCode(Math.floor(Math.random() * 127))).join("");
  const junk = () => [null, 1, "x", [], {}, { signature: { jws: rnd(20), kid: "did:key:z" } }, { statementFormat: "0.1", type: "revocation", signature: { jws: "a..b", kid: "x" } }][Math.floor(Math.random() * 7)];
  it("never crashes in unexpected ways on random input", () => {
    for (let i = 0; i < 300; i++) {
      try { verifyReceiptLog(parseReceiptLog(rnd(80))); } catch (e) { expect(e).toBeInstanceOf(Error); }
      expect(typeof verifyDocument((junk() ?? {}) as never).valid).toBe("boolean");
      expect(checkStatement(junk()).ok).toBe(false);
      expect(() => decideIntent(m as never, { name: rnd(8) } as never, { [rnd(5)]: rnd(10) })).not.toThrow();
      try { verifyPasskeyAssertion({ authenticatorData: rnd(40), clientDataJSON: rnd(40), signature: rnd(40) }, { kty: "EC" } as never, { challenge: "c", origin: "o", rpId: "r" }); } catch (e) { expect(e).toBeInstanceOf(Error); }
    }
  });
});
