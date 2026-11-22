import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalize, generateSigningKey, loadOrCreateKey, publicKeyFromDidKey, signDocument, verifyDocument } from "@saktum/sign";

describe("signing", () => {
  it("canonicalises per RFC 8785 (sorted keys, no whitespace)", () => {
    expect(canonicalize({ b: 1, a: [true, null, "x"], c: { z: 1.5, y: "\u00e9" } })).toBe('{"a":[true,null,"x"],"b":1,"c":{"y":"\u00e9","z":1.5}}');
  });
  it("signs and verifies; any change breaks verification", () => {
    const key = generateSigningKey();
    const doc = signDocument({ score: 93, findings: [{ check: "a", status: "pass" }] }, key);
    expect(verifyDocument(doc)).toMatchObject({ valid: true, kid: key.kid });
    expect(verifyDocument({ ...doc, score: 94 }).valid).toBe(false);
    expect(verifyDocument({ ...doc, findings: [{ check: "a", status: "fail" }] }).valid).toBe(false);
  });
  it("round-trips did:key identifiers", () => {
    const key = generateSigningKey();
    expect(key.kid).toMatch(/^did:key:z6Mk/);
    expect(publicKeyFromDidKey(key.kid).export({ format: "jwk" }).x).toBe(key.publicKey.export({ format: "jwk" }).x);
  });
  it("stores the local key readable only by the user and reuses it", () => {
    const path = join(mkdtempSync(join(tmpdir(), "saktum-")), "key.jwk.json");
    const a = loadOrCreateKey(path); const b = loadOrCreateKey(path);
    expect(b.kid).toBe(a.kid);
    if (process.platform !== "win32") expect(statSync(path).mode & 0o777).toBe(0o600);
  });
});
