// "Testing the tests": every scored check must pass on a good fixture, fail on at least one bad fixture,
// and never fail on a good fixture. Remote-only checks are proven against the HTTP fixtures (oauth-good, oauth-broken).
import { beforeAll, describe, expect, it } from "vitest";
import { analysers, loadPack, loadPackDir, runTrustCheck, type Result } from "@saktum/testkit-core";
import { generateSigningKey, signDocument } from "@saktum/sign";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll } from "vitest";
import { fixture, root, startHttpFixture } from "./helpers.js";

const packs = loadPackDir(root + "packs");

const GOOD = ["good", "oauth-good"];
/** Narrow, documented exceptions: failures that cannot be produced by a local fixture, proven against the analyser directly. */
const UNIT_PROVEN_FAILURES: Record<string, () => Promise<string>> = {
  // A failing case needs plain HTTP on a non-local host; every test fixture runs on localhost, where HTTP is allowed.
  "auth.https": async () => (await analysers["auth-https"]!({ tools: [], target: { kind: "streamable-http", url: "http://api.example.com/mcp" } })).status
};
const BAD = ["broken", "malicious", "leaky", "faulty", "raw-init", "raw-list", "oauth-broken"];

describe("every check has a passing and a failing fixture", () => {
  const results: Record<string, Result> = {};
  const stops: (() => void)[] = [];
  beforeAll(async () => {
    // good and faulty run in active mode, so the functional checks (active only) have a passing and a failing case.
    for (const f of ["broken", "malicious", "leaky", "raw-init", "raw-list"] as const) results[f] = await runTrustCheck(fixture(f), { packs });
    for (const f of ["good", "faulty"] as const) results[f] = await runTrustCheck(fixture(f), { packs, mode: "active" });
    for (const f of ["oauth-good", "oauth-broken"] as const) {
      const h = await startHttpFixture(f); stops.push(h.stop);
      results[f] = await runTrustCheck({ kind: "streamable-http", url: h.url, ...(f === "oauth-good" ? { headers: { Authorization: "Bearer fixture-good-token" } } : {}) }, { packs });
    }
  }, 120_000);
  afterAll(() => stops.forEach((s) => s()));
  for (const { pack } of packs) for (const check of pack.checks) {
    if (check.severity === "info" || check.scored === false) continue;
    it(`${check.id}`, () => {
      const status = (f: string) => results[f]!.findings.find((x) => x.check === check.id)?.status;
      expect(GOOD.some((f) => status(f) === "pass"), "must pass on a good fixture").toBe(true);
      expect(GOOD.every((f) => status(f) !== "fail"), "must never fail on a good fixture").toBe(true);
      const unit = UNIT_PROVEN_FAILURES[check.id];
      if (unit) return unit().then((st) => expect(st, "must fail in its documented unit case").toBe("fail"));
      expect(BAD.some((f) => status(f) === "fail"), "must fail on at least one bad fixture").toBe(true);
    });
  }
});

describe("pack integrity", () => {
  it("accepts a correctly signed pack and rejects a tampered one", () => {
    const key = generateSigningKey();
    const dir = mkdtempSync(join(tmpdir(), "saktum-packs-"));
    const signed = signDocument({ ...packs.find((p) => p.pack.id === "security")!.pack }, key);
    writeFileSync(join(dir, "ok.json"), JSON.stringify(signed));
    expect(loadPack(join(dir, "ok.json"), { requireSignature: true, trustedKids: [key.kid] }).signedBy).toBe(key.kid);
    const tampered = { ...signed, checks: signed.checks.map((c) => ({ ...c, severity: "low" })) };
    writeFileSync(join(dir, "bad.json"), JSON.stringify(tampered));
    expect(() => loadPack(join(dir, "bad.json"), { requireSignature: true })).toThrow(/signature invalid/);
    expect(() => loadPack(join(dir, "ok.json"), { requireSignature: true, trustedKids: ["did:key:zOther"] })).toThrow(/untrusted key/);
  });
});
