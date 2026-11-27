// v0.6: watch, OpenTelemetry export, Verifiable Credentials, ROI.
import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { attestationToCredential, buildAllowlist, buildAttestation, chainEntry, loadPackDir, receiptsToOtlp, roiEstimate, ROI_DEFAULTS, runTrustCheck, signCredentialJwt, signReceipt, verifyCredentialJwt, watchAllowlist } from "@saktum/testkit-core";
import { generateSigningKey } from "@saktum/sign";
import { fixture, root } from "./helpers.js";

const packs = loadPackDir(root + "packs");
const cli = (args: string[], cwd = root) => spawnSync(process.execPath, ["--import", "tsx", root + "packages/cli/src/main.ts", ...args], { cwd, encoding: "utf8", timeout: process.platform === "win32" ? 360_000 : 120_000 });
const goodCmd = `"${process.execPath}" --import tsx "${root}fixtures/src/good.ts"`;

describe("saktum watch", () => {
  it("reports unchanged servers, and flags changed tools and grade drops", async () => {
    const r = await runTrustCheck(fixture("good"), { packs });
    const entry = { server: "fixture-good", target: goodCmd, transport: "stdio", toolsFingerprint: r.target.toolsFingerprint, trustGrade: r.grade ?? null, readinessGrade: r.readiness?.grade ?? null };
    const same = await watchAllowlist([entry], packs);
    expect(same.findings[0]!.status).toBe("unchanged");
    const changed = await watchAllowlist([{ ...entry, toolsFingerprint: "sha256:different" }], packs);
    expect(changed.findings[0]!.status).toBe("changed");
    expect(changed.alerts).toBe(1);
    const gone = await watchAllowlist([{ ...entry, target: "definitely-not-a-command-xyz" }], packs);
    expect(gone.findings[0]!.status).toBe("unreachable");
  }, 120_000);
  it("works from an allowlist file and exits 1 when something needs attention", async () => {
    const r = await runTrustCheck(fixture("good"), { packs });
    const list = buildAllowlist([{ result: r }], { minTrust: "A", minReadiness: "B", noFailedCritical: true });
    (list.allowed[0] as { target: string }).target = goodCmd;
    const dir = mkdtempSync(join(tmpdir(), "watch-"));
    writeFileSync(join(dir, "a.json"), JSON.stringify(list));
    const ok = cli(["watch", join(dir, "a.json")]);
    expect(ok.stdout).toMatch(/1 server\(s\) checked; 0 need attention/);
    expect(ok.status).toBe(0);
    (list.allowed[0] as { toolsFingerprint: string }).toolsFingerprint = "sha256:other";
    writeFileSync(join(dir, "a.json"), JSON.stringify(list));
    expect(cli(["watch", join(dir, "a.json")]).status).toBe(1);
  }, 120_000);
});

describe("OpenTelemetry export", () => {
  it("turns receipts into OTLP spans with GenAI tool attributes and error status for blocked calls", () => {
    const key = generateSigningKey();
    const mk = (tool: string, outcome: "allow" | "deny") => signReceipt({ receiptFormat: "0.1", envelope: { envelopeFormat: "0.1", id: `id-${tool}`, protocol: "mcp", operation: "tools/call", tool, caller: { agent: key.kid }, target: { service: "billing" }, argumentsHash: "sha256:x", timestamp: "2026-11-26T10:00:00.000Z" }, outcome, reason: outcome, issuedAt: "2026-11-26T10:00:01.000Z" }, key);
    const e1 = chainEntry(undefined, mk("get_invoice", "allow"), { status: "ok", latencyMs: 40 });
    const e2 = chainEntry(e1, mk("refund", "deny"), { status: "blocked" });
    const o = receiptsToOtlp([e1, e2], { verified: true, version: "0.6.0" });
    const spans = o.resourceSpans[0]!.scopeSpans[0]!.spans;
    expect(spans).toHaveLength(2);
    expect(spans[0]!.traceId).toMatch(/^[0-9a-f]{32}$/);
    expect(spans[0]!.spanId).toMatch(/^[0-9a-f]{16}$/);
    expect(spans[0]!.attributes).toContainEqual({ key: "gen_ai.tool.name", value: { stringValue: "get_invoice" } });
    expect(spans[1]!.status.code).toBe(2);
    expect(BigInt(spans[0]!.endTimeUnixNano) - BigInt(spans[0]!.startTimeUnixNano)).toBe(40_000_000n);
  });
});

describe("Verifiable Credentials", () => {
  it("issues a vc+jwt from an attestation that verifies, and detects tampering and a wrong issuer", async () => {
    const key = generateSigningKey();
    const att = buildAttestation(await runTrustCheck(fixture("good"), { packs }));
    const vc = attestationToCredential(att, key.kid);
    expect(vc["@context"]).toEqual(["https://www.w3.org/ns/credentials/v2"]);
    const jwt = signCredentialJwt(vc, key);
    const v = verifyCredentialJwt(jwt);
    expect(v.valid && v.issuer).toBe(key.kid);
    const [h, p, s] = jwt.split(".");
    const forged = JSON.parse(Buffer.from(p!, "base64url").toString()); forged.credentialSubject.trustGrade = "A+";
    expect(verifyCredentialJwt(`${h}.${Buffer.from(JSON.stringify(forged)).toString("base64url")}.${s}`).valid).toBe(false);
    expect(verifyCredentialJwt(signCredentialJwt({ ...vc, issuer: generateSigningKey().kid }, key))).toMatchObject({ valid: false, reason: expect.stringMatching(/issuer/) });
  });
});

describe("ROI", () => {
  it("estimates annual tool-definition cost and savings with stated assumptions", () => {
    const r = roiEstimate({ ...ROI_DEFAULTS, tokensPerTurn: 32_833, agents: 1, vendorReviews: 10 });
    expect(r.annualToolCost).toBe(35_952);
    expect(r.tokenSavings).toBe(10_786);
    expect(r.reviewSavings).toBe(12_000);
    expect(r.assumptions).toMatch(/32,833 tokens/);
    expect(cli(["roi", "--tokens-per-turn", "32833"]).stdout).toMatch(/about \$35,952 a year/);
  });
});
