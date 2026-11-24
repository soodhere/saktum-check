// Enterprise: policy as code, redaction, fleet inventory.
import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildFleet, evaluatePolicy, loadPackDir, parsePolicy, redactCommand, redactUrl, runTrustCheck, subjectFromResult } from "@saktum/testkit-core";
import { fixture, root } from "./helpers.js";

const packs = loadPackDir(root + "packs");
const cli = (args: string[], cwd = root) => spawnSync(process.execPath, ["--import", "tsx", root + "packages/cli/src/main.ts", ...args], { cwd, encoding: "utf8", timeout: 120_000 });
const subject = (o: Partial<Parameters<typeof evaluatePolicy>[0]> = {}) => ({ server: "s", trustGrade: "A", readinessGrade: "A", capabilities: [], lethalTrifecta: false, contextTokens: 1000, failedSeverities: [], ...o });

describe("policy as code", () => {
  it("validates the example policy and rejects an invalid one", async () => {
    expect((await parsePolicy(readFileSync(root + "examples/saktum-policy.yaml", "utf8"))).minTrust).toBe("A");
    await expect(parsePolicy('policyFormat: "0.1"\nminTrust: Z\n')).rejects.toThrow(/Invalid policy/);
  });
  it("finds violations, honours exceptions, and ignores expired ones", () => {
    const p = { policyFormat: "0.1" as const, minReadiness: "B", forbidCapabilities: ["money"], maxContextTokens: 5000, exceptions: [{ server: "pay", rules: ["forbidCapabilities"], reason: "approved pilot", until: "2027-01-31" }] };
    const v = evaluatePolicy(subject({ server: "x", readinessGrade: "C", contextTokens: 9000 }), p);
    expect(v.compliant).toBe(false);
    expect(v.violations.map((x) => x.rule)).toEqual(["minReadiness", "maxContextTokens"]);
    expect(evaluatePolicy(subject({ server: "pay", capabilities: ["money"] }), p, undefined, "2026-12-01").compliant).toBe(true);
    expect(evaluatePolicy(subject({ server: "pay", capabilities: ["money"] }), p, undefined, "2027-02-01").compliant).toBe(false);
  });
  it("requires the allowlist to match the exact tools", () => {
    const p = { policyFormat: "0.1" as const, requireAllowlist: true };
    expect(evaluatePolicy(subject({ toolsFingerprint: "sha256:a" }), p, new Set(["sha256:a"])).compliant).toBe(true);
    expect(evaluatePolicy(subject({ toolsFingerprint: "sha256:b" }), p, new Set(["sha256:a"])).compliant).toBe(false);
  });
  it("fails CI when a server violates the policy", () => {
    const dir = mkdtempSync(join(tmpdir(), "pol-"));
    writeFileSync(join(dir, "p.yaml"), 'policyFormat: "0.1"\nname: strict\nminReadiness: A\n');
    const target = ["--", process.execPath, "--import", "tsx", `${root}fixtures/src/`];
    const good = cli(["check", "--policy", join(dir, "p.yaml"), "--out", join(dir, "a.json"), ...target.slice(0, 4), `${root}fixtures/src/good.ts`]);
    const broken = cli(["check", "--fail-on", "critical", "--policy", join(dir, "p.yaml"), "--out", join(dir, "b.json"), ...target.slice(0, 4), `${root}fixtures/src/broken.ts`]);
    expect(good.status).toBe(0);
    expect(good.stdout).toMatch(/complies with policy/);
    expect(broken.status).toBe(1);
    expect(broken.stdout).toMatch(/violates policy[\s\S]*agent readiness F is below the required A/);
  }, 120_000);
});

describe("redaction", () => {
  it("redacts secret flags, long random strings and URL credentials", () => {
    const r = redactCommand("npx", ["-y", "@acme/mcp", "--api-key=sk_live_51HcQwerty", "--token", "abc123", "Zx9kQ2mN8vL4pR7tY1wE5uI3oA6sD0fG", "--region", "eu"]);
    expect(r).toBe("npx -y @acme/mcp --api-key=\u2039redacted\u203a --token \u2039redacted\u203a \u2039redacted\u203a --region eu");
    expect(redactUrl("https://user:pw@mcp.acme.com/mcp?key=abc")).toBe("https://mcp.acme.com/mcp");
  });
});

describe("saktum fleet", () => {
  it("merges machines into one inventory with policy verdicts", async () => {
    const good = subjectFromResult(await runTrustCheck(fixture("good"), { packs }));
    const rec = (name: string, extra = {}) => ({ name, client: "Cursor", target: "npx -y x", fingerprint: `fp-${name}`, trustGrade: "A", readinessGrade: "A", toolCount: 2, tokens: 500, capabilities: [] as string[], ...extra });
    const f = buildFleet([{ machine: "m1", servers: [rec("shared"), rec("risky", { readinessGrade: "C" })] }, { machine: "m2", servers: [rec("shared")] }], { policyFormat: "0.1", minReadiness: "B" });
    expect(f.machines).toBe(2);
    expect(f.servers.find((s) => s.name === "shared")!.machines).toBe(2);
    expect(f.nonCompliant).toBe(1);
    expect(good.trustGrade).toBe("A");
  });
  it("works end to end: scan-config on two machines, then fleet with a policy", () => {
    const dir = mkdtempSync(join(tmpdir(), "fleet-"));
    const fx = (n: string) => ({ command: process.execPath, args: ["--import", "tsx", `${root}fixtures/src/${n}.ts`, "--token", "very-secret-token-value"] });
    writeFileSync(join(dir, "c1.json"), JSON.stringify({ mcpServers: { good: fx("good"), broken: fx("broken") } }));
    writeFileSync(join(dir, "c2.json"), JSON.stringify({ mcpServers: { good: fx("good") } }));
    writeFileSync(join(dir, "p.yaml"), 'policyFormat: "0.1"\nminReadiness: B\n');
    for (const m of ["1", "2"]) cli(["scan-config", "--config", join(dir, `c${m}.json`), "--yes", "--machine", `laptop-${m}`, "--out", join(dir, `s${m}.json`)]);
    expect(readFileSync(join(dir, "s1.json"), "utf8")).not.toMatch(/very-secret-token-value/);
    const out = cli(["fleet", join(dir, "s1.json"), join(dir, "s2.json"), "--policy", join(dir, "p.yaml"), "--html", join(dir, "fleet.html")]);
    expect(out.stdout).toMatch(/2 distinct MCP servers across 2 machine\(s\)/);
    expect(out.stdout).toMatch(/1 violate policy/);
    expect(out.status).toBe(1);
    expect(readFileSync(join(dir, "fleet.html"), "utf8")).toMatch(/MCP server inventory/);
  }, 180_000);
});
