// v0.9: evidence for governance (framework crosswalk), the coding-agent story, assurance in words.
import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { actionClass, coverageSummary, crosswalk, DISCLAIMER, FRAMEWORKS, loadPackDir, runTrustCheck } from "@saktum/testkit-core";
import { renderAssessment, renderServerPassport } from "@saktum/report";
import { fixture, root } from "./helpers.js";

const cli = (args: string[], cwd = root) => spawnSync(process.execPath, ["--import", "tsx", root + "packages/cli/src/main.ts", ...args], { cwd, encoding: "utf8", timeout: process.platform === "win32" ? 600_000 : 200_000 });

describe("framework crosswalk", () => {
  it("covers six frameworks with honest coverage and never claims compliance", () => {
    expect(FRAMEWORKS.map((f) => f.id)).toEqual(["eu-ai-act", "nist-ai-rmf", "iso-42001", "owasp-llm", "dora-nis2", "gdpr-dpdp"]);
    for (const f of FRAMEWORKS) { const s = coverageSummary(f); expect(s.covered + s.partial + s.gap).toBe(s.total); }
    expect(crosswalk("eu-ai-act")[0]!.items.some((i) => i.coverage === "gap")).toBe(true);
    expect(JSON.stringify(FRAMEWORKS)).not.toMatch(/\bcompliant\b/i);
    expect(DISCLAIMER).toMatch(/does not establish compliance/);
    const out = cli(["evidence", "--framework", "eu-ai-act"]).stdout;
    expect(out).toMatch(/Art\. 12[\s\S]*Record-keeping/);
    expect(out).toMatch(/does not establish compliance/);
    expect(cli(["evidence", "--framework", "nope"]).status).not.toBe(0);
  });
  it("adds an evidence card to the executive assessment", () => {
    const html = renderAssessment("Acme", { generatedAt: "2026-12-01T00:00:00Z", machines: 1, nonCompliant: 0, unassessed: 0, servers: [] }, [], undefined, FRAMEWORKS.map((f) => ({ name: f.name, summary: coverageSummary(f) })), DISCLAIMER);
    expect(html).toMatch(/Evidence for the frameworks you are held to[\s\S]*EU AI Act/);
  });
});

describe("assurance in words, and the deploy action class", () => {
  it("shows self-tested rather than an L-level on passports", async () => {
    let tools: never[] = [];
    const r = await runTrustCheck(fixture("good"), { packs: loadPackDir(root + "packs"), onTools: (t) => { tools = t as never[]; } });
    const html = renderServerPassport(r, tools);
    expect(html).toContain("self-tested");
    expect(html).not.toMatch(/Assurance<\/small> <b>L1/);
    expect(actionClass({ name: "deploy_to_production" }).cls).toBe("deploy");
  });
});

describe("saktum demo --story coding", () => {
  it("keeps a coding agent to its repository and makes production wait for a signed approval", () => {
    const out = cli(["demo", "--story", "coding", "--out", join(mkdtempSync(join(tmpdir(), "cod-")), "d")]).stdout;
    for (const s of ["only the payments-service repository (got billing-core)", "approval-needed: asks before deploy", "retries the same release: approved by you, once", "(1 after your signed approval)"]) expect(out).toContain(s);
  }, process.platform === "win32" ? 600_000 : 200_000);
});
