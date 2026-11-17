import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { compileContract } from "@saktum/testkit-core";
import { root } from "./helpers.js";

const dir = mkdtempSync(join(tmpdir(), "saktum-cli-"));
const cli = (...args: string[]) => spawnSync(process.execPath, ["--import", "tsx", "packages/cli/src/main.ts", ...args], { cwd: root, encoding: "utf8", env: { ...process.env, SAKTUM_HOME: dir }, timeout: 60000 });

describe("saktum CLI", () => {
  it("checks the malicious fixture without letting its terminal attack through, and exits 1", () => {
    const out = join(dir, "malicious.json"); const html = join(dir, "malicious.html");
    const r = cli("check", "--out", out, "--html", html, "--", process.execPath, "--import", "tsx", "fixtures/src/malicious.ts");
    expect(r.status).toBe(1);
    expect(r.stdout).not.toMatch(/\u001b/);
    expect(r.stdout).toContain("sec.description.hidden-instructions");
    expect(r.stdout).toContain("Assurance level L1");
    expect(readFileSync(html, "utf8")).not.toMatch(/<IMPORTANT>/);
    const doc = JSON.parse(readFileSync(out, "utf8"));
    expect((compileContract("result.schema.json") as (d: unknown) => boolean)(doc)).toBe(true);
  });

  it("checks the good fixture and exits 0; verify accepts the result and rejects a tampered copy", () => {
    const out = join(dir, "good.json");
    expect(cli("check", "--out", out, "--", process.execPath, "--import", "tsx", "fixtures/src/good.ts").status).toBe(0);
    const ok = cli("verify", out);
    expect(ok.status).toBe(0);
    expect(ok.stdout).toContain("Valid signature by did:key:z");
    const doc = JSON.parse(readFileSync(out, "utf8")); doc.scores.overall = 100; doc.findings[0].status = "pass"; doc.target.toolCount = 99;
    const bad = join(dir, "tampered.json"); writeFileSync(bad, JSON.stringify(doc));
    const no = cli("verify", bad);
    expect(no.status).toBe(1);
    expect(no.stdout).toContain("NOT VALID");
  });

  it("exits 2 with a hint when the server cannot start", () => {
    const r = cli("check", "--out", join(dir, "x.json"), "--", "definitely-not-a-real-command-xyz");
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("Could not connect");
  });
});
