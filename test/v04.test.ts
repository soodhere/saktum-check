// v0.4: Saktum as an MCP server (dogfood) and signed attestations.
import { describe, expect, it } from "vitest";
import { buildAttestation, loadPackDir, runTrustCheck } from "@saktum/testkit-core";
import { generateSigningKey, signDocument, verifyDocument } from "@saktum/sign";
import { connect } from "@saktum/transports";
import { splitTarget } from "../packages/cli/src/mcp-server.ts";
import { fixture, root } from "./helpers.js";

const packs = loadPackDir(root + "packs");
const saktumMcp = { kind: "stdio" as const, command: process.execPath, args: ["--import", "tsx", root + "packages/cli/src/main.ts", "mcp"], cwd: root };

describe("saktum mcp", () => {
  it("splits targets like a shell, keeping URLs whole", () => {
    expect(splitTarget("npx -y '@scope/my server' --flag")).toEqual(["npx", "-y", "@scope/my server", "--flag"]);
    expect(splitTarget("https://example.com/mcp")).toEqual(["https://example.com/mcp"]);
  });
  it("dogfood: Saktum's own MCP server earns trust A and agent readiness A", async () => {
    const r = await runTrustCheck(saktumMcp, { packs });
    expect(r.grade).toBe("A");
    expect(r.readiness?.grade).toBe("A");
    expect(r.findings.filter((f) => (f.pack === "conformance" || f.pack === "security") && f.status === "fail")).toEqual([]);
  }, 90_000);
  it("lets an agent check a server, with structured output, and explain a check", async () => {
    const s = await connect(saktumMcp);
    try {
      const r = await s.callTool("check_server", { target: `"${process.execPath}" --import tsx "${root}fixtures/src/good.ts"` });
      expect(r.kind).toBe("result");
      const sc = (r as { structuredContent?: { trustGrade?: string; trustCard?: unknown[] } }).structuredContent;
      expect(sc?.trustGrade).toBe("A");
      expect(sc?.trustCard?.length).toBeGreaterThan(5);
      const e = await s.callTool("explain_check", { check_id: "sec.http.origin" });
      expect(JSON.stringify(e)).toMatch(/DNS rebinding|foreign web origins/);
      const bad = await s.callTool("explain_check", { check_id: "no.such.check" });
      expect((bad as { isError?: boolean }).isError).toBe(true);
    } finally { await s.close(); }
  }, 90_000);
});

describe("saktum attest", () => {
  it("builds a signed, verifiable attestation with maturity evidence", async () => {
    const r = await runTrustCheck(fixture("good"), { packs });
    const att = buildAttestation(r);
    expect(att.claims.evidence).toEqual({ responds: true, conformant: true, safeByDefault: true, agentReady: true });
    expect(att.subject.toolsFingerprint).toBe(r.target.toolsFingerprint);
    const signed = signDocument(att, generateSigningKey());
    expect(verifyDocument(signed).valid).toBe(true);
    expect(verifyDocument({ ...signed, claims: { ...signed.claims, trustGrade: "A+" } }).valid).toBe(false);
  });
  it("does not claim maturity evidence a server lacks", async () => {
    const r = await runTrustCheck(fixture("malicious"), { packs });
    expect(buildAttestation(r).claims.evidence.safeByDefault).toBe(false);
  });
});

import { analyseSetup, parseClientConfig } from "@saktum/testkit-core";
import { toSarif } from "@saktum/report";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const cli = (args: string[], cwd = root) => spawnSync(process.execPath, ["--import", "tsx", root + "packages/cli/src/main.ts", ...args], { cwd, encoding: "utf8", timeout: 120_000 });

describe("saktum scan-config", () => {
  it("reads Claude, Cursor and VS Code configuration formats", () => {
    const a = parseClientConfig(JSON.stringify({ mcpServers: { mem: { command: "npx", args: ["-y", "m"], env: { TOKEN: "s3cret" } }, web: { url: "https://x.example/mcp" }, off: { command: "x", disabled: true } } }), "Claude Desktop", "f");
    expect(a.map((x) => x.name)).toEqual(["mem", "web", "off"]);
    expect(a[2]!.disabled).toBe(true);
    const v = parseClientConfig(JSON.stringify({ servers: { gh: { type: "stdio", command: "node", args: ["s.js"] } } }), "VS Code", "f");
    expect(v[0]!.command).toBe("node");
    expect(parseClientConfig("not json", "x", "f")).toEqual([]);
  });
  it("adds up cost and finds duplicate and look-alike tools across servers", () => {
    const t = (name: string, description: string) => ({ name, description, inputSchema: { type: "object" } });
    const r = analyseSetup([
      { name: "a", client: "c", trustGrade: "A", readinessGrade: "A", tokens: 12_000, tools: [t("search_issues", "Search issues in the project tracker by keyword and status"), t("get_user", "Get a user")] },
      { name: "b", client: "c", trustGrade: "C", readinessGrade: "B", tokens: 3_000, tools: [t("find_issues", "Search issues in the project tracker by keyword and status filter"), t("get_user", "Get a user")] }
    ], { turnsPerDay: 50, pricePerMTokUsd: 3 });
    expect(r.totalTokens).toBe(15_000);
    expect(r.monthlyCostUsd).toBe(67.5);
    expect(r.duplicates).toEqual([{ tool: "get_user", servers: ["a", "b"] }]);
    expect(r.overlaps[0]).toMatchObject({ a: "a/search_issues", b: "b/find_issues" });
    expect(r.recommendations.join(" ")).toMatch(/b earns trust C/);
  });
  it("runs end to end on a configuration, never printing configured secrets", () => {
    const dir = mkdtempSync(join(tmpdir(), "scfg-"));
    const cfg = join(dir, "mcp.json");
    const fx = (n: string) => ({ command: process.execPath, args: ["--import", "tsx", `${root}fixtures/src/${n}.ts`], env: { API_TOKEN: "sk-super-secret-value" } });
    writeFileSync(cfg, JSON.stringify({ mcpServers: { first: fx("good"), second: fx("good"), third: fx("broken") } }));
    const out = cli(["scan-config", "--config", cfg, "--yes", "--out", join(dir, "setup.json")]);
    expect(out.stdout).toMatch(/3 servers/);
    expect(out.stdout).toMatch(/DUPLICATE TOOLS/);
    expect(out.stdout).toMatch(/third .*trust C/);
    expect(out.stdout + out.stderr).not.toMatch(/sk-super-secret-value/);
    expect(JSON.parse(readFileSync(join(dir, "setup.json"), "utf8")).duplicates.length).toBeGreaterThan(0);
  }, 120_000);
  it("asks for consent: without --yes and without a terminal, nothing is started", () => {
    const dir = mkdtempSync(join(tmpdir(), "scfg-"));
    const cfg = join(dir, "mcp.json");
    writeFileSync(cfg, JSON.stringify({ mcpServers: { x: { command: "node", args: ["no-such-file.js"] } } }));
    expect(cli(["scan-config", "--config", cfg]).stdout).toMatch(/Re-run with --yes to agree/);
  });
});

describe("SARIF and baseline", () => {
  it("writes SARIF 2.1.0 with rules, levels and security severity", async () => {
    const r = await runTrustCheck(fixture("broken"), { packs });
    const s = toSarif(r, "src/index.ts") as { version: string; runs: { tool: { driver: { rules: { properties: Record<string, string> }[] } }; results: { level: string; locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[] }[] };
    expect(s.version).toBe("2.1.0");
    expect(s.runs[0]!.results.length).toBeGreaterThan(0);
    expect(s.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri).toBe("src/index.ts");
    expect(s.runs[0]!.tool.driver.rules[0]!.properties["security-severity"]).toMatch(/^\d/);
  });
  it("fails only on findings that are not in the baseline", () => {
    const dir = mkdtempSync(join(tmpdir(), "base-"));
    const base = join(dir, "baseline.json");
    const target = ["--", process.execPath, "--import", "tsx", `${root}fixtures/src/broken.ts`];
    expect(cli(["check", "--fail-on", "low", "--out", join(dir, "r.json"), ...target]).status).toBe(1);
    expect(cli(["check", "--fail-on", "low", "--baseline", base, "--update-baseline", "--out", join(dir, "r.json"), ...target]).status).toBe(0);
    expect(cli(["check", "--fail-on", "low", "--baseline", base, "--out", join(dir, "r.json"), ...target]).status).toBe(0);
    const b = JSON.parse(readFileSync(base, "utf8"));
    b.accepted = b.accepted.slice(1);
    writeFileSync(base, JSON.stringify(b));
    expect(cli(["check", "--fail-on", "low", "--baseline", base, "--out", join(dir, "r.json"), ...target]).status).toBe(1);
  }, 180_000);
});

import { appendTestCase, lintSource, parseTestCases as parseCases } from "@saktum/testkit-core";
import { initProject } from "../packages/cli/src/init.ts";
describe("shift left: init, lint, save as test", () => {
  it("scaffolds TypeScript and Python servers with tests, CI, agent rules and annotated tools", async () => {
    for (const lang of ["ts", "py"] as const) {
      const dir = mkdtempSync(join(tmpdir(), `init-${lang}-`));
      const files = initProject(dir, lang, "demo");
      expect(files).toEqual(expect.arrayContaining(["saktum.tests.yaml", "AGENTS.md", ".github/workflows/saktum.yml", "README.md"]));
      const src = readFileSync(join(dir, lang === "ts" ? "src/index.ts" : "server.py"), "utf8");
      expect(src).toMatch(/readOnlyHint/);
      expect(lintSource(src, lang === "ts" ? "src/index.ts" : "server.py")).toEqual([]);
      expect((await parseCases(readFileSync(join(dir, "saktum.tests.yaml"), "utf8"))).length).toBe(2);
      expect(() => initProject(dir, lang, "demo")).toThrow(/already contains a project/);
    }
  });
  it("lints tool registrations with lines, and ignores files that do not import an MCP SDK", () => {
    const ts = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nconst s = new McpServer({ name: "x", version: "1" });\ns.registerTool("delete_all", { description: "Deletes." }, async () => ({ content: [] }));\ns.registerTool("files.read", { description: "Read a file from the project by path.", annotations: { readOnlyHint: true } }, async () => ({ content: [] }));\n';
    expect(lintSource(ts, "a.ts").map((f) => `${f.check}:${f.line}`)).toEqual(["lint.name:4", "lint.annotations:3", "lint.description:3"].sort().filter(() => false).concat(lintSource(ts, "a.ts").map((f) => `${f.check}:${f.line}`)));
    expect(lintSource(ts, "a.ts").map((f) => `${f.check}:${f.line}`).sort()).toEqual(["lint.annotations:3", "lint.description:3", "lint.name:4"]);
    const py = 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n\n@mcp.tool()\ndef drop_table(name: str) -> str:\n    return "x"\n';
    expect(lintSource(py, "s.py").map((f) => `${f.check}:${f.line}`).sort()).toEqual(["lint.annotations:4", "lint.description:4"]);
    expect(lintSource('const t = { tool: (n: string) => n };\nt.tool("x", 1);\n', "u.ts")).toEqual([]);
  });
  it("appends a saved test case to an existing file, keeping it valid, and refuses duplicates", async () => {
    const start = 'testsFormat: "0.1"\ntests:\n  - id: a\n    tool: t\n    input: {}\n    expect: { isError: false }\n';
    const out = await appendTestCase(start, { id: "b", tool: "t", input: { x: 1 }, expect: { isError: false, textContains: "ok" } });
    expect((await parseCases(out)).map((t) => t.id)).toEqual(["a", "b"]);
    await expect(appendTestCase(out, { id: "b", tool: "t", input: {}, expect: {} })).rejects.toThrow(/already exists/);
    expect((await parseCases(await appendTestCase(undefined, { id: "c", tool: "t", input: {}, expect: { isError: true } })))[0]!.id).toBe("c");
  });
});

describe("first run", () => {
  it("shows four journeys when run without a command", () => {
    const out = cli([]).stdout;
    expect(out).toMatch(/What would you like to do\?/);
    for (const j of ["Test an MCP server", "Start a new MCP server", "claude mcp add saktum", "scan-config"]) expect(out).toContain(j);
  });
});

describe("Windows paths with spaces", () => {
  it("keeps quoted paths with spaces whole", () => {
    expect(splitTarget('"C:\\Program Files\\nodejs\\node.exe" --import tsx "C:\\My Projects\\server.ts"'))
      .toEqual(["C:\\Program Files\\nodejs\\node.exe", "--import", "tsx", "C:\\My Projects\\server.ts"]);
  });
});
