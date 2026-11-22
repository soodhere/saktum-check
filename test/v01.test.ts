// v0.1 behaviour: grade and summary, sign-in checks against the OAuth fixture, secrets and leakage,
// performance measurement, the active burst, cost in money, doctor, and the embedded copies.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { EMBEDDED_CONTRACTS, EMBEDDED_PACKS, gradeFor, loadEmbeddedPacks, loadPackDir, parseChallenge, runTrustCheck, wellKnownUrls, type Result } from "@saktum/testkit-core";
import { owaspCoverage, renderTerminal } from "@saktum/report";
import { runDoctor } from "../packages/cli/src/doctor.js";
import { fixture, root, startHttpFixture } from "./helpers.js";

const packs = loadPackDir(root + "packs");
const find = (r: Result, id: string) => r.findings.find((f) => f.check === id)!;

describe("grade", () => {
  it("maps scores to letters, and any capped result to F", () => {
    expect([gradeFor(95, false), gradeFor(85, false), gradeFor(75, false), gradeFor(60, false), gradeFor(40, false), gradeFor(95, true), gradeFor(null, false)])
      .toEqual(["A", "B", "C", "D", "F", "F", null]);
  });
});

describe("sign-in helpers", () => {
  it("parses a Bearer challenge with quoted parameters", () => {
    const c = parseChallenge('Bearer error="invalid_token", resource_metadata="https://x.example/.well-known/oauth-protected-resource/mcp"');
    expect(c.scheme).toBe("Bearer");
    expect(c.params["resource_metadata"]).toBe("https://x.example/.well-known/oauth-protected-resource/mcp");
    expect(c.params["error"]).toBe("invalid_token");
  });
  it("builds RFC 9728 well-known URLs by inserting before the path", () => {
    expect(wellKnownUrls(new URL("https://api.example/mcp"), "oauth-protected-resource"))
      .toEqual(["https://api.example/.well-known/oauth-protected-resource/mcp", "https://api.example/.well-known/oauth-protected-resource"]);
  });
});

describe("OAuth fixture", () => {
  let good: { url: string; stop: () => void }, broken: { url: string; stop: () => void };
  beforeAll(async () => { good = await startHttpFixture("oauth-good"); broken = await startHttpFixture("oauth-broken"); }, 60_000);
  afterAll(() => { good?.stop(); broken?.stop(); });

  it("without a token: sign-in checks pass, the rest wait for a token, and there is no grade yet", async () => {
    const r = await runTrustCheck({ kind: "streamable-http", url: good.url }, { packs });
    for (const id of ["auth.https", "auth.www-authenticate", "auth.resource-metadata", "auth.server-metadata", "auth.invalid-token"]) expect(find(r, id).status, id).toBe("pass");
    expect(find(r, "conf.tools.list").status).toBe("inconclusive");
    expect(find(r, "conf.tools.list").message).toMatch(/--header/);
    expect(r.grade).toBeNull();
    expect(r.summary?.[0]).toMatch(/No grade yet/);
  });

  it("with a valid token: everything runs and the server earns a grade", async () => {
    const r = await runTrustCheck({ kind: "streamable-http", url: good.url, headers: { Authorization: "Bearer fixture-good-token" } }, { packs });
    expect(find(r, "conf.tools.list").status).toBe("pass");
    expect(find(r, "auth.invalid-token").status).toBe("pass");
    expect(r.grade).toBe("A");
  });

  it("the broken server fails the challenge, metadata and invalid-token checks", async () => {
    const r = await runTrustCheck({ kind: "streamable-http", url: broken.url }, { packs });
    for (const id of ["auth.www-authenticate", "auth.resource-metadata", "auth.server-metadata", "auth.invalid-token"]) expect(find(r, id).status, id).toBe("fail");
    expect(find(r, "auth.invalid-token").message).toMatch(/invalid bearer token/);
  });
});

describe("secrets and leakage", () => {
  it("finds the hard-coded key without repeating it, and the stack trace with internal paths", async () => {
    const r = await runTrustCheck(fixture("leaky"), { packs });
    const sec = find(r, "sec.secrets.exposed");
    expect(sec.status).toBe("fail");
    expect(sec.message).toMatch(/AWS access key/);
    expect(JSON.stringify(r)).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(sec.evidence?.excerpt).toMatch(/redacted/);
    const leak = find(r, "sec.errors.leakage");
    expect(leak.status).toBe("fail");
    expect(leak.message).toMatch(/stack trace|internal file path/);
    expect(r.grade).toBe("F");
  });
});

describe("performance, cost and the burst test", () => {
  it("measures start-up, latency and (on Linux and macOS) memory; reports cost in money", async () => {
    const r = await runTrustCheck(fixture("good"), { packs, pricePerMTokUsd: 15 });
    expect(r.metrics.performance?.initMs).toBeGreaterThan(0);
    expect(r.metrics.performance?.listMs).toBeGreaterThanOrEqual(0);
    if (process.platform !== "win32") expect(find(r, "perf.memory").message).toMatch(/MB of memory/);
    expect(r.metrics.pricePerMTokUsd).toBe(15);
    expect(r.metrics.contextCostPer1kTurnsUsd).toBeGreaterThan(0);
    expect(find(r, "perf.burst").status).toBe("skipped");
    expect(r.summary?.join(" ")).toMatch(/per 1,000 turns/);
    expect(r.findings.filter((f) => f.pack === "performance").every((f) => !f.scored)).toBe(true);
  });
  it("runs the burst only with --active", async () => {
    const r = await runTrustCheck(fixture("good"), { packs, mode: "active" });
    expect(find(r, "perf.burst").status).toBe("info");
    expect(find(r, "perf.burst").message).toMatch(/20 of 20 concurrent requests succeeded/);
  });
});

describe("reports", () => {
  it("lead with the grade and summary and show OWASP MCP Top 10 coverage", async () => {
    const r = await runTrustCheck(fixture("malicious"), { packs });
    const text = renderTerminal(r);
    expect(text.indexOf("GRADE")).toBeLessThan(text.indexOf("FAIL"));
    expect(text).toContain("OWASP MCP Top 10 coverage");
    const cov = owaspCoverage(r);
    expect(cov.find((c) => c.id === "MCP03")!.failed).toBeGreaterThan(0);
    expect(cov.find((c) => c.id === "MCP04")!.later).toMatch(/v0.5/);
  });
});

describe("doctor", () => {
  it("passes for a server that starts and completes the handshake", async () => {
    const r = await runDoctor(["--", process.execPath, "--import", "tsx", "fixtures/src/good.ts"].slice(1).length ? [process.execPath, "--import", "tsx", root + "fixtures/src/good.ts"] : []);
    expect(r.code).toBe(0);
    expect(r.text).toMatch(/MCP handshake OK/);
  }, 30_000);
  it("explains a server that exits because it needs credentials", async () => {
    const r = await runDoctor([process.execPath, "-e", "console.error('Error: missing API key: set ACME_API_KEY'); process.exit(1)"]);
    expect(r.code).toBe(1);
    expect(r.text).toMatch(/exited during start-up/);
    expect(r.text).toMatch(/--env NAME=VALUE/);
  }, 30_000);
});

describe("embedded copies (single-file bundle)", () => {
  it("match contracts/ and packs/ exactly (run pnpm embed if this fails)", () => {
    for (const f of readdirSync(root + "packs").filter((x) => /\.ya?ml$/.test(x))) expect(EMBEDDED_PACKS[f], f).toBe(readFileSync(root + "packs/" + f, "utf8"));
    for (const f of readdirSync(root + "contracts").filter((x) => x.endsWith(".schema.json"))) expect(EMBEDDED_CONTRACTS[f], f).toBe(readFileSync(root + "contracts/" + f, "utf8"));
    expect(loadEmbeddedPacks().map((p) => p.hash)).toEqual(packs.map((p) => p.hash));
  });
});

import { LEAK_PATTERNS } from "@saktum/testkit-core";
describe("findings from the wider real-server run (regressions)", () => {
  const leaks = (t: string) => LEAK_PATTERNS.filter((p) => p.re.test(t)).map((p) => p.name);
  it("does not treat installed system binaries as leaked internals", () => {
    expect(leaks("Browser not found at /opt/google/chrome/chrome")).toEqual([]);
    expect(leaks("Executable doesn't exist at /usr/bin/chromium")).toEqual([]);
  });
  it("still flags application source paths and dependency folders", () => {
    expect(leaks("failed in /home/deploy/acme/src/handlers.js")).toContain("internal source path");
    expect(leaks("at /srv/api/node_modules/pg/lib/client.js")).toContain("internal source path");
    expect(leaks("C:\\Users\\bob\\app\\server.py raised")).toContain("internal source path");
  });
  it("gives no grade when a server lists no tools, and says why", async () => {
    const r = await runTrustCheck(fixture("empty"), { packs });
    expect(r.grade).toBeNull();
    expect(r.summary?.[0]).toMatch(/listed no tools/);
    expect(find(r, "conf.init.handshake").status).toBe("pass");
  });
  it("gives no grade when the tool list cannot be read, and reports the error", async () => {
    const r = await runTrustCheck(fixture("raw-list"), { packs });
    expect(r.grade).toBeNull();
    expect(find(r, "conf.init.handshake").status).toBe("pass");
  });
  it("names the exact reason a schema is invalid", async () => {
    const r = await runTrustCheck(fixture("broken"), { packs });
    const f = find(r, "conf.tools.schema-valid");
    if (f.status === "fail") expect(f.message).toMatch(/For \S+: /);
  });
});

import { hintsFrom, keyLine } from "../packages/cli/src/doctor.js";
describe("doctor hints from real start-up failures", () => {
  it("picks the meaningful error line, not trailing punctuation", () => {
    expect(keyLine("Error: Invalid API key provided\n    at x (y.js:1:1)\n  }\n}")).toBe("Error: Invalid API key provided");
  });
  it("recognises a crash inside the server's own code", () => {
    expect(hintsFrom("Traceback (most recent call last):\n  ...\nAttributeError: 'Server' object has no attribute 'list_resources'").join(" ")).toMatch(/error in its own code/);
  });
  it("recognises a missing dependency service", () => {
    expect(hintsFrom("Error: connect ECONNREFUSED 127.0.0.1:6379").join(" ")).toMatch(/service the server depends on/);
  });
});

describe("v0.1.1: honest labels from the first Windows run", () => {
  it("labels partly covered OWASP categories as partial", async () => {
    const r = await runTrustCheck(fixture("good"), { packs });
    const text = renderTerminal(r);
    expect(text).toMatch(/MCP08 .*passed \(partial: /);
    expect(owaspCoverage(r).find((c) => c.id === "MCP03")!.partial).toBeUndefined();
  });
  it("does not call a launcher's download time slow", async () => {
    const { analysers } = await import("@saktum/testkit-core");
    const v = await analysers["perf-startup"]!({ tools: [], target: { kind: "stdio", command: "npx", args: ["-y", "x"] }, perf: { initMs: 15000 } });
    expect(v.message).toMatch(/resolve or download the package/);
    expect(v.message).not.toMatch(/slow/);
  });
});

import { quoteWin, spawnPlan } from "../packages/cli/src/doctor.js";
describe("doctor on Windows (from the first Windows test run)", () => {
  it("never sends full program paths through the shell, so spaces are safe", () => {
    expect(spawnPlan("C:\\Program Files\\nodejs\\node.exe", ["-e", "x"], "win32")).toEqual({ command: "C:\\Program Files\\nodejs\\node.exe", args: ["-e", "x"], shell: false });
  });
  it("starts bare commands and .cmd files through the shell, quoting arguments", () => {
    expect(spawnPlan("npx", ["-y", "@scope/server", "C:\\My Files\\db"], "win32")).toEqual({ command: "npx", args: ["-y", "@scope/server", '"C:\\My Files\\db"'], shell: true });
    expect(spawnPlan("C:\\tools\\run me.cmd", [], "win32").command).toBe('"C:\\tools\\run me.cmd"');
  });
  it("runs everything directly on other platforms", () => {
    expect(spawnPlan("npx", ["-y", "x"], "linux").shell).toBe(false);
  });
  it("quotes only when needed", () => {
    expect(quoteWin("@modelcontextprotocol/server-memory")).toBe("@modelcontextprotocol/server-memory");
    expect(quoteWin("a b")).toBe('"a b"');
  });
});
