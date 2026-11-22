import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadPackDir, runTrustCheck, type Result } from "@saktum/testkit-core";
import { fixture, root, startHttpFixture } from "./helpers.js";

const packs = loadPackDir(root + "packs");
const fails = (r: Result) => r.findings.filter((f) => f.status === "fail").map((f) => f.check).sort();

describe("engine against fixtures (stdio)", () => {
  let good: Result, broken: Result, malicious: Result;
  beforeAll(async () => {
    [good, broken, malicious] = await Promise.all([runTrustCheck(fixture("good"), { packs }), runTrustCheck(fixture("broken"), { packs }), runTrustCheck(fixture("malicious"), { packs })]);
  });

  it("good fixture passes every scored check and scores 100", () => {
    expect(fails(good)).toEqual([]);
    expect(good.scores.overall).toBe(100);
    expect(good.target.toolCount).toBe(2);
    expect(good.target.toolsFingerprint).toMatch(/^sha256:/);
    expect(good.metrics.contextCostTokens).toBeGreaterThan(0);
  });

  it("broken fixture fails exactly the expected checks", () => {
    expect(fails(broken)).toEqual(["ax.annotations", "ax.short-descriptions", "conf.tools.names", "conf.tools.schema-valid", "conf.tools.unknown-not-success"]);
    expect(broken.scores.categories.conformance).toBe(43);
    expect(broken.scores.categories.security).toBe(100);
    expect(broken.scores.overall).toBe(76);
    expect(broken.scores.capped).toBe(false);
  });

  it("malicious fixture is caught, and its critical failure caps the score", () => {
    expect(fails(malicious)).toEqual(["sec.description.control-characters", "sec.description.hidden-instructions", "sec.description.invisible-text"]);
    expect(malicious.scores.overall).toBeLessThanOrEqual(49);
    const evidence = JSON.stringify(malicious.findings);
    expect(evidence).not.toMatch(/\u001b/);
    expect(evidence).toContain("<U+202E>");
  });

  it("results conform to the result contract once a run section is complete", () => {
    expect(good.run).toMatchObject({ mode: "passive", runner: "self", sandbox: "none" });
  });
});

describe("engine over Streamable HTTP", () => {
  let server: { url: string; stop: () => void };
  beforeAll(async () => { server = await startHttpFixture("good"); });
  afterAll(() => server?.stop());
  it("good fixture passes over HTTP too", async () => {
    const r = await runTrustCheck({ kind: "streamable-http", url: server.url }, { packs });
    expect(r.target.transport).toBe("streamable-http");
    expect(fails(r)).toEqual([]);
    expect(r.scores.overall).toBe(100);
  });
});
