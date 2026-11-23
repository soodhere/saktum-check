// Generate test-vectors/expected.json: for every fixture server, the verdict Saktum Check gives for every check.
// Other MCP testing tools can run the same fixtures and compare. Regenerate after changing packs or fixtures:
//   pnpm build && node --import tsx scripts/test-vectors.mjs
import { writeFileSync } from "node:fs";
import { loadPackDir, runTrustCheck } from "../packages/testkit-core/src/index.ts";
const packs = loadPackDir(new URL("../packs/", import.meta.url).pathname);
const fixtures = [["good", "passive"], ["good", "active"], ["broken", "passive"], ["malicious", "passive"], ["leaky", "passive"], ["faulty", "active"], ["empty", "passive"]];
const out = { generatedBy: "Saktum Check", note: "Expected verdicts per fixture and check. pass/fail are normative for these fixtures; info and skipped are informational.", vectors: [] };
for (const [name, mode] of fixtures) {
  const r = await runTrustCheck({ kind: "stdio", command: process.execPath, args: ["--import", "tsx", new URL(`../fixtures/src/${name}.ts`, import.meta.url).pathname] }, { packs, mode });
  out.vectors.push({ fixture: `fixtures/src/${name}.ts`, mode, trustGrade: r.grade, readinessGrade: r.readiness?.grade ?? null,
    verdicts: Object.fromEntries(r.findings.filter((f) => f.status === "pass" || f.status === "fail").map((f) => [f.check, f.status])) });
}
writeFileSync(new URL("../test-vectors/expected.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${out.vectors.length} vectors`);
