// CycloneDX 1.5 SBOM of everything bundled into Saktum Check (production dependencies of the workspace packages).
// Usage: node scripts/sbom.mjs [out=dist-bundle/saktum.sbom.cdx.json]
import { execSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
const out = process.argv[2] ?? "dist-bundle/saktum.sbom.cdx.json";
const version = JSON.parse(readFileSync("npm/package.json", "utf8")).version;
const tree = JSON.parse(execSync("pnpm list -r --prod --json --depth Infinity", { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }));
const seen = new Map();
const walk = (deps) => { for (const [name, d] of Object.entries(deps ?? {})) {
  if (!d?.version || d.version.startsWith("link:") || name.startsWith("@saktum/")) { walk(d?.dependencies); continue; }
  const key = `${name}@${d.version}`;
  if (!seen.has(key)) seen.set(key, { type: "library", name, version: d.version, purl: `pkg:npm/${name.startsWith("@") ? `%40${name.slice(1)}` : name}@${d.version}`, "bom-ref": key });
  walk(d.dependencies);
} };
for (const pkg of tree) walk(pkg.dependencies);
const components = [...seen.values()].sort((a, b) => a["bom-ref"].localeCompare(b["bom-ref"]));
let bundleHash;
try { bundleHash = createHash("sha256").update(readFileSync("dist-bundle/saktum.mjs")).digest("hex"); } catch {}
const sbom = { bomFormat: "CycloneDX", specVersion: "1.5", serialNumber: `urn:uuid:${randomUUID()}`, version: 1,
  metadata: { timestamp: new Date().toISOString(), tools: [{ name: "saktum scripts/sbom.mjs" }],
    component: { type: "application", name: "saktum", version, purl: `pkg:npm/saktum@${version}`, "bom-ref": "saktum", licenses: [{ license: { id: "Apache-2.0" } }], ...(bundleHash ? { hashes: [{ alg: "SHA-256", content: bundleHash }] } : {}) } },
  components };
writeFileSync(out, JSON.stringify(sbom, null, 2) + "\n");
console.log(`SBOM: ${components.length} components -> ${out}`);
