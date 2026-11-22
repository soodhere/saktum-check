// Build the single-file CLI (dist-bundle/saktum.mjs) for the private beta: Node 20+, no install, packs and contracts embedded.
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync("packages/cli/package.json", "utf8"));
await build({
  entryPoints: ["packages/cli/dist/main.js"],
  outfile: "dist-bundle/saktum.mjs",
  bundle: true, platform: "node", format: "esm", target: "node20", minify: false, legalComments: "inline",
  banner: { js: `// Saktum Check ${pkg.version} (private beta). Licensed Apache-2.0; bundled dependencies keep their own licences.\nimport { createRequire as __saktumCreateRequire } from "node:module";\nconst require = __saktumCreateRequire(import.meta.url);` }
});
const bytes = readFileSync("dist-bundle/saktum.mjs");
const sha = createHash("sha256").update(bytes).digest("hex");
writeFileSync("dist-bundle/saktum.mjs.sha256", `${sha}  saktum.mjs\n`);
console.log(`dist-bundle/saktum.mjs  ${(bytes.length / 1024).toFixed(0)} KB  sha256 ${sha}`);
