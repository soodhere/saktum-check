// One-time setup after creating the GitHub repository: node scripts/set-repo.mjs <owner>/<repo>
// Replaces the OWNER/saktum-check placeholder everywhere (README, issue templates, npm package, report feedback link).
import { readFileSync, writeFileSync } from "node:fs";
const slug = process.argv[2];
if (!/^[\w.-]+\/[\w.-]+$/.test(slug ?? "")) { console.error("Usage: node scripts/set-repo.mjs <owner>/<repo>"); process.exit(1); }
const files = ["README.md", ".github/ISSUE_TEMPLATE/config.yml", "npm/package.json", "packages/report/src/index.ts", "docs/QUICKSTART.md"];
for (const f of files) {
  const before = readFileSync(f, "utf8");
  const after = before.replaceAll("OWNER/saktum-check", slug);
  if (after !== before) { writeFileSync(f, after); console.log(`updated ${f}`); }
}
console.log(`Done. Commit, then tag a release: git tag v0.1.0 && git push --tags`);
