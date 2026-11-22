// Renderers. Every string from the result passes through sanitizeText (terminal) or escapeHtml (HTML):
// the result contains server-derived text, and the server is untrusted.
import { escapeHtml, sanitizeText, type Finding, type Result, type Severity } from "@saktum/testkit-core";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const rank = (s: Severity) => SEV_ORDER.indexOf(s);
const SYMBOL: Record<Finding["status"], string> = { fail: "\u2717 FAIL", inconclusive: "! INCONCLUSIVE", pass: "\u2713 PASS", skipped: "- SKIPPED", info: "i INFO" };
/** Where users give feedback. Set by scripts/set-repo.mjs. */
export const FEEDBACK_URL = "https://github.com/soodhere/saktum-check/discussions";
export const DISCLAIMER = "Findings describe this server at the time of the run. They are not a guarantee of security or correctness.";
export const SELF_SIGNED_NOTE = "Assurance level L1 (self-tested): the signature proves this report was not changed after the run, not that it was run independently.";

/** The OWASP MCP Top 10 categories (verify names against the official OWASP project). */
export const OWASP_MCP: [string, string][] = [
  ["MCP01", "Token mismanagement and secret exposure"], ["MCP02", "Privilege escalation via scope creep"], ["MCP03", "Tool poisoning"],
  ["MCP04", "Software supply chain and dependency tampering"], ["MCP05", "Command injection and execution"], ["MCP06", "Intent flow subversion"],
  ["MCP07", "Insufficient authentication and authorization"], ["MCP08", "Lack of audit and telemetry"], ["MCP09", "Shadow MCP servers"],
  ["MCP10", "Context injection and over-sharing"]
];
/** Where untested categories are covered later. */
const LATER: Record<string, string> = {
  MCP02: "scope tests in v0.2 to v0.6", MCP04: "supply-chain checks in v0.5", MCP05: "active injection checks in v0.2",
  MCP06: "adversarial agent tests in v0.6", MCP08: "runtime receipts (Saktum gateway)", MCP09: "scan-config in v0.4", MCP10: "memory and over-sharing tests in v0.6"
};

/** Categories that v0.1 only partly covers: a pass means "no problem found by the checks that exist", not full coverage. */
export const PARTIAL: Record<string, string> = {
  MCP02: "danger annotations only; scope tests in v0.2 to v0.6",
  MCP05: "schema validity only; active injection tests in v0.2",
  MCP06: "hidden-instruction scanning only; adversarial agent tests in v0.6",
  MCP08: "error handling only; audit trails need runtime receipts (Saktum gateway)"
};

export function owaspCoverage(r: Result): { id: string; name: string; tested: number; failed: number; later?: string; partial?: string }[] {
  return OWASP_MCP.map(([id, name]) => {
    const all = r.findings.filter((f) => (f.references ?? []).some((ref) => ref.includes(`OWASP MCP Top 10: ${id}`)));
    const related = all.filter((f) => f.status === "pass" || f.status === "fail");
    const notApplicable = related.length === 0 && all.length > 0 && all.every((f) => f.status === "skipped");
    return { id, name, tested: related.length, failed: related.filter((f) => f.status === "fail").length, partial: related.length ? PARTIAL[id] : undefined,
      later: related.length ? undefined : notApplicable ? `not applicable here (${all[0]!.message?.replace(/\.$/, "").toLowerCase() ?? "skipped"})` : LATER[id] ?? "planned" };
  });
}

export function renderTerminal(r: Result): string {
  const s = (x: unknown, n?: number) => sanitizeText(x, n);
  const lines: string[] = [];
  lines.push(`Saktum Check ${s(r.tool.version)} \u00b7 ${s(r.target.description, 120)}`);
  lines.push(`Server: ${s(r.target.serverInfo?.["name"] ?? "unknown", 60)} ${s(r.target.serverInfo?.["version"] ?? "", 30)} \u00b7 ${r.target.toolCount ?? 0} tools`);
  if (r.run.sandbox === "none" && r.target.transport === "stdio") lines.push("Note: the local server ran without a sandbox. Only run servers you trust this way.");
  lines.push("");
  lines.push(`  GRADE ${r.grade ?? "-"}${r.scores.overall !== null ? `  (trust score ${r.scores.overall}${r.scores.capped ? ", capped: a critical check failed" : ""})` : ""}`);
  for (const line of r.summary ?? []) lines.push(`  ${s(line, 300)}`);
  lines.push("");
  for (const [c, v] of Object.entries(r.scores.categories)) lines.push(`  ${c.padEnd(18)} ${v === null ? "n/a" : String(v).padStart(3)}`);
  lines.push("");
  const shown = [...r.findings].filter((f) => f.status === "fail" || f.status === "inconclusive").sort((a, b) => rank(a.severity) - rank(b.severity));
  for (const f of shown) {
    lines.push(`${SYMBOL[f.status]} ${f.severity.toUpperCase()} ${s(f.check)}  ${s(f.title)}`);
    if (f.message) lines.push(`    ${s(f.message, 300)}`);
    if (f.evidence?.excerpt) lines.push(`    Evidence: ${s(f.evidence.excerpt, 200)}`);
    if (f.fix && f.status === "fail") lines.push(`    Fix: ${s(f.fix, 300)}`);
  }
  const passed = r.findings.filter((f) => f.status === "pass").length;
  const skipped = r.findings.filter((f) => f.status === "skipped").length;
  lines.push(`${SYMBOL.pass} ${passed} checks passed${skipped ? ` \u00b7 ${skipped} not applicable` : ""}`);
  const info = r.findings.filter((f) => f.status === "info");
  if (info.length) { lines.push(""); for (const f of info) lines.push(`i ${s(f.title)}: ${s(f.message, 300)}`); }
  lines.push("");
  lines.push("OWASP MCP Top 10 coverage in this run:");
  for (const c of owaspCoverage(r)) {
    const status = c.tested ? (c.failed ? `\u2717 ${c.failed} of ${c.tested} failed` : `\u2713 ${c.tested} passed`) : (c.later?.startsWith("not applicable") ? c.later : `later: ${c.later}`);
    lines.push(`  ${c.id} ${c.name.padEnd(48)} ${status}${c.partial ? ` (partial: ${c.partial})` : ""}`);
  }
  lines.push("");
  lines.push(SELF_SIGNED_NOTE);
  lines.push(DISCLAIMER);
  lines.push("");
  lines.push(`Feedback shapes the next release (2 minutes): ${FEEDBACK_URL}`);
  return lines.join("\n");
}

export function renderHtml(r: Result): string {
  const e = (x: unknown) => escapeHtml(sanitizeText(x, 1000));
  const rows = [...r.findings].sort((a, b) => rank(a.severity) - rank(b.severity)).map((f) =>
    `<tr class="${e(f.status)}"><td>${e(SYMBOL[f.status])}</td><td>${e(f.severity)}</td><td><code>${e(f.check)}</code><br>${e(f.title)}</td><td>${e(f.message ?? "")}${f.evidence?.excerpt ? `<br><small>Evidence: ${e(f.evidence.excerpt)}</small>` : ""}${f.fix && f.status === "fail" ? `<br><strong>Fix:</strong> ${e(f.fix)}` : ""}</td></tr>`).join("\n");
  const cov = owaspCoverage(r).map((c) => `<tr><td>${e(c.id)}</td><td>${e(c.name)}</td><td>${c.tested ? (c.failed ? `\u2717 ${c.failed} of ${c.tested} failed` : `\u2713 ${c.tested} passed`) : e(c.later ?? "planned")}${c.partial ? ` <small>(partial: ${e(c.partial)})</small>` : ""}</td></tr>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Saktum Check report</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%;margin:1rem 0}td{border-top:1px solid #ddd;padding:.5rem;vertical-align:top}.grade{font-size:3rem;font-weight:700}.fail td:first-child{font-weight:600}code{font-size:13px}</style></head><body>
<h1>Saktum Check report</h1>
<p>${e(r.target.description)} &middot; ${e(r.target.serverInfo?.["name"] ?? "")} ${e(r.target.serverInfo?.["version"] ?? "")} &middot; ${r.target.toolCount ?? 0} tools</p>
<p class="grade">Grade ${e(r.grade ?? "-")}</p>
${(r.summary ?? []).map((l) => `<p>${e(l)}</p>`).join("")}
<table>${rows}</table>
<h2>OWASP MCP Top 10 coverage</h2><table>${cov}</table>
<p><small>${e(SELF_SIGNED_NOTE)} ${e(DISCLAIMER)}</small></p></body></html>`;
}
