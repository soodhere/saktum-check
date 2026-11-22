// Renderers. Every string from the result passes through sanitizeText (terminal) or escapeHtml (HTML):
// the result contains server-derived text, and the server is untrusted.
import { escapeHtml, sanitizeText, type Finding, type Result, type Severity } from "@saktum/testkit-core";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const rank = (s: Severity) => SEV_ORDER.indexOf(s);
const SYMBOL: Record<Finding["status"], string> = { fail: "\u2717 FAIL", inconclusive: "! INCONCLUSIVE", pass: "\u2713 PASS", skipped: "- SKIPPED", info: "i INFO" };
/** Where users give feedback. Set by scripts/set-repo.mjs. */
export const FEEDBACK_URL = "https://github.com/soodhere/saktum-check/discussions";
/** Shown beside the trust grade, so an A reads as "passed what this version tests", not "proven safe". */
export const COVERAGE_NOTE = "This version tests conformance, sign-in basics, security hygiene, functional behaviour (with --active or test cases), performance and agent readiness; deeper sign-in, injection and supply-chain checks arrive in later releases.";
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
  MCP08: "error handling only; audit trails need runtime receipts from the Saktum gateway"
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


const PACK_DIMENSION: Record<string, string> = { conformance: "Conformance", auth: "Sign-in", security: "Security", functional: "Functional", tests: "Functional", performance: "Performance", "agent-experience": "Agent readiness" };
const dim = (f: Finding) => PACK_DIMENSION[f.pack] ?? "Other";

/** One line per trust dimension: tested and fine, issues found, or not tested (and why). */
export function trustCard(r: Result): { dimension: string; mark: string; text: string }[] {
  const rows: { dimension: string; mark: string; text: string }[] = [];
  const counted = (d: string) => r.findings.filter((f) => dim(f) === d && f.scored && !f.suppressed && (f.status === "pass" || f.status === "fail"));
  for (const d of ["Security", "Conformance", "Sign-in"]) {
    const fs = counted(d);
    const fails = fs.filter((f) => f.status === "fail");
    if (!fs.length) {
      const skipped = r.findings.find((f) => dim(f) === d && f.status === "skipped");
      const inconclusive = r.findings.find((f) => dim(f) === d && f.status === "inconclusive");
      rows.push({ dimension: d, mark: "-", text: skipped ? `not applicable: ${(skipped.message ?? "").replace(/\.$/, "").toLowerCase()}` : inconclusive ? `not tested: ${(inconclusive.message ?? "").replace(/\.$/, "")}` : "not tested" });
    } else rows.push({ dimension: d, mark: fails.length ? "\u2717" : "\u2713", text: fails.length ? `${fails.length} of ${fs.length} checks failed (worst: ${fails.sort((a, b) => rank(a.severity) - rank(b.severity))[0]!.severity})` : `${fs.length} checks passed` });
  }
  const fn = counted("Functional");
  const fnFails = fn.filter((f) => f.status === "fail");
  const called = r.functional?.calledTools.length ?? 0;
  if (fn.length) rows.push({ dimension: "Functional", mark: fnFails.length ? "\u2717" : "\u2713", text: `${fn.length - fnFails.length} of ${fn.length} functional checks passed${called ? ` (${called} tool${called === 1 ? "" : "s"} called)` : ""}${r.tests?.length ? `, ${r.tests.filter((t) => t.status === "pass").length} of ${r.tests.length} test cases` : ""}` });
  else rows.push({ dimension: "Functional", mark: "-", text: r.functional && !r.functional.ran ? "not tested: run with --active (read-only tools only) or add test cases with --tests" : "not tested: no tools were eligible to call (annotate read-only tools, use --call, or add test cases)" });
  if (r.load) rows.push({ dimension: "Performance", mark: r.load.levels.some((l) => l.errors) ? "!" : "\u2713", text: r.load.verdicts.join(" ") });
  else rows.push({ dimension: "Performance", mark: "-", text: `start-up and tool-list latency only${r.metrics.performance?.listMs !== undefined ? ` (${r.metrics.performance.listMs} ms)` : ""}; run with --active for latency percentiles and concurrency` });
  if (r.readiness) rows.push({ dimension: "Agent readiness", mark: r.readiness.grade ?? "-", text: r.readiness.topImprovement ? `${r.readiness.topImprovement}` : "annotations, descriptions and context cost all good" });
  if (r.capabilities) {
    const caps = r.capabilities.capabilities.map((c) => c.label);
    rows.push({ dimension: "Capabilities", mark: r.capabilities.lethalTrifecta ? "!" : "i", text: caps.length ? `${caps.join("; ")}${r.capabilities.lethalTrifecta ? ". Warning: private data + untrusted content + outbound channel (the lethal trifecta); limit what agents can combine" : ""}` : "no notable capabilities inferred" });
  }
  return rows;
}

/** What this run did and did not test, so a grade is never read as more than it is. */
export function scopeOfRun(r: Result): string[] {
  const lines: string[] = [];
  const ran = r.findings.filter((f) => f.status !== "skipped").length;
  const skipped = r.findings.filter((f) => f.status === "skipped");
  const reasons = new Map<string, number>();
  for (const f of skipped) { const k = (f.message ?? "skipped").replace(/\.$/, ""); reasons.set(k, (reasons.get(k) ?? 0) + 1); }
  lines.push(`Mode: ${r.run.mode}${r.run.mode === "passive" ? " (no tool was called; only listing, a call to a non-existent tool, and read-only probes)" : " (tools were called as listed above)"}.`);
  lines.push(`${ran} checks ran; ${skipped.length} did not apply to this run.`);
  for (const [why, n] of reasons) lines.push(`  ${n} \u00b7 ${why}`);
  const later = owaspCoverage(r).filter((c) => !c.tested && c.later && !c.later.startsWith("not applicable")).map((c) => `${c.id} (${c.later})`);
  if (later.length) lines.push(`Not yet tested by this version: ${later.join("; ")}.`);
  lines.push("Full list of checks, with the standard behind each: saktum checks.");
  return lines;
}

export function renderTerminal(r: Result): string {
  const s = (x: unknown, n?: number) => sanitizeText(x, n);
  const lines: string[] = [];
  lines.push(`Saktum Check ${s(r.tool.version)} \u00b7 ${s(r.target.description, 120)}`);
  lines.push(`Server: ${s(r.target.serverInfo?.["name"] ?? "unknown", 60)} ${s(r.target.serverInfo?.["version"] ?? "", 30)} \u00b7 ${r.target.toolCount ?? 0} tools`);
  if (r.run.sandbox === "none" && r.target.transport === "stdio") lines.push("Note: the local server ran without a sandbox. Only run servers you trust this way.");
  lines.push("");
  const ran = r.coverage?.trustChecksRun;
  lines.push(`  TRUST            ${r.grade ?? "-"}${r.scores.overall !== null ? `  (score ${r.scores.overall}${r.scores.capped ? ", capped: a critical check failed" : ""}${ran !== undefined ? ` \u00b7 ${ran} checks` : ""})` : ""}`);
  if (r.readiness) {
    const rd = r.readiness;
    lines.push(`  AGENT READINESS  ${rd.grade ?? "-"}  (score ${rd.score} \u00b7 annotations ${rd.toolsAnnotated}/${rd.toolCount} tools \u00b7 ${rd.contextTokens.toLocaleString("en-US")} tokens per turn)`);
  }
  const fn = r.findings.filter((f) => (f.pack === "functional" || f.pack === "tests") && f.scored && !f.suppressed && (f.status === "pass" || f.status === "fail"));
  lines.push(`  FUNCTIONAL       ${fn.length ? `${fn.filter((f) => f.status === "pass").length} of ${fn.length} checks passed${r.functional?.calledTools.length ? ` \u00b7 ${r.functional.calledTools.length} tool${r.functional.calledTools.length === 1 ? "" : "s"} called` : ""}${r.tests?.length ? ` \u00b7 ${r.tests.length} test cases` : ""}` : "not tested (run with --active, or add test cases)"}`);
  lines.push(`  ${COVERAGE_NOTE}`);
  for (const line of r.summary ?? []) lines.push(`  ${s(line, 300)}`);
  lines.push("");
  lines.push("TRUST CARD");
  for (const row of trustCard(r)) lines.push(`  ${row.dimension.padEnd(16)} ${row.mark.padEnd(2)} ${s(row.text, 400)}`);
  lines.push("");
  const shown = [...r.findings].filter((f) => f.status === "fail" || f.status === "inconclusive").sort((a, b) => rank(a.severity) - rank(b.severity));
  for (const f of shown) {
    lines.push(`${SYMBOL[f.status]} ${f.severity.toUpperCase()} ${s(f.check)}  ${s(f.title)}`);
    if (f.message) lines.push(`    ${s(f.message, 300)}`);
    if (f.evidence?.excerpt) lines.push(`    Evidence: ${s(f.evidence.excerpt, 200)}`);
    if (f.fix && f.status === "fail") lines.push(`    Fix: ${s(f.fix, 300)}`);
  }
  const passedF = r.findings.filter((f) => f.status === "pass");
  const byDim = new Map<string, number>();
  for (const f of passedF) byDim.set(dim(f), (byDim.get(dim(f)) ?? 0) + 1);
  const skipped = r.findings.filter((f) => f.status === "skipped").length;
  lines.push(`${SYMBOL.pass} ${passedF.length} checks passed (${[...byDim].map(([d, n]) => `${n} ${d.toLowerCase()}`).join(", ")})${skipped ? ` \u00b7 ${skipped} not applicable` : ""}`);
  const info = r.findings.filter((f) => f.status === "info");
  if (info.length) { lines.push(""); for (const f of info) lines.push(`i ${s(f.title)}: ${s(f.message, 300)}`); }
  if (r.functional?.ran) {
    lines.push(""); lines.push("TOOLS CALLED");
    for (const c of r.functional.calls) lines.push(`  ${s(c.tool, 40).padEnd(30)} ${c.purpose.padEnd(13)} ${s(c.outcome, 40).padEnd(18)} ${String(c.latencyMs).padStart(5)} ms${c.problems.length ? `  \u2717 ${s(c.problems.join("; "), 200)}` : ""}`);
    for (const n of r.functional.notCalled) lines.push(`  ${s(n.tool, 40).padEnd(30)} not called: ${s(n.why, 160)}`);
  }
  if (r.tests?.length) {
    lines.push(""); lines.push("TEST CASES");
    for (const t of r.tests) lines.push(`  ${t.status === "pass" ? "\u2713" : t.status === "fail" ? "\u2717" : "-"} ${s(t.id, 60).padEnd(30)} ${s(t.tool, 40).padEnd(24)} ${t.status === "pass" ? `${t.latencyMs ?? ""} ms` : s(t.problems.join("; "), 200)}`);
  }
  if (r.capabilities?.capabilities.length) {
    lines.push(""); lines.push("CAPABILITIES (inferred from annotations, names and descriptions; informational)");
    for (const c of r.capabilities.capabilities) lines.push(`  ${s(c.label, 80).padEnd(58)} ${c.basis === "declared" ? "declared" : "inferred"}: ${s(c.tools.join(", "), 160)}`);
    if (r.capabilities.lethalTrifecta) lines.push("  ! This server combines private data, untrusted content and an outbound channel (the lethal trifecta). Limit what an agent can do with it.");
  }
  if (r.suppressions?.length) {
    lines.push(""); lines.push("IGNORED BY THE PROVIDER (not scored)");
    for (const x of r.suppressions) lines.push(`  ${s(x.check, 60)}: ${s(x.reason, 200)}`);
  }
  lines.push(""); lines.push("SCOPE OF THIS RUN");
  for (const l of scopeOfRun(r)) lines.push(`  ${s(l, 400)}`);
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
<p class="grade">Trust ${e(r.grade ?? "-")}${r.readiness ? ` &middot; Agent readiness ${e(r.readiness.grade ?? "-")}` : ""}</p>
<p><small>${e(COVERAGE_NOTE)}</small></p>
${(r.summary ?? []).map((l) => `<p>${e(l)}</p>`).join("")}
<h2>Trust card</h2><table>${trustCard(r).map((x) => `<tr><td>${e(x.dimension)}</td><td>${e(x.mark)}</td><td>${e(x.text)}</td></tr>`).join("")}</table>
<h2>Findings</h2><table>${rows}</table>
<h2>Scope of this run</h2>${scopeOfRun(r).map((l) => `<p>${e(l)}</p>`).join("")}
<h2>OWASP MCP Top 10 coverage</h2><table>${cov}</table>
<p><small>${e(SELF_SIGNED_NOTE)} ${e(DISCLAIMER)}</small></p></body></html>`;
}

/** A README badge: "saktum | trust A · readiness C". Self-tested (L1), dated in its tooltip. Text is escaped. */
export function badgeSvg(r: Result): string {
  const colour = (g?: string | null) => ({ A: "#2e7d32", B: "#558b2f", C: "#f9a825", D: "#ef6c00", F: "#c62828" } as Record<string, string>)[g ?? ""] ?? "#757575";
  const right = `trust ${r.grade ?? "-"} \u00b7 readiness ${r.readiness?.grade ?? "-"}`;
  const lw = 52, rw = 7 * right.length + 14, w = lw + rw;
  const worst = [r.grade, r.readiness?.grade].filter(Boolean).sort().pop();
  const title = escapeHtml(`Saktum Check ${r.tool.version}: trust ${r.grade ?? "-"}, agent readiness ${r.readiness?.grade ?? "-"}; self-tested (L1) on ${r.run.startedAt.slice(0, 10)}`);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${title}"><title>${title}</title>`
    + `<rect width="${lw}" height="20" fill="#3b2e8c"/><rect x="${lw}" width="${rw}" height="20" fill="${colour(worst)}"/>`
    + `<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11"><text x="8" y="14">saktum</text><text x="${lw + 7}" y="14">${escapeHtml(right)}</text></g></svg>\n`;
}

/** Every check in the given packs, for `saktum checks`: what it tests, the standard behind it, and when it runs. */
export function checksTable(packs: { pack: { id: string; category: string; checks: { id: string; title: string; severity: string; safety: string; scored?: boolean; appliesTo?: { transports?: string[] }; references?: string[]; normative?: { source: string; clause?: string; level: string }[] }[] } }[], markdown = false): string {
  const rows = packs.flatMap(({ pack }) => pack.checks.map((c) => ({
    id: c.id, title: c.title, area: PACK_DIMENSION[pack.id] ?? pack.category, severity: c.severity, scored: c.scored === false || c.severity === "info" ? "no" : "yes",
    when: `${c.safety === "active" ? "--active only" : "every run"}${c.appliesTo?.transports ? `, ${c.appliesTo.transports.join("/")} servers` : ""}`,
    basis: (c.normative ?? []).map((n) => `${n.source}${n.clause ? `: ${n.clause}` : ""} (${n.level})`).concat((c.references ?? []).filter((x) => /OWASP|CWE|RFC/.test(x))).slice(0, 3).join("; ")
  })));
  if (markdown) return ["| Check | What it tests | Area | Severity | Scored | When it runs | Standard |", "| --- | --- | --- | --- | --- | --- | --- |",
    ...rows.map((x) => `| \`${x.id}\` | ${x.title} | ${x.area} | ${x.severity} | ${x.scored} | ${x.when} | ${x.basis.replace(/\|/g, "/")} |`)].join("\n") + "\n";
  return rows.map((x) => `${x.id.padEnd(34)} ${x.area.padEnd(16)} ${x.severity.padEnd(9)} ${x.when.padEnd(32)} ${x.title}`).join("\n") + "\n";
}
