// v0.5 visuals: the MCP Server Passport, the Agent Passport (with the receipt timeline), ledger passport pages and
// gallery, and the executive assessment report for pilots. Self-contained HTML, light and dark, printable. All text is
// escaped; everything shown comes from signed evidence or the inputs named on each page.
import type { Result } from "@saktum/testkit-core";

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const GRADE_COLOUR: Record<string, string> = { A: "#2e7d32", B: "#558b2f", C: "#b7791f", D: "#c05621", F: "#c62828" };
const chip = (label: string, value: string | null | undefined, colour?: string) => `<span class="chip" style="${colour ? `background:${colour};color:#fff` : ""}"><small>${esc(label)}</small> <b>${esc(value ?? "-")}</b></span>`;

const STYLE = `:root{--bg:#f7f7fb;--card:#fff;--ink:#16161d;--muted:#5b5b6e;--line:#e2e2ea;--accent:#5a3fc0;--soft:#f0eff7}
@media (prefers-color-scheme:dark){:root{--bg:#101016;--card:#191922;--ink:#ededf5;--muted:#a3a3b8;--line:#2c2c3a;--accent:#8c78e6;--soft:#21212d;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:920px;margin:0 auto;padding:24px 16px 48px}.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px;margin-bottom:16px}
.top{display:flex;gap:16px;align-items:center;flex-wrap:wrap}.seal{width:64px;height:64px;border-radius:50%;display:grid;place-items:center;color:#fff;font-weight:800;font-size:22px;flex:none}
h1{font-size:24px;margin:0}h2{font-size:16px;margin:0 0 10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}.muted{color:var(--muted)}small{color:var(--muted)}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.chip{border:1px solid var(--line);border-radius:999px;padding:4px 10px;background:var(--soft);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}.kv{background:var(--soft);border-radius:10px;padding:10px}.kv b{display:block;font-size:20px}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%}td,th{border-top:1px solid var(--line);padding:7px 6px;text-align:left;vertical-align:top;font-size:14px}
code{font:12.5px ui-monospace,Menlo,Consolas,monospace;word-break:break-all}.levels{display:flex;gap:4px}.lv{flex:1;text-align:center;padding:6px 0;border-radius:6px;background:var(--soft);font-weight:700;font-size:13px}
.lv.on{background:var(--accent);color:#fff}.timeline{display:flex;flex-wrap:wrap;gap:6px}.step{border-radius:8px;padding:5px 8px;font-size:12.5px;border:1px solid var(--line)}
.ok{background:#e8f5e9;color:#1b5e20}.deny{background:#ffebee;color:#b71c1c}.err{background:#fff8e1;color:#7a5a00}.rep{outline:2px solid #b7791f}
@media (prefers-color-scheme:dark){.ok{background:#1b3a1e;color:#a5d6a7}.deny{background:#3b1616;color:#ef9a9a}.err{background:#3a3214;color:#ffe082}}
@media print{body{background:#fff}.card{break-inside:avoid}}`;
const page = (title: string, body: string) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><title>${esc(title)}</title><style>${STYLE}</style></head><body><main>${body}</main></body></html>\n`;

const levelBar = (level: number, note?: string) => `<div class="levels">${[1, 2, 3, 4, 5].map((l) => `<div class="lv${l <= level ? " on" : ""}">L${l}</div>`).join("")}</div><small>${esc(["", "Responds", "Conformant", "Safe by default", "Agent-ready", "Assured"][level] ?? "Not assessed")}${note ? ` · ${esc(note)}` : ""}</small>`;

export function levelFromResult(r: Result): number {
  if (!r.grade || !(r.target.toolCount ?? 0)) return 0;
  const failed = (pack: string) => r.findings.some((f) => f.pack === pack && f.status === "fail" && f.scored && !f.suppressed);
  if (failed("conformance")) return 1;
  if (failed("security")) return 2;
  return (r.readiness?.score ?? 0) >= 90 ? 4 : 3;
}

type Tool = { name: string; description?: string; inputSchema?: unknown; outputSchema?: unknown; annotations?: Record<string, unknown> };
const effect = (t: Tool) => { const a = t.annotations ?? {}; return a.readOnlyHint === true ? "reads" : a.destructiveHint === true ? "can destroy" : a.readOnlyHint === false ? "changes data" : "not declared"; };

/** The MCP Server Passport: identity, interface, trust and how to verify it, on one card. */
export function renderServerPassport(r: Result & { signature?: { kid?: string } }, tools: Tool[], o: { ledgerEntry?: number } = {}): string {
  const name = String(r.target.serverInfo?.["name"] ?? r.target.description), version = String(r.target.serverInfo?.["version"] ?? "");
  const lvl = levelFromResult(r), g = r.grade ?? "-";
  const caps = r.capabilities?.capabilities ?? [];
  const rows = tools.slice(0, 60).map((t) => { const req = ((t.inputSchema as { required?: string[] } | undefined)?.required ?? []).join(", ");
    return `<tr><td><code>${esc(t.name)}</code><br><small>${esc((t.description ?? "").split(/(?<=[.!?])\s/)[0]!.slice(0, 140))}</small></td><td>${esc(effect(t))}</td><td>${t.outputSchema ? "yes" : "no"}</td><td>${esc(req || "none")}</td></tr>`; }).join("");
  const body = `<div class="card"><div class="top"><div class="seal" style="background:${GRADE_COLOUR[g] ?? "#757575"}">${esc(g)}</div>
<div><small>MCP SERVER PASSPORT</small><h1>${esc(name)} ${esc(version)}</h1><div class="muted">${esc(r.target.transport)} · protocol ${esc(r.target.protocolVersion ?? "unknown")} · ${esc(String(r.target.toolCount ?? tools.length))} tools</div></div></div>
<div class="chips">${chip("Trust", r.grade, GRADE_COLOUR[g])}${chip("Agent readiness", r.readiness?.grade, GRADE_COLOUR[r.readiness?.grade ?? ""])}${chip("Context", `${(r.readiness?.contextTokens ?? 0).toLocaleString("en-US")} tokens/turn`)}${chip("Assurance", r.assuranceLevel ?? "L1")}${o.ledgerEntry ? chip("Ledger entry", `#${o.ledgerEntry}`) : ""}</div></div>
<div class="card"><h2>Maturity</h2>${levelBar(lvl, lvl === 4 ? "L5 also needs supply-chain evidence (provenance, no install scripts)" : undefined)}</div>
<div class="card"><h2>What it can do</h2>${caps.length ? `<div class="chips">${caps.map((c) => chip(c.basis, c.label)).join("")}</div>` : `<p class="muted">No notable capabilities inferred.</p>`}${r.capabilities?.lethalTrifecta ? `<p><b>Note:</b> combines private data, untrusted content and an outbound channel.</p>` : ""}</div>
<div class="card"><h2>Interface</h2>${tools.length ? `<div class="wrap"><table><tr><th>Tool</th><th>Effect</th><th>Output schema</th><th>Required inputs</th></tr>${rows}</table></div>${tools.length > 60 ? `<p class="muted">First 60 of ${tools.length} tools.</p>` : ""}` : `<p class="muted">Tool list not included.</p>`}</div>
<div class="card"><h2>Verify this passport</h2><p>Generated by Saktum Check ${esc(r.tool.version)} on ${esc(r.run.startedAt.slice(0, 10))} from a signed result${r.signature?.kid ? ` (signer <code>${esc(r.signature.kid)}</code>)` : ""}; tool fingerprint <code>${esc(r.target.toolsFingerprint ?? "-")}</code>. Check it yourself: <code>npx saktum verify saktum-report.json</code>${o.ledgerEntry ? ` and <code>npx saktum ledger find "${esc(name)}"</code>` : ""}.</p><p class="muted">Self-tested (L1) unless stated otherwise. A passport describes these exact tools at that time; any tool change needs a new one.</p></div>`;
  return page(`${name}: MCP Server Passport`, body);
}

export interface ReceiptSummaryLike { calls: number; denied: number; errors: number; destructiveAllowed: number; repeatedIdenticalCalls: { call: string; times: number }[]; servers: string[]; from?: string; to?: string }
export interface TimelineStep { tool: string; outcome: string; status: string; repeated: boolean }

/** The Agent Passport: identity, owner, mandate, validity, and the path its tool calls took. */
export function renderAgentPassport(m: { agent: { id: string; name: string }; owner: { id: string; name?: string }; purpose?: string; allow: { servers?: string[]; tools?: string[]; destructive: boolean }; issuedAt: string; expires: string },
  valid: { ok: boolean; reason?: string }, receipts?: { verified: boolean; summary: ReceiptSummaryLike; timeline: TimelineStep[] }): string {
  const s = receipts?.summary;
  const steps = (receipts?.timeline ?? []).slice(0, 80).map((t) => `<span class="step ${t.outcome === "deny" ? "deny" : t.status === "ok" ? "ok" : "err"}${t.repeated ? " rep" : ""}" title="${esc(t.outcome)} · ${esc(t.status)}">${t.outcome === "deny" ? "\u26d4" : t.status === "ok" ? "\u2713" : "!"} ${esc(t.tool)}</span>`).join("<span class=\"muted\">\u2192</span>");
  const body = `<div class="card"><div class="top"><div class="seal" style="background:${valid.ok ? "#5a3fc0" : "#c62828"}">AI</div>
<div><small>AGENT PASSPORT</small><h1>${esc(m.agent.name)}</h1><div class="muted">acts for ${esc(m.owner.name ?? m.owner.id)}${m.purpose ? ` · ${esc(m.purpose)}` : ""}</div></div></div>
<div class="chips">${chip("Mandate", valid.ok ? "valid" : "not valid", valid.ok ? "#2e7d32" : "#c62828")}${chip("Expires", m.expires)}${chip("Destructive actions", m.allow.destructive ? "allowed" : "not allowed")}${s ? chip("Receipts", receipts!.verified ? "verified" : "DO NOT verify", receipts!.verified ? "#2e7d32" : "#c62828") : ""}</div>${valid.ok ? "" : `<p><b>${esc(valid.reason)}</b></p>`}</div>
<div class="card"><h2>Mandate</h2><div class="grid"><div class="kv"><small>Servers</small><b>${esc(m.allow.servers?.join(", ") ?? "any")}</b></div><div class="kv"><small>Tools</small><b>${esc(m.allow.tools?.join(", ") ?? "any")}</b></div><div class="kv"><small>Issued</small><b>${esc(m.issuedAt.slice(0, 10))}</b></div></div>
<p class="muted">Agent identity <code>${esc(m.agent.id)}</code>, signed by its owner <code>${esc(m.owner.id)}</code>.</p></div>
${s ? `<div class="card"><h2>What it did</h2><div class="grid"><div class="kv"><small>Tool calls</small><b>${s.calls}</b></div><div class="kv"><small>Blocked</small><b>${s.denied}</b></div><div class="kv"><small>Errors</small><b>${s.errors}</b></div><div class="kv"><small>Destructive actions</small><b>${s.destructiveAllowed}</b></div></div>
${s.repeatedIdenticalCalls.length ? `<p><b>Repeated identical calls:</b> ${s.repeatedIdenticalCalls.map((x) => `${esc(x.call)} \u00d7${x.times}`).join(", ")} (possible retry storm; highlighted below).</p>` : ""}
<h2 style="margin-top:14px">The path, not the answer</h2><div class="timeline">${steps}</div><p class="muted">${esc(s.from?.slice(0, 19).replace("T", " ") ?? "")} to ${esc(s.to?.slice(0, 19).replace("T", " ") ?? "")} · ${esc(s.servers.join(", "))}. Each step is a signed, hash-chained receipt; arguments are stored only as digests.</p></div>` : ""}
<div class="card"><h2>Verify</h2><p><code>npx saktum agent verify agent-mandate.json</code> · <code>npx saktum receipts verify</code></p><p class="muted">Preview: receipts are signed by the agent side; the Saktum gateway adds the server side's signature.</p></div>`;
  return page(`${m.agent.name}: Agent Passport`, body);
}

type LedgerEntryLike = { seq: number; recordedAt: string; signer: string; subject: { server: string; version?: string; toolsFingerprint?: string };
  attestation: { claims: { trustGrade: string | null; readinessGrade: string | null; assuranceLevel: string; evidence: { responds: boolean; conformant: boolean; safeByDefault: boolean; agentReady: boolean } }; checkedAt: string; checkedWith: string; subject: { toolCount?: number; transport: string } } };
export const passportSlug = (server: string) => server.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 80) || "server";
const evidenceLevel = (e: LedgerEntryLike["attestation"]["claims"]["evidence"]) => (e.agentReady ? 4 : e.safeByDefault ? 3 : e.conformant ? 2 : e.responds ? 1 : 0);

/** A public passport page for one ledger entry (servers whose owners published an attestation). */
export function renderLedgerPassport(e: LedgerEntryLike): string {
  const c = e.attestation.claims, g = c.trustGrade ?? "-";
  const body = `<div class="card"><div class="top"><div class="seal" style="background:${GRADE_COLOUR[g] ?? "#757575"}">${esc(g)}</div><div><small>MCP SERVER PASSPORT · TRUST LEDGER ENTRY #${e.seq}</small><h1>${esc(e.subject.server)} ${esc(e.subject.version ?? "")}</h1>
<div class="muted">${esc(e.attestation.subject.transport)} · ${esc(String(e.attestation.subject.toolCount ?? "?"))} tools · checked ${esc(e.attestation.checkedAt.slice(0, 10))} with ${esc(e.attestation.checkedWith)}</div></div></div>
<div class="chips">${chip("Trust", c.trustGrade, GRADE_COLOUR[g])}${chip("Agent readiness", c.readinessGrade, GRADE_COLOUR[c.readinessGrade ?? ""])}${chip("Assurance", c.assuranceLevel)}${chip("Recorded", e.recordedAt.slice(0, 10))}</div></div>
<div class="card"><h2>Maturity evidence</h2>${levelBar(evidenceLevel(c.evidence))}</div>
<div class="card"><h2>Verify</h2><p>Signed by <code>${esc(e.signer)}</code>; tools fingerprint <code>${esc(e.subject.toolsFingerprint ?? "-")}</code>.</p><p><code>npx saktum ledger verify</code> · <code>npx saktum ledger find "${esc(e.subject.server)}"</code></p><p class="muted">A signed claim by the server's publisher (assurance ${esc(c.assuranceLevel)}; L1 = self-tested). It describes the tools matching the fingerprint at that time.</p></div>
<p class="muted"><a href="index.html">All passports</a> · <a href="../index.html">State of MCP Trust</a></p>`;
  return page(`${e.subject.server}: MCP Server Passport`, body);
}

export function renderPassportGallery(entries: LedgerEntryLike[]): string {
  const latest = new Map<string, LedgerEntryLike>();
  for (const e of entries) latest.set(e.subject.server, e);
  const cards = [...latest.values()].sort((a, b) => b.seq - a.seq).map((e) => { const g = e.attestation.claims.trustGrade ?? "-";
    return `<a class="card" style="display:flex;gap:12px;align-items:center;text-decoration:none;color:inherit" href="${passportSlug(e.subject.server)}.html"><div class="seal" style="width:44px;height:44px;font-size:16px;background:${GRADE_COLOUR[g] ?? "#757575"}">${esc(g)}</div><div><b>${esc(e.subject.server)}</b> <span class="muted">${esc(e.subject.version ?? "")}</span><br><small>readiness ${esc(e.attestation.claims.readinessGrade ?? "-")} · L${evidenceLevel(e.attestation.claims.evidence)} evidence · entry #${e.seq}</small></div></a>`; }).join("");
  return page("MCP Server Passports: the Saktum trust ledger", `<div class="card"><small>SAKTUM TRUST LEDGER</small><h1>MCP Server Passports</h1><p class="muted">Servers whose publishers recorded a signed Saktum attestation in the public, append-only ledger. Anyone can verify every entry: <code>npx saktum ledger verify</code>. Add yours: <code>npx saktum attest saktum-report.json --publish</code>.</p></div>${cards || `<p class="muted">No entries yet.</p>`}`);
}

type FleetLike = { generatedAt: string; machines: number; nonCompliant: number; unassessed: number; policyName?: string;
  servers: { name: string; machines: number; clients: string[]; trustGrade: string | null; readinessGrade: string | null; tokens: number; capabilities: string[]; verdict?: { compliant: boolean; violations: { rule: string; message: string; excepted?: unknown }[] } }[] };

/** The executive assessment for an MCP Trust Pilot: inventory, risk, policy, agent receipts and next steps. */
export function renderAssessment(org: string, f: FleetLike, receipts: { agent: string; summary: ReceiptSummaryLike; verified: boolean }[] = [],
  roi?: { annualToolCost: number; tokenSavings: number; reviewSavings: number; totalSavings: number; assumptions: string }): string {
  const risky = new Set(["code-execution", "money", "sends-messages", "writes-or-deletes", "reads-private-data"]);
  const caps = ["code-execution", "money", "sends-messages", "writes-or-deletes", "reads-private-data", "network", "filesystem", "untrusted-content"];
  const grades = ["A", "B", "C", "D", "F", "-"];
  const heat = caps.map((c) => `<tr><td>${esc(c)}</td>${grades.map((g) => { const n = f.servers.filter((s) => s.capabilities.includes(c) && (s.trustGrade ?? "-") === g).length; const hot = n && risky.has(c) && "CDF-".includes(g);
    return `<td style="text-align:center;${n ? `background:${hot ? "rgba(198,40,40,.18)" : "rgba(90,63,192,.10)"}` : ""}">${n || ""}</td>`; }).join("")}</tr>`).join("");
  const top = f.servers.filter((s) => (s.verdict && !s.verdict.compliant) || (!s.trustGrade) || (s.capabilities.some((c) => risky.has(c)) && "CDF".includes(s.readinessGrade ?? "F"))).slice(0, 12)
    .map((s) => `<tr><td><b>${esc(s.name)}</b></td><td>${s.machines}</td><td>${esc(s.trustGrade ?? "not assessed")} / ${esc(s.readinessGrade ?? "-")}</td><td>${esc(s.verdict?.violations.filter((v) => !v.excepted).map((v) => v.message).join("; ") || (s.trustGrade ? "risky capabilities with weak agent readiness" : "could not be assessed"))}</td></tr>`).join("");
  const tokens = f.servers.reduce((a, s) => a + s.tokens, 0);
  const rec: string[] = [];
  if (f.nonCompliant) rec.push(`Resolve or formally except the ${f.nonCompliant} server(s) that violate policy; enforce the policy in CI (Saktum Action, policy input).`);
  if (f.unassessed) rec.push(`Investigate the ${f.unassessed} server(s) that could not be assessed: unknown servers are the riskiest.`);
  if (f.servers.some((s) => s.capabilities.includes("money") || s.capabilities.includes("code-execution"))) rec.push("Put servers that move money or run code behind agent mandates with enforcement, and keep receipts for every call.");
  rec.push("Build an allowlist from approved results for your MCP firewall or gateway, pinned to tool fingerprints; re-check on every change.");
  if (tokens > 50_000) rec.push(`Tool definitions cost ${tokens.toLocaleString("en-US")} tokens per turn across distinct servers: remove duplicates and unused servers.`);
  const rc = receipts.map((r) => `<tr><td><b>${esc(r.agent)}</b></td><td>${r.summary.calls}</td><td>${r.summary.denied}</td><td>${r.summary.destructiveAllowed}</td><td>${esc(r.summary.repeatedIdenticalCalls.map((x) => `${x.call} \u00d7${x.times}`).join(", ") || "none")}</td><td>${r.verified ? "verified" : "NOT verified"}</td></tr>`).join("");
  const body = `<div class="card"><small>MCP TRUST ASSESSMENT</small><h1>${esc(org)}</h1><p class="muted">Prepared with Saktum on ${esc(f.generatedAt.slice(0, 10))}${f.policyName ? ` against policy “${esc(f.policyName)}”` : ""}. Evidence collected inside ${esc(org)}'s environment; nothing was sent to Saktum.</p>
<div class="grid"><div class="kv"><small>Machines</small><b>${f.machines}</b></div><div class="kv"><small>Distinct MCP servers</small><b>${f.servers.length}</b></div><div class="kv"><small>Violate policy</small><b>${f.nonCompliant}</b></div><div class="kv"><small>Not assessable</small><b>${f.unassessed}</b></div></div></div>
<div class="card"><h2>Risk heat map: capability by trust grade</h2><div class="wrap"><table><tr><th>Capability</th>${grades.map((g) => `<th style="text-align:center">${g === "-" ? "n/a" : g}</th>`).join("")}</tr>${heat}</table></div><small>Red cells: risky capabilities on servers graded C or below, or not assessed.</small></div>
<div class="card"><h2>Servers needing attention</h2>${top ? `<div class="wrap"><table><tr><th>Server</th><th>Machines</th><th>Trust / readiness</th><th>Why</th></tr>${top}</table></div>` : `<p>None: every assessed server meets the policy.</p>`}</div>
${rc ? `<div class="card"><h2>Agent receipts</h2><div class="wrap"><table><tr><th>Agent</th><th>Calls</th><th>Blocked</th><th>Destructive</th><th>Repeated calls</th><th>Receipts</th></tr>${rc}</table></div></div>` : ""}
${roi ? `<div class="card"><h2>Business case</h2><div class="grid"><div class="kv"><small>Tool definitions cost a year</small><b>$${roi.annualToolCost.toLocaleString("en-US")}</b></div><div class="kv"><small>Savings from fixes</small><b>$${roi.tokenSavings.toLocaleString("en-US")}</b></div><div class="kv"><small>Review effort replaced by passports</small><b>$${roi.reviewSavings.toLocaleString("en-US")}</b></div><div class="kv"><small>Total a year</small><b>$${roi.totalSavings.toLocaleString("en-US")}</b></div></div><p class="muted">Estimate. Assumptions: ${esc(roi.assumptions)}. Replace them with your own figures.</p></div>` : ""}
<div class="card"><h2>Recommendations</h2><ol>${rec.map((x) => `<li>${esc(x)}</li>`).join("")}</ol></div>
<div class="card"><h2>Next steps</h2><p>1. Agree the policy and exceptions with security. 2. Enforce it in CI on MCP repositories. 3. Deploy the allowlist to the MCP firewall or gateway. 4. Extend agent mandates and receipts to production agent workflows with the Saktum gateway (design partnership).</p><p class="muted">Findings describe the servers and agents at the time of assessment and are not a guarantee of security.</p></div>`;
  return page(`MCP Trust Assessment: ${org}`, body);
}
