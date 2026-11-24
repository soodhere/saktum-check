// saktum fleet (v0.4, enterprise): merge scan-config results from many machines into one organisation inventory,
// evaluated against the organisation's policy. Command lines are redacted before they ever leave a machine.
import { evaluatePolicy, type Policy, type PolicyVerdict } from "./policy.js";
import { sanitizeText } from "./safe.js";

const SECRET_FLAG = /(key|token|secret|password|passwd|auth|bearer|credential|cookie)/i;
const RANDOM = /^[A-Za-z0-9_\-+/=]{24,}$/;
/** Redact secrets in a command line: values of secret-looking flags, long random strings, URL credentials and queries. */
export function redactCommand(command: string | undefined, args: string[] = []): string {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    const eq = a.indexOf("=");
    if (a.startsWith("-") && eq > 0 && SECRET_FLAG.test(a.slice(0, eq))) { out.push(`${a.slice(0, eq)}=\u2039redacted\u203a`); continue; }
    if (a.startsWith("-") && SECRET_FLAG.test(a) && i + 1 < args.length && !args[i + 1]!.startsWith("-")) { out.push(a, "\u2039redacted\u203a"); i++; continue; }
    if (RANDOM.test(a) && !/^[a-z@][a-z0-9@/._-]*$/.test(a)) { out.push("\u2039redacted\u203a"); continue; }
    out.push(redactUrl(a));
  }
  return sanitizeText([command ?? "", ...out].join(" ").trim(), 300);
}
export function redactUrl(s: string): string {
  if (!/^https?:\/\//i.test(s)) return s;
  try { const u = new URL(s); u.username = ""; u.password = ""; u.search = ""; u.hash = ""; return u.toString(); } catch { return s; }
}

export interface SetupServerRecord { name: string; client: string; target?: string; fingerprint?: string; trustGrade: string | null; readinessGrade: string | null; toolCount: number; tokens: number; capabilities?: string[]; lethalTrifecta?: boolean; failedSeverities?: string[]; error?: string }
export interface FleetServer { key: string; name: string; target?: string; fingerprint?: string; machines: number; clients: string[]; trustGrade: string | null; readinessGrade: string | null; tokens: number; capabilities: string[]; verdict?: PolicyVerdict }
export interface FleetReport { generatedAt: string; machines: number; servers: FleetServer[]; nonCompliant: number; unassessed: number; policyName?: string }

export function buildFleet(setups: { machine: string; servers: SetupServerRecord[] }[], policy?: Policy, allowlistFingerprints?: Set<string>): FleetReport {
  const map = new Map<string, FleetServer & { _machines: Set<string> }>();
  for (const s of setups) for (const x of s.servers) {
    const key = x.fingerprint ?? x.target ?? x.name;
    const e = map.get(key) ?? { key, name: x.name, target: x.target, fingerprint: x.fingerprint, machines: 0, clients: [], trustGrade: x.trustGrade, readinessGrade: x.readinessGrade, tokens: x.tokens, capabilities: x.capabilities ?? [], _machines: new Set<string>() };
    e._machines.add(s.machine);
    if (!e.clients.includes(x.client)) e.clients.push(x.client);
    if (policy && !x.error && !e.verdict) e.verdict = evaluatePolicy({ server: x.name, trustGrade: x.trustGrade, readinessGrade: x.readinessGrade, capabilities: x.capabilities ?? [], lethalTrifecta: Boolean(x.lethalTrifecta), contextTokens: x.tokens, failedSeverities: x.failedSeverities ?? [], toolsFingerprint: x.fingerprint }, policy, allowlistFingerprints);
    map.set(key, e);
  }
  const servers = [...map.values()].map(({ _machines, ...rest }) => ({ ...rest, machines: _machines.size })).sort((a, b) => b.machines - a.machines);
  return { generatedAt: new Date().toISOString(), machines: setups.length, servers, nonCompliant: servers.filter((s) => s.verdict && !s.verdict.compliant).length, unassessed: servers.filter((s) => !s.trustGrade).length, policyName: policy?.name };
}

export function renderFleet(f: FleetReport): string {
  const L = [`Saktum fleet: ${f.servers.length} distinct MCP servers across ${f.machines} machine(s)${f.policyName ? ` \u00b7 policy: ${f.policyName}` : ""}`, `  ${f.nonCompliant} violate policy \u00b7 ${f.unassessed} could not be assessed`, ""];
  for (const s of f.servers) L.push(`  ${s.verdict ? (s.verdict.compliant ? "\u2713" : "\u2717") : " "} ${sanitizeText(s.name, 30).padEnd(30)} ${String(s.machines).padStart(4)} machine(s)  trust ${s.trustGrade ?? "-"} \u00b7 readiness ${s.readinessGrade ?? "-"} \u00b7 ${s.tokens.toLocaleString("en-US")} tokens${s.verdict && !s.verdict.compliant ? `  \u2014 ${s.verdict.violations.filter((v) => !v.excepted).map((v) => v.message).join("; ")}` : ""}`);
  return L.join("\n") + "\n";
}

export function fleetHtml(f: FleetReport): string {
  const e = (x: unknown) => String(x ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
  const rows = f.servers.map((s) => `<tr><td>${s.verdict ? (s.verdict.compliant ? "\u2713" : "\u2717") : ""}</td><td><b>${e(s.name)}</b><br><small>${e(s.target ?? "")}</small></td><td class="n">${s.machines}</td><td>${e(s.clients.join(", "))}</td><td>${e(s.trustGrade ?? "-")}</td><td>${e(s.readinessGrade ?? "-")}</td><td class="n">${s.tokens.toLocaleString("en-US")}</td><td>${e(s.capabilities.join(", "))}</td><td>${e(s.verdict?.violations.map((v) => `${v.excepted ? "(excepted) " : ""}${v.message}`).join("; ") ?? "")}</td></tr>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>MCP server inventory</title>
<style>body{font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:24px;color:#16161d}table{border-collapse:collapse;width:100%}td,th{border-top:1px solid #ddd;padding:7px;text-align:left;vertical-align:top}.n{text-align:right}small{color:#666}</style></head><body>
<h1>MCP server inventory</h1><p>${f.servers.length} distinct servers across ${f.machines} machines${f.policyName ? ` · policy ${e(f.policyName)}` : ""} · ${f.nonCompliant} violate policy · ${f.unassessed} not assessed · generated ${e(f.generatedAt.slice(0, 10))} with Saktum Check.</p>
<div style="overflow-x:auto"><table><tr><th></th><th>Server</th><th>Machines</th><th>Clients</th><th>Trust</th><th>Readiness</th><th>Tokens/turn</th><th>Capabilities</th><th>Policy</th></tr>${rows}</table></div></body></html>
`;
}
