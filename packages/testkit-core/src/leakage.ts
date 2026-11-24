// Secrets and information leakage. Scans tool definitions (descriptions, schemas, defaults, examples) and the answers
// to safe probe calls (an unknown tool; a read-only tool called with empty arguments). OWASP MCP01 and CWE-209.
// Excerpts are always redacted: Saktum never repeats a secret it finds.
import type { CallOutcome, ToolDef } from "@saktum/transports";
import type { Analyser, AnalyserContext } from "./analysers.js";
import { sanitizeText } from "./safe.js";

/** Specific, low-false-positive secret formats. Test keys (for example sk_test_) are deliberately not flagged. */
/** `valid` rejects look-alikes found in real servers' documentation (census reviews, Nov and Dec 2026):
 *  AWS's documented example keys (ending in EXAMPLE), and "password:" followed by a plain word rather than a value. */
export const SECRET_PATTERNS: { name: string; re: RegExp; valid?: (m: RegExpMatchArray) => boolean }[] = [
  { name: "AWS access key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, valid: (m) => !/EXAMPLE$/.test(m[0]) },
  { name: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "Stripe live key", re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/ },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "AI provider key", re: /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}\b/ },
  { name: "private key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/ },
  { name: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { name: "password or secret assignment", re: /\b(?:password|passwd|client_secret|api_secret|secret_key)\b["']?\s*[:=]\s*["']?(?!\{|\$|<|%|x{4})([^\s"',;]{8,})/i,
    valid: (m) => { const v = (m[1] ?? "").replace(/[).,;:!?]+$/, ""); return v.length >= 8 && /[A-Za-z]/.test(v) && /\d/.test(v) && !/example|placeholder|changeme|your[-_]?|redacted/i.test(v); } }
];

/** Signs of internal detail in error output: stack traces, file paths, database errors. */
export const LEAK_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "JavaScript stack trace", re: /\n?\s+at\s+[\w$.<>\[\] ]+\s+\(?(?:file:\/\/)?[\w./\\:-]+:\d+:\d+\)?/ },
  { name: "Python traceback", re: /Traceback \(most recent call last\)|File "[^"]+", line \d+/ },
  { name: "Java or .NET stack trace", re: /\bat [\w$.]+\([\w]+\.(?:java|cs|kt):\d+\)|Exception in thread "/ },
  // Application code paths only (source files, dependency folders): installed system binaries such as a browser are not internals.
  { name: "internal source path", re: /(?:\/home\/[\w.-]+|\/Users\/[\w.-]+|\/var\/www|\/srv|\/app|\/opt\/[\w.-]+|[A-Z]:\\(?:Users|inetpub)\\[\w.-]+)[\w./\\-]*?(?:\/(?:node_modules|site-packages|src|dist|lib)\/[\w./-]+|\.(?:js|mjs|cjs|ts|py|rb|php|java|go|cs)\b)/ },
  { name: "database error", re: /SQLSTATE\[|syntax error at or near|ORA-\d{5}|ECONNREFUSED [\d.]+:\d+/ }
];

function redact(text: string, match: string): string {
  const i = text.indexOf(match);
  const masked = match.length > 8 ? `${match.slice(0, 4)}…[redacted ${match.length - 4} chars]` : "[redacted]";
  const start = Math.max(0, i - 40);
  return sanitizeText(text.slice(start, i) + masked + text.slice(i + match.length, i + match.length + 20), 200);
}

export function outcomeText(o: CallOutcome | undefined): string {
  if (!o) return "";
  if (o.kind === "protocol-error") return o.message;
  if (o.kind === "result") return JSON.stringify(o.content ?? "") + JSON.stringify(o.structuredContent ?? "");
  return "";
}

function sources(ctx: AnalyserContext): { where: string; text: string }[] {
  const out: { where: string; text: string }[] = ctx.tools.map((t: ToolDef) => ({ where: `tool ${sanitizeText(t.name, 60)}`, text: JSON.stringify(t) }));
  if (ctx.probes?.unknownTool) out.push({ where: "the error for an unknown tool", text: outcomeText(ctx.probes.unknownTool) });
  if (ctx.probes?.invalidArgs) out.push({ where: `the error for ${sanitizeText(ctx.probes.invalidArgs.tool, 60)} called with empty arguments`, text: outcomeText(ctx.probes.invalidArgs.outcome) });
  return out;
}

export const leakageAnalysers: Record<string, Analyser> = {
  secrets: (ctx) => {
    for (const s of sources(ctx)) for (const p of SECRET_PATTERNS) {
      // Check every match, so a harmless look-alike cannot hide a real secret later in the same text.
      const all = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g");
      for (const m of s.text.matchAll(all)) if (!p.valid || p.valid(m))
        return { status: "fail", subject: s.where, message: `Found what looks like ${/^[aeiou]/i.test(p.name) ? "an" : "a"} ${p.name} in ${s.where}. Anyone who can list tools or trigger an error can read it.`, evidence: { excerpt: redact(s.text, m[0]) } };
    }
    return { status: "pass", message: "No secrets found in tool definitions or probe responses." };
  },
  "error-leakage": (ctx) => {
    const probes = sources(ctx).filter((s) => !s.where.startsWith("tool "));
    if (probes.length === 0) return { status: "inconclusive", message: "No error responses were available to inspect." };
    for (const s of probes) for (const p of LEAK_PATTERNS) {
      const m = s.text.match(p.re);
      if (m) return { status: "fail", subject: s.where, message: `${s.where[0]!.toUpperCase()}${s.where.slice(1)} exposes ${/^[aeiou]/i.test(p.name) ? "an" : "a"} ${p.name}, which helps attackers map your internals.`, evidence: { excerpt: sanitizeText(m[0], 200) } };
    }
    return { status: "pass", message: "Error responses do not expose stack traces, internal paths or database errors." };
  }
};

export const LEAKAGE_NEEDS = { secrets: "tools" as const, "error-leakage": "session" as const };
