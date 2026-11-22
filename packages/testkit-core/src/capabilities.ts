// Capability profile (v0.2): what this server's tools can do, so consumers see the risk before connecting.
// Inferred from annotations (declared), then names, descriptions and argument names (inferred). Always reported with
// the tools that triggered it, and labelled as inferred: it informs, it never changes a grade.
import type { ToolDef } from "@saktum/transports";
import { sanitizeText } from "./safe.js";

export type Capability = "reads-private-data" | "untrusted-content" | "network" | "code-execution" | "filesystem" | "writes-or-deletes" | "sends-messages" | "money";

export const CAPABILITY_LABELS: Record<Capability, string> = {
  "reads-private-data": "reads private or account data",
  "untrusted-content": "brings in untrusted content (web pages, emails, documents)",
  network: "reaches the network",
  "code-execution": "runs code or commands",
  filesystem: "reads or writes files",
  "writes-or-deletes": "changes or deletes data",
  "sends-messages": "sends messages or posts content",
  money: "moves money or makes purchases"
};

/** Conservative rules (tuned on 30 real servers). A capability is reported only when declared by annotations, when two
 *  independent signals agree (name, description, argument name), or when the description states it unambiguously
 *  (strong). Ambiguous words (search, post, set, save, add, order, checkout, user, profile, document) are not signals. */
const RULES: { cap: Capability; name: RegExp; text: RegExp; strong?: RegExp; arg?: RegExp }[] = [
  { cap: "code-execution", name: /(^|[_-])(exec|execute|eval|shell|bash|terminal|psql|run_command|run_code|run_script)([_-]|$)|exec_in_/i, text: /\b(execute|run)s? (a |an |the )?(shell|terminal|bash|command|script|code|program|sql|query)\b/i, strong: /\b(arbitrary (code|commands?)|shell commands?|(executes?|runs?) (shell|terminal|bash) commands?|runs? (javascript|python) code|starts? (a |an )?(new )?(terminal|shell) (process|session))\b/i, arg: /^(command|cmd|script|code|shell)$/i },
  { cap: "filesystem", name: /(^|[_-])(read_file|write_file|edit_file|move_file|list_directory|create_directory|directory_tree|filesystem|fs)([_-]|$)/i, text: /\b(local )?file ?system\b|\bon (the )?(local )?(disk|machine)\b|\b(files?|director(y|ies)) (on|in) the (user'?s )?(computer|machine|disk)\b/i, arg: /^(path|filepath|file_path|directory|dir)$/i },
  { cap: "network", name: /(^|[_-])(fetch|http|download|webhook|crawl|scrape|browse|navigate)([_-]|$)/i, text: /\b(fetch(es)? (a |the )?(url|web ?page|website)|http requests?|crawls?|scrapes?|web ?hooks?|downloads? .{0,20} from)\b/i, strong: /\b(http requests?|fetch(es)? (a |the |any )?(url|web ?page|website))\b/i, arg: /^(url|uri|endpoint|webhook|href)$/i },
  { cap: "untrusted-content", name: /(^|[_-])(fetch|crawl|scrape|browse|web_search|read_email|get_email|read_emails|read_message|read_messages)([_-]|$)/i, text: /\b(web ?pages?|websites?|internet|emails?|inbox|scrap(e|es|ing)|crawl(s|ing)?)\b/i, strong: /\b(search(es)? the (web|internet)|web search|scrap(e|es|ing) (web|pages|sites)|crawl(s|ing)? (a |the )?(web|site|website)|web ?pages?)\b/i },
  { cap: "reads-private-data", arg: /^(sql)$/i, name: /(^|[_-])(query|sql|customers?|contacts?|inbox|calendar|crm|database|db)([_-]|$)/i, text: /\b(reads?|retrieves?|gets?|lists?|search(es)?|quer(y|ies)|looks? up|fetch(es)?|returns?)\b.{0,40}\b(database|customers?|contacts?|account (data|details)|personal|private|inbox|calendar|crm)\b/i },
  { cap: "writes-or-deletes", name: /(^|[_-])(create|update|delete|remove|write|insert|upsert|drop|patch|edit|modify|move|rename|overwrite|reset|commit|push|purge)([_-]|$)/i, text: /\b(deletes?|removes?|overwrites?|modif(y|ies)|updates?|creates?|writes?) (a |an |the |one or more )?(new )?\w+/i },
  { cap: "sends-messages", name: /(^|[_-])(send|notify|reply|tweet|sms|send_message|send_email|post_message)([_-]|$)/i, text: /\bsends? (an? )?(new )?(email|message|sms|notification)|\bposts? (a |an )?(new )?(message|comment|tweet|reply)\b|\brepl(y|ies) to (a |the )?(specific )?(message|thread|email)/i, strong: /\bsends? (an? )?(email|sms|text message|slack message)s?\b|\bposts? (a |an )?(new )?message to (a |the )?(slack )?channel\b/i },
  { cap: "money", name: /(^|[_-])(pay|payment|payments|charge|refund|refunds|invoice|invoices|payout|purchase|billing)([_-]|$)/i, text: /\b(payments?|charges? (a |the )?(card|customer)|refunds?|invoices?|transfers? (funds|money)|purchases?)\b/i, strong: /\b(refunds? (a |the )?(payment|charge)|charges? (a |the )?(card|customer)|creates? (a |an )?(invoice|payment|payout))\b/i }
];

export interface CapabilityProfile {
  capabilities: { capability: Capability; label: string; tools: string[]; basis: "declared" | "inferred" }[];
  lethalTrifecta: boolean;
  note: string;
}

export function capabilityProfile(tools: ToolDef[]): CapabilityProfile {
  const found = new Map<Capability, { tools: Set<string>; declared: boolean }>();
  const add = (c: Capability, tool: string, declared = false) => {
    const e = found.get(c) ?? { tools: new Set<string>(), declared: false };
    e.tools.add(sanitizeText(tool, 60)); e.declared ||= declared; found.set(c, e);
  };
  for (const t of tools) {
    const a = (t.annotations ?? {}) as { readOnlyHint?: boolean; destructiveHint?: boolean; openWorldHint?: boolean };
    if (a.openWorldHint === true) add("network", t.name, true);
    if (a.destructiveHint === true || a.readOnlyHint === false) add("writes-or-deletes", t.name, true);
    const args = Object.keys(((t.inputSchema ?? {}) as { properties?: Record<string, unknown> }).properties ?? {});
    // Judge a tool by its first sentence: long descriptions often list related settings or other tools further down.
    const desc = (t.description ?? "").trim().split(/(?<=[.!?])\s/)[0]!.slice(0, 280);
    for (const r of RULES) {
      if (r.cap === "writes-or-deletes" && a.readOnlyHint === true) continue; // a declared read-only tool overrides name guesses
      const signals = Number(r.name.test(t.name)) + Number(r.text.test(desc)) + Number(Boolean(r.arg && args.some((x) => r.arg!.test(x))));
      if (signals >= 2 || (r.strong && r.strong.test(desc))) add(r.cap, t.name);
    }
  }
  const has = (c: Capability) => found.has(c);
  const lethalTrifecta = has("reads-private-data") && has("untrusted-content") && (has("network") || has("sends-messages"));
  const order = Object.keys(CAPABILITY_LABELS) as Capability[];
  return {
    capabilities: order.filter(has).map((c) => ({ capability: c, label: CAPABILITY_LABELS[c], tools: [...found.get(c)!.tools].slice(0, 8), basis: found.get(c)!.declared ? "declared" : "inferred" })),
    lethalTrifecta,
    note: "Inferred from annotations, tool names, descriptions and argument names; it describes what the tools appear able to do, not a finding."
  };
}
