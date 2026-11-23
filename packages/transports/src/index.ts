// MCP transports for Trust Check. One session interface over Streamable HTTP and stdio,
// with timeouts, response-size limits and an identifying user agent. All server data is untrusted.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";

export const USER_AGENT = "saktum-check/0.3.2 (+https://saktum.dev/check)";
export const LIMITS = { requestTimeoutMs: 10_000, connectTimeoutMs: 60_000, maxResponseChars: 5_000_000 };

export type TransportKind = "stdio" | "streamable-http";
export type Target =
  | { kind: "streamable-http"; url: string; headers?: Record<string, string> }
  | { kind: "stdio"; command: string; args: string[]; env?: Record<string, string>; cwd?: string };

export interface ToolDef { name: string; description?: string; inputSchema?: unknown; outputSchema?: unknown; annotations?: Record<string, unknown>; [k: string]: unknown }

export type CallOutcome =
  | { kind: "result"; isError: boolean; content: unknown; structuredContent?: unknown; latencyMs: number }
  | { kind: "protocol-error"; code: number; message: string; latencyMs: number }
  | { kind: "timeout"; latencyMs: number }
  | { kind: "transport-error"; message: string; latencyMs: number };

export interface Session {
  transport: TransportKind;
  /** Process ID of a local (stdio) server, for resource measurement. */
  pid?: number;
  description: string;
  sandbox: "none" | "docker";
  serverInfo?: { name?: string; version?: string; [k: string]: unknown };
  capabilities?: Record<string, unknown>;
  protocolVersion?: string;
  initMs: number;
  listTools(): Promise<ToolDef[]>;
  callTool(name: string, args: Record<string, unknown>): Promise<CallOutcome>;
  close(): Promise<void>;
}

export class LimitError extends Error {}
/** The server answered, but not in the shape the protocol requires. This is a finding about the server, not a network problem. */
export class ShapeError extends Error {}

// Trust Check must see raw responses: the SDK's strict validation would throw on exactly the malformed data we need to report.
// The SDK accepts any object with safeParse as a result schema, so this passes responses through untouched.
const PASS_THROUGH = { safeParse: (data: unknown) => ({ success: true as const, data }) } as never;

/** Parse a CLI target: an http(s) URL, or a command line for a local stdio server. */
export function parseTarget(parts: string[]): Target {
  const [first, ...rest] = parts;
  if (!first) throw new Error("no target given");
  if (/^https?:\/\//i.test(first)) return { kind: "streamable-http", url: first };
  return { kind: "stdio", command: first, args: rest };
}

export function describeTarget(t: Target): string {
  return t.kind === "streamable-http" ? t.url : [t.command, ...t.args].join(" ");
}

/** Variables a local server needs to start: paths, plus network plumbing (proxies, certificate bundles, package-manager
 *  configuration), so first-run downloads through corporate proxies work. Never credentials: any name suggesting a
 *  token, password, secret or auth value is excluded, even inside these families. */
const KEEP = ["PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "APPDATA", "LOCALAPPDATA", "NODE_PATH", "LANG",
  "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
  "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"];
const KEEP_PREFIXES = ["NPM_CONFIG_", "npm_config_", "UV_", "PIP_INDEX", "PIP_EXTRA_INDEX"];
const NEVER = /token|password|passwd|secret|auth|credential|_key$|apikey/i;

/** Environment passed to local servers: only what is needed to start, never the user's secrets. */
export function minimalEnv(extra?: Record<string, string>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (!v) continue;
    if ((KEEP.includes(k) || KEEP_PREFIXES.some((p) => k.startsWith(p))) && !NEVER.test(k)) env[k] = v;
  }
  return { ...env, ...(extra ?? {}) };
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${what} timed out after ${ms} ms`)), ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e); });
  });
}

function guardSize(value: unknown, what: string): void {
  const n = JSON.stringify(value ?? null).length;
  if (n > LIMITS.maxResponseChars) throw new LimitError(`${what} exceeded ${LIMITS.maxResponseChars} characters (${n})`);
}

export async function connect(target: Target): Promise<Session> {
  const client = new Client({ name: "saktum-trust-check", version: "0.0.1" }, { capabilities: {} });
  const transport = target.kind === "streamable-http"
    ? new StreamableHTTPClientTransport(new URL(target.url), { requestInit: { headers: { "User-Agent": USER_AGENT, ...(target.headers ?? {}) } } })
    : new StdioClientTransport({ command: target.command, args: target.args, env: minimalEnv(target.env), cwd: target.cwd, stderr: "ignore" });
  // The SDK records the negotiated protocol version only on transports that accept it; give every transport a setter.
  const tAny = transport as unknown as { protocolVersion?: string; setProtocolVersion?: (v: string) => void };
  if (!tAny.setProtocolVersion) tAny.setProtocolVersion = (v: string) => { tAny.protocolVersion = v; };
  const t0 = Date.now();
  await withTimeout(client.connect(transport), LIMITS.connectTimeoutMs, "connect");
  const initMs = Date.now() - t0;
  const anyTransport = transport as unknown as { protocolVersion?: string; setProtocolVersion?: (v: string) => void };
  return {
    transport: target.kind,
    description: describeTarget(target),
    sandbox: "none",
    pid: target.kind === "stdio" ? ((transport as unknown as { pid?: number | null }).pid ?? undefined) : undefined,
    serverInfo: client.getServerVersion() as Session["serverInfo"],
    capabilities: client.getServerCapabilities() as Record<string, unknown> | undefined,
    protocolVersion: anyTransport.protocolVersion,
    initMs,
    async listTools() {
      const tools: ToolDef[] = [];
      let cursor: string | undefined;
      for (let page = 0; page < 50; page++) {
        const res = (await client.request({ method: "tools/list", params: cursor ? { cursor } : {} }, PASS_THROUGH, { timeout: LIMITS.requestTimeoutMs })) as { tools?: unknown; nextCursor?: unknown };
        guardSize(res, "tools/list response");
        if (!res || !Array.isArray(res.tools)) throw new ShapeError("tools/list response has no tools array");
        tools.push(...(res.tools.filter((t) => t && typeof t === "object") as ToolDef[]));
        cursor = typeof res.nextCursor === "string" && res.nextCursor ? res.nextCursor : undefined;
        if (!cursor) break;
      }
      return tools;
    },
    async callTool(name, args) {
      const t = Date.now();
      try {
        const res = (await client.request({ method: "tools/call", params: { name, arguments: args } }, PASS_THROUGH, { timeout: LIMITS.requestTimeoutMs })) as { isError?: unknown; content?: unknown; structuredContent?: unknown };
        guardSize(res, "tools/call response");
        return { kind: "result", isError: Boolean(res.isError), content: res.content, structuredContent: res.structuredContent, latencyMs: Date.now() - t };
      } catch (e) {
        const latencyMs = Date.now() - t;
        if (e instanceof LimitError) throw e;
        if (e instanceof McpError) {
          if (e.code === -32001) return { kind: "timeout", latencyMs };
          return { kind: "protocol-error", code: e.code, message: e.message, latencyMs };
        }
        return { kind: "transport-error", message: (e as Error).message, latencyMs };
      }
    },
    async close() { await client.close().catch(() => undefined); }
  };
}


// ---------- Raw HTTP probing (sign-in checks run before, and independently of, an MCP session) ----------

export const HTTP_LIMITS = { timeoutMs: 8_000, maxBodyChars: 200_000 };

export interface HttpProbe {
  status: number | null;
  headers: Record<string, string>;
  body: string;
  error?: string;
  ms: number;
}

const INIT_BODY = JSON.stringify({
  jsonrpc: "2.0", id: 1, method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "saktum-trust-check-probe", version: "0.3.2" } }
});

/** One bounded HTTP request. Never throws: network failures come back as { status: null, error }. */
export async function httpRequest(url: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<HttpProbe> {
  const t0 = Date.now();
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), HTTP_LIMITS.timeoutMs);
  try {
    const res = await fetch(url, { method: init.method ?? "GET", headers: { "User-Agent": USER_AGENT, ...(init.headers ?? {}) }, body: init.body, signal: ctl.signal, redirect: "manual" });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    let body = "";
    try { body = (await res.text()).slice(0, HTTP_LIMITS.maxBodyChars); } catch { /* body unreadable */ }
    return { status: res.status, headers, body, ms: Date.now() - t0 };
  } catch (e) {
    return { status: null, headers: {}, body: "", error: (e as Error).name === "AbortError" ? "timed out" : (e as Error).message, ms: Date.now() - t0 };
  } finally { clearTimeout(timer); }
}

/** POST an MCP initialize request, optionally with an Authorization header, and report how the server answers. */
export function probeInitialize(url: string, headers: Record<string, string> = {}): Promise<HttpProbe> {
  return httpRequest(url, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers }, body: INIT_BODY });
}

/** Fetch and parse a JSON document (metadata endpoints). */
export async function fetchJson(url: string): Promise<{ status: number | null; json?: Record<string, unknown>; error?: string }> {
  const r = await httpRequest(url, { headers: { Accept: "application/json" } });
  if (r.status === null) return { status: null, error: r.error };
  if (r.status < 200 || r.status >= 300) return { status: r.status, error: `HTTP ${r.status}` };
  try {
    const json = JSON.parse(r.body);
    if (!json || typeof json !== "object" || Array.isArray(json)) return { status: r.status, error: "not a JSON object" };
    return { status: r.status, json: json as Record<string, unknown> };
  } catch { return { status: r.status, error: "not valid JSON" }; }
}

// ---------- Resource measurement for local servers ----------

/** Resident memory (MB) and CPU (%) of a local server, summed over its whole process tree: servers started through
 *  npx, uvx or a shell run as children of the launcher, so measuring only the launcher would be wrong. Via ps;
 *  unavailable on Windows (returns undefined). */
export async function processUsage(pid: number): Promise<{ rssMb: number; cpuPct: number; processes: number } | undefined> {
  if (process.platform === "win32") return undefined;
  const { execFile } = await import("node:child_process");
  const table = await new Promise<string | undefined>((resolve) =>
    execFile("ps", ["-A", "-o", "pid=,ppid=,rss=,pcpu="], { timeout: 3000, maxBuffer: 4_000_000 }, (err, stdout) => resolve(err ? undefined : stdout)));
  if (!table) return undefined;
  const rows = table.trim().split("\n").map((l) => l.trim().split(/\s+/).map(Number)).filter((r) => r.length >= 4 && r.every(Number.isFinite));
  const children = new Map<number, number[]>();
  for (const [p, pp] of rows) { const list = children.get(pp!) ?? []; list.push(p!); children.set(pp!, list); }
  const tree = new Set<number>([pid]);
  const queue = [pid];
  while (queue.length) for (const c of children.get(queue.shift()!) ?? []) if (!tree.has(c)) { tree.add(c); queue.push(c); }
  let rssKb = 0, cpu = 0, n = 0;
  for (const [p, , rss, pc] of rows) if (tree.has(p!)) { rssKb += rss!; cpu += pc!; n++; }
  if (n === 0) return undefined;
  return { rssMb: Math.round((rssKb / 1024) * 10) / 10, cpuPct: Math.round(cpu * 10) / 10, processes: n };
}
