// Sign-in (authorization) analysers. They run against the raw HTTP answers of a remote server, so they work even when
// the server refuses an unauthenticated MCP session, which is exactly the behaviour being tested.
// References: MCP authorization specification; RFC 9728 (protected resource metadata); RFC 8414 (authorization server
// metadata); RFC 6750 (bearer tokens); RFC 7636 (PKCE). Every network answer is untrusted.
import { fetchJson } from "@saktum/transports";
import type { Analyser, AnalyserContext, Verdict } from "./analysers.js";
import { sanitizeText } from "./safe.js";

const skippedNotHttp: Verdict = { status: "skipped", message: "Applies to remote (HTTP) servers only." };
const skippedNoAuth: Verdict = { status: "skipped", message: "The server does not require sign-in, so this check does not apply." };

function serverUrl(ctx: AnalyserContext): URL | undefined {
  if (ctx.target?.kind !== "streamable-http") return undefined;
  try { return new URL(ctx.target.url); } catch { return undefined; }
}
const isLocal = (u: URL) => ["localhost", "127.0.0.1", "[::1]", "::1"].includes(u.hostname) || u.hostname.endsWith(".localhost");
const requiresAuth = (ctx: AnalyserContext) => ctx.http?.unauthenticated?.status === 401;

/** Parse a WWW-Authenticate challenge such as: Bearer resource_metadata="https://x/.well-known/...", error="invalid_token". */
export function parseChallenge(header: string | undefined): { scheme?: string; params: Record<string, string> } {
  if (!header) return { params: {} };
  const scheme = header.trim().split(/\s+/)[0];
  const params: Record<string, string> = {};
  const re = /([a-zA-Z_][\w-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(header))) params[m[1]!.toLowerCase()] = (m[2] ?? m[3] ?? "").replace(/\\(.)/g, "$1");
  return { scheme, params };
}

/** RFC 9728 section 3: the well-known URI is inserted between the host and the path of the resource identifier. */
export function wellKnownUrls(resource: URL, suffix: string): string[] {
  const path = resource.pathname.replace(/\/$/, "");
  const urls = [`${resource.origin}/.well-known/${suffix}${path}`];
  if (path) urls.push(`${resource.origin}/.well-known/${suffix}`);
  return urls;
}

// Per-run cache, so several checks share one metadata fetch.
const cache = new WeakMap<AnalyserContext, { prm?: Promise<{ url?: string; doc?: Record<string, unknown>; error?: string }>; as?: Promise<{ url?: string; doc?: Record<string, unknown>; error?: string }> }>();
function slot(ctx: AnalyserContext) { let s = cache.get(ctx); if (!s) { s = {}; cache.set(ctx, s); } return s; }

function loadResourceMetadata(ctx: AnalyserContext) {
  const s = slot(ctx);
  s.prm ??= (async () => {
    const u = serverUrl(ctx);
    if (!u) return { error: "not an HTTP target" };
    const fromHeader = parseChallenge(ctx.http?.unauthenticated?.headers["www-authenticate"]).params["resource_metadata"];
    const candidates = [...(fromHeader ? [fromHeader] : []), ...wellKnownUrls(u, "oauth-protected-resource")];
    let lastError = "not found";
    for (const url of candidates) {
      let parsed: URL;
      try { parsed = new URL(url, u); } catch { lastError = "invalid resource_metadata URL"; continue; }
      const r = await fetchJson(parsed.toString());
      if (r.json) return { url: parsed.toString(), doc: r.json };
      lastError = `${sanitizeText(parsed.toString(), 120)}: ${r.error}`;
    }
    return { error: lastError };
  })();
  return s.prm;
}

function loadServerMetadata(ctx: AnalyserContext) {
  const s = slot(ctx);
  s.as ??= (async () => {
    const prm = await loadResourceMetadata(ctx);
    const servers = prm.doc?.["authorization_servers"];
    const issuer = Array.isArray(servers) && typeof servers[0] === "string" ? servers[0] : undefined;
    if (!issuer) return { error: "no authorization server listed in the protected resource metadata" };
    let iu: URL;
    try { iu = new URL(issuer); } catch { return { error: "authorization server is not a valid URL" }; }
    const candidates = [...wellKnownUrls(iu, "oauth-authorization-server"), ...wellKnownUrls(iu, "openid-configuration"), `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`];
    let lastError = "not found";
    for (const url of [...new Set(candidates)]) {
      const r = await fetchJson(url);
      if (r.json) return { url, doc: r.json };
      lastError = `${sanitizeText(url, 120)}: ${r.error}`;
    }
    return { error: lastError };
  })();
  return s.as;
}

const sameResource = (a: string, b: URL) => {
  try { const x = new URL(a); return x.origin === b.origin && x.pathname.replace(/\/$/, "") === b.pathname.replace(/\/$/, ""); } catch { return false; }
};
const secureUrl = (v: unknown) => { try { const u = new URL(String(v)); return u.protocol === "https:" || isLocal(u); } catch { return false; } };

export const authAnalysers: Record<string, Analyser> = {
  "auth-https": (ctx) => {
    const u = serverUrl(ctx);
    if (!u) return skippedNotHttp;
    if (u.protocol === "https:") return { status: "pass", message: "Served over HTTPS." };
    if (isLocal(u)) return { status: "pass", message: "Plain HTTP on a local address (acceptable for development only)." };
    return { status: "fail", message: `Served over plain HTTP at ${sanitizeText(u.host, 80)}: tokens and data can be read or altered in transit.` };
  },

  "auth-unauthenticated": (ctx) => {
    if (!serverUrl(ctx)) return skippedNotHttp;
    const p = ctx.http?.unauthenticated;
    if (!p || p.status === null) return { status: "inconclusive", message: `No answer without credentials${p?.error ? `: ${sanitizeText(p.error, 120)}` : ""}.` };
    if (p.status === 401) return { status: "info", message: "Requires sign-in: unauthenticated requests are refused with 401." };
    if (p.status >= 200 && p.status < 300) return { status: "info", message: "Accepts calls without sign-in. Fine for public, read-only servers; add OAuth before exposing user data or actions." };
    return { status: "info", message: `Answered an unauthenticated request with HTTP ${p.status}.` };
  },

  "auth-www-authenticate": (ctx) => {
    if (!serverUrl(ctx)) return skippedNotHttp;
    if (!requiresAuth(ctx)) return skippedNoAuth;
    const header = ctx.http?.unauthenticated?.headers["www-authenticate"];
    if (!header) return { status: "fail", message: "Refused with 401 but sent no WWW-Authenticate header, so clients cannot discover how to sign in." };
    const c = parseChallenge(header);
    if ((c.scheme ?? "").toLowerCase() !== "bearer") return { status: "fail", message: `The challenge uses scheme "${sanitizeText(c.scheme, 30)}"; MCP clients expect Bearer.`, evidence: { excerpt: sanitizeText(header, 200) } };
    if (!c.params["resource_metadata"]) return { status: "fail", message: "The Bearer challenge has no resource_metadata parameter (RFC 9728 section 5.1), so clients must guess where sign-in is described.", evidence: { excerpt: sanitizeText(header, 200) } };
    return { status: "pass", message: "Refuses unauthenticated calls with a Bearer challenge that points to its resource metadata." };
  },

  "auth-resource-metadata": async (ctx) => {
    const u = serverUrl(ctx);
    if (!u) return skippedNotHttp;
    if (!requiresAuth(ctx)) return skippedNoAuth;
    const prm = await loadResourceMetadata(ctx);
    if (!prm.doc) return { status: "fail", message: `No protected resource metadata found (${prm.error}).` };
    const problems: string[] = [];
    const resource = prm.doc["resource"];
    if (typeof resource !== "string") problems.push("missing \"resource\"");
    else if (!sameResource(resource, u)) problems.push(`"resource" (${sanitizeText(resource, 80)}) does not identify this server`);
    const servers = prm.doc["authorization_servers"];
    if (!Array.isArray(servers) || servers.length === 0) problems.push("no \"authorization_servers\" listed");
    else if (!servers.every(secureUrl)) problems.push("an authorization server URL is not HTTPS");
    return problems.length
      ? { status: "fail", message: `Protected resource metadata at ${sanitizeText(prm.url, 120)} has problems: ${problems.join("; ")}.` }
      : { status: "pass", message: `Protected resource metadata found at ${sanitizeText(prm.url, 120)}, naming this server and its authorization server.` };
  },

  "auth-server-metadata": async (ctx) => {
    if (!serverUrl(ctx)) return skippedNotHttp;
    if (!requiresAuth(ctx)) return skippedNoAuth;
    const as = await loadServerMetadata(ctx);
    if (!as.doc) return { status: "fail", message: `Authorization server metadata not found (${as.error}).` };
    const d = as.doc;
    const problems: string[] = [];
    for (const f of ["issuer", "authorization_endpoint", "token_endpoint"]) if (typeof d[f] !== "string") problems.push(`missing "${f}"`);
    for (const f of ["authorization_endpoint", "token_endpoint"]) if (typeof d[f] === "string" && !secureUrl(d[f])) problems.push(`"${f}" is not HTTPS`);
    const rts = d["response_types_supported"];
    if (Array.isArray(rts) && !rts.includes("code")) problems.push("authorization code flow not supported");
    const pkce = d["code_challenge_methods_supported"];
    if (!Array.isArray(pkce) || !pkce.includes("S256")) problems.push("PKCE with S256 not advertised (MCP requires PKCE)");
    return problems.length
      ? { status: "fail", message: `Authorization server metadata at ${sanitizeText(as.url, 120)} has problems: ${problems.join("; ")}.` }
      : { status: "pass", message: `Authorization server metadata is complete, with PKCE (S256) advertised.` };
  },

  "auth-invalid-token": (ctx) => {
    if (!serverUrl(ctx)) return skippedNotHttp;
    if (!requiresAuth(ctx)) return skippedNoAuth;
    const p = ctx.http?.invalidToken;
    if (!p || p.status === null) return { status: "inconclusive", message: "No answer to a request with an invalid token." };
    if (p.status === 401 || p.status === 403) return { status: "pass", message: `Rejects an invalid bearer token with HTTP ${p.status}.` };
    if (p.status >= 200 && p.status < 300) return { status: "fail", message: "Accepted a request carrying an invalid bearer token: anyone can call this server." };
    return { status: "fail", message: `Answered an invalid token with HTTP ${p.status} instead of 401 (RFC 6750); server errors on bad tokens can hide validation bugs.` };
  }
};

export const AUTH_NEEDS = Object.fromEntries(Object.keys(authAnalysers).map((k) => [k, "none" as const]));
