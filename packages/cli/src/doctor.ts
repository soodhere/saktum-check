// saktum doctor: explains why a server will not start or connect, before anyone files a bug.
// Field test lesson (Oct 2026): most "broken" servers were missing a runtime, credentials or network at start-up.
import { spawn, spawnSync } from "node:child_process";
import { connect, minimalEnv, parseTarget, probeInitialize, type Target } from "@saktum/transports";
import { sanitizeText } from "@saktum/testkit-core";

interface Line { ok: boolean | null; label: string; hint?: string }

/** Quote one argument for cmd.exe when it contains spaces or shell characters. */
export function quoteWin(a: string): string {
  return /^[\w.:\/\\@=+-]+$/.test(a) ? a : `"${a.replace(/"/g, '\\"')}"`;
}

/** How to start a command on Windows. Bare names such as npx or uvx resolve to .cmd shims, which Node starts only through
 *  a shell (since the 2024 security fix), as do .cmd and .bat files. Full paths to programs run directly, so spaces in
 *  paths such as "C:\\Program Files" are never split by the shell. Elsewhere, commands always run directly. */
export function spawnPlan(command: string, args: string[], platform: string = process.platform): { command: string; args: string[]; shell: boolean } {
  if (platform !== "win32") return { command, args, shell: false };
  const bare = !/[\\/]/.test(command) && !/\.(exe|com)$/i.test(command);
  const script = /\.(cmd|bat)$/i.test(command);
  if (!bare && !script) return { command, args, shell: false };
  return { command: quoteWin(command), args: args.map(quoteWin), shell: true };
}
const mark = (ok: boolean | null) => (ok === true ? "\u2713" : ok === false ? "\u2717" : "-");

function has(cmd: string, args = ["--version"]): string | undefined {
  const plan = spawnPlan(cmd, args);
  const r = spawnSync(plan.command, plan.args, { encoding: "utf8", timeout: 8000, shell: plan.shell, windowsHide: true });
  return r.status === 0 ? (r.stdout || r.stderr).trim().split("\n")[0] : undefined;
}

/** Hints from a local server's error output. */
export function hintsFrom(stderr: string): string[] {
  const h: string[] = [];
  if (/ENOENT|command not found|is not recognized/i.test(stderr)) h.push("The command was not found on PATH. Use the full path, or install the runtime it needs.");
  if (/api[_ -]?key|access[_ -]?token|credential|unauthori[sz]ed|missing.*(key|secret|token)|environment variable/i.test(stderr)) h.push("It looks like the server needs credentials at start-up. Pass them with --env NAME=VALUE (your own environment is never passed).");
  if (/ENOTFOUND|EAI_AGAIN|getaddrinfo|fetch failed|network/i.test(stderr)) h.push("It looks like the server needs network access at start-up.");
  if (/Cannot find module|ModuleNotFoundError|No module named/i.test(stderr)) h.push("A dependency is missing. Install the server's dependencies, or run it through npx or uvx.");
  if (/EADDRINUSE/i.test(stderr)) h.push("A port it wants is already in use.");
  if (/ECONNREFUSED|connection refused|could not connect to (the )?(server|database)|Redis|postgres|mongo/i.test(stderr) && !h.length) h.push("It looks like a service the server depends on (for example a database) is not running at the address it was given.");
  if (/Traceback \(most recent call last\)|AttributeError|TypeError:|ReferenceError:|SyntaxError:/.test(stderr)) h.push("The server crashed with an error in its own code: probably a bug or an incompatible version. Try another version, or report it to its maintainers.");
  return h;
}

/** The most useful line of error output: the last line that reads like an error, otherwise the last line with words. */
export function keyLine(stderr: string): string {
  const lines = stderr.split("\n").map((l) => l.trim()).filter((l) => /[a-z]{3}/i.test(l));
  return [...lines].reverse().find((l) => /error|exception|failed|not found|missing|denied|refused|invalid|cannot|unable/i.test(l)) ?? lines[lines.length - 1] ?? "";
}

async function startProbe(t: Extract<Target, { kind: "stdio" }>): Promise<{ exited: boolean; code: number | null; stderr: string }> {
  return new Promise((resolve) => {
    let stderr = "";
    let done = false;
    const plan = spawnPlan(t.command, t.args);
    const child = spawn(plan.command, plan.args, { env: minimalEnv(t.env), cwd: t.cwd, stdio: ["pipe", "ignore", "pipe"], shell: plan.shell, windowsHide: true });
    const finish = (exited: boolean, code: number | null) => { if (done) return; done = true; clearTimeout(timer); if (!exited) child.kill(); resolve({ exited, code, stderr }); };
    child.stderr?.on("data", (d: Buffer) => { stderr = (stderr + d.toString()).slice(-4000); });
    child.on("error", (e) => { stderr += `\n${e.message}`; finish(true, null); });
    child.on("exit", (code) => finish(true, code));
    const timer = setTimeout(() => finish(false, null), 4000);
  });
}

export async function runDoctor(targetParts: string[], env: string[] = [], headers: string[] = []): Promise<{ text: string; code: number }> {
  const lines: Line[] = [];
  const nodeMajor = Number(process.versions.node.split(".")[0]);
  lines.push({ ok: nodeMajor >= 20, label: `Node.js ${process.versions.node}`, hint: nodeMajor >= 20 ? undefined : "Saktum Check needs Node.js 20 or later." });
  lines.push({ ok: null, label: `Platform ${process.platform} ${process.arch}` });
  if (process.env["NVM_DIR"]) lines.push({ ok: null, label: "nvm detected", hint: "Desktop clients may not see nvm's Node. In client configuration, use the absolute path to node." });
  const npx = has("npx");
  lines.push({ ok: npx ? true : null, label: npx ? `npx ${npx}` : "npx not found", hint: npx ? undefined : "Needed only for servers started with npx." });
  const uvx = has("uvx");
  lines.push({ ok: uvx ? true : null, label: uvx ? `uvx ${uvx}` : "uvx not found", hint: uvx ? undefined : "Needed only for Python servers started with uvx." });

  if (targetParts.length) {
    const target = parseTarget(targetParts);
    if (target.kind === "stdio") {
      if (env.length) target.env = Object.fromEntries(env.map((kv) => { const i = kv.indexOf("="); return [kv.slice(0, i), kv.slice(i + 1)]; }));
      const p = await startProbe(target);
      if (p.exited) {
        lines.push({ ok: false, label: `The server exited during start-up${p.code !== null ? ` (code ${p.code})` : ""}`, hint: [...hintsFrom(p.stderr), keyLine(p.stderr) ? `Server said: ${sanitizeText(keyLine(p.stderr), 240)}` : ""].filter(Boolean).join(" ") || undefined });
      } else lines.push({ ok: true, label: "The server starts and stays up" });
    } else {
      if (headers.length) target.headers = Object.fromEntries(headers.map((h) => { const i = h.indexOf(":"); return [h.slice(0, i).trim(), h.slice(i + 1).trim()]; }));
      const p = await probeInitialize(target.url, target.headers);
      if (p.status === null) lines.push({ ok: false, label: `Cannot reach ${sanitizeText(target.url, 100)}`, hint: `${sanitizeText(p.error, 160)}. Check the URL, DNS, TLS certificate and any proxy.` });
      else if (p.status === 401) lines.push({ ok: null, label: "Reachable; requires sign-in (401)", hint: "Sign-in checks will run. To test the tools, add --header \"Authorization: Bearer <token>\"." });
      else lines.push({ ok: p.status < 400, label: `Reachable; answered HTTP ${p.status} in ${p.ms} ms` });
    }
    const canHandshake = !lines.some((l) => l.ok === false);
    if (canHandshake) {
      try {
        const s = await connect(target);
        const tools = await s.listTools().catch(() => []);
        lines.push({ ok: true, label: `MCP handshake OK (protocol ${sanitizeText(s.protocolVersion, 20)}, ${tools.length} tools)` });
        await s.close();
      } catch (e) {
        const msg = (e as Error).message;
        const timeout = /timed out/i.test(msg);
        lines.push({ ok: /401/.test(msg) ? null : false, label: /401/.test(msg) ? "MCP handshake needs sign-in" : "MCP handshake failed",
          hint: /401/.test(msg) ? undefined : /Connection closed/i.test(msg)
            ? "The server closed the connection during the handshake: it probably exited because something it needs is missing (credentials, a running service such as a database, or network). Run it directly in a terminal to see its error output."
            : timeout
            ? "The server started but did not answer the handshake. If it is launched with npx or uvx, the first run downloads it: check your network, proxy (HTTPS_PROXY) and certificates (NODE_EXTRA_CA_CERTS), then try again. Otherwise the server may write logs to standard output, which breaks the protocol."
            : sanitizeText(msg, 200) });
      }
    }
  }

  const text = lines.map((l) => `${mark(l.ok)} ${l.label}${l.hint ? `\n    ${l.hint}` : ""}`).join("\n");
  const failed = lines.some((l) => l.ok === false);
  return { text: `Saktum doctor\n${text}\n\n${failed ? "Fix the items marked \u2717, then run saktum check." : "Ready: run saktum check with the same target."}`, code: failed ? 1 : 0 };
}
