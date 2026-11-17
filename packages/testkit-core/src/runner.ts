import type { CallOutcome } from "@saktum/transports";
import { LimitError } from "@saktum/transports";
import { analysers, needsOf, type AnalyserContext, type Verdict } from "./analysers.js";
import { sanitizeText } from "./safe.js";
import type { Check, Expectation, Step } from "./types.js";

function getPath(value: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((v, k) => (v && typeof v === "object" ? (v as Record<string, unknown>)[k] : undefined), value);
}

function meets(value: unknown, e: Expectation): boolean {
  const call = value as CallOutcome | undefined;
  if (e.anyOf) return e.anyOf.some((x) => meets(value, x));
  if (e.exists && !e.exists.every((p) => getPath(value, p) !== undefined)) return false;
  if (e.isError !== undefined && !(call?.kind === "result" && call.isError === e.isError)) return false;
  if (e.errorCodeIn && !(call?.kind === "protocol-error" && e.errorCodeIn.includes(call.code))) return false;
  if (e.failed && !(call?.kind === "protocol-error" || (call?.kind === "result" && call.isError))) return false;
  return true;
}

function describe(value: unknown): string {
  const c = value as CallOutcome;
  if (c && typeof c === "object" && "kind" in c) {
    if (c.kind === "result") return c.isError ? "a tool result flagged as an error" : "a successful result";
    if (c.kind === "protocol-error") return `protocol error ${c.code}`;
    return c.kind;
  }
  return "the response";
}

/** Run one check's steps in order. The first failing step decides the verdict; network problems give "inconclusive", never "fail". */
export const SIGN_IN_HINT = "Not run: the server requires sign-in. Re-run with --header \"Authorization: Bearer <token>\" to test it.";

/** Whether a check can run without an MCP session (sign-in checks can). */
export function checkNeedsSession(check: Check): boolean {
  return check.steps.some((s) => s.action !== "analyse" || needsOf(s.analyser ?? "") !== "none");
}

export async function runCheck(check: Check, ctx: AnalyserContext): Promise<Verdict> {
  let last: Verdict = { status: "pass", message: "All steps passed." };
  if (!ctx.session && checkNeedsSession(check)) return { status: "inconclusive", message: SIGN_IN_HINT };
  for (const step of check.steps as Step[]) {
    try {
      const session = ctx.session!;
      let value: unknown;
      switch (step.action) {
        case "mcp.initialize": value = { serverInfo: session.serverInfo, capabilities: session.capabilities, protocolVersion: session.protocolVersion }; break;
        case "mcp.listTools": value = { tools: ctx.tools }; break;
        case "mcp.callTool": {
          value = await session.callTool(step.tool ?? "", step.arguments ?? {});
          const k = (value as CallOutcome).kind;
          if (k === "timeout" || k === "transport-error") return { status: "inconclusive", message: `The call ended with ${k}; retry later.` };
          break;
        }
        case "analyse": {
          const fn = step.analyser ? analysers[step.analyser] : undefined;
          if (!fn) return { status: "inconclusive", message: `Unknown analyser "${step.analyser}" for this engine version.` };
          last = await fn(ctx);
          if (last.status === "fail" || last.status === "skipped") return last;
          continue;
        }
      }
      if (step.expect && !meets(value, step.expect)) return { status: "fail", message: `Got ${describe(value)}, which does not meet the expectation.` };
    } catch (e) {
      if (e instanceof LimitError) return { status: "inconclusive", message: sanitizeText(e.message) };
      return { status: "inconclusive", message: `Step failed to run: ${sanitizeText((e as Error).message)}` };
    }
  }
  return last;
}
