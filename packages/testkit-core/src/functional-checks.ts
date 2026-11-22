// Analysers for the functional pack. They read the functional report the engine built (active runs only) and judge
// conservatively: an error *result* on generated arguments is not a failure (the tool may need credentials or real
// data); only refusing valid arguments, timing out, crashing or returning malformed or schema-violating data is.
import type { Analyser } from "./analysers.js";
import { sanitizeText } from "./safe.js";

const notEligible = { status: "skipped" as const, message: "No tools were eligible to call: annotate read-only tools (readOnlyHint), name tools with --call, or add test cases." };
const describe = (xs: { tool: string; problems: string[] }[]) => xs.slice(0, 3).map((x) => `${sanitizeText(x.tool, 50)}: ${x.problems.join("; ")}`).join(" \u00b7 ");

export const functionalAnalysers: Record<string, Analyser> = {
  "func-respond": ({ functional }) => {
    if (!functional?.ran) return { status: "skipped", message: functional?.reason ?? "Functional calls did not run." };
    const smoke = functional.calls.filter((c) => c.purpose === "smoke");
    if (!smoke.length) return notEligible;
    const bad = smoke.filter((c) => c.outcome.kind === "timeout" || c.outcome.kind === "transport-error" || (c.outcome.kind === "protocol-error" && c.outcome.code === -32602));
    if (bad.length) return { status: "fail", subject: "tools", message: `${bad.length} of ${smoke.length} tool(s) failed with valid arguments: ${describe(bad.map((b) => ({ tool: b.tool, problems: b.problems.length ? b.problems : [b.outcome.kind] })))}.` };
    const errored = smoke.filter((c) => c.outcome.kind !== "result" || c.outcome.isError).length;
    return { status: "pass", message: `${smoke.length} tool(s) called with arguments generated from their schemas${errored ? ` (${errored} answered with an error result, for example because they need credentials or real data; that is not counted as a failure)` : ""}.` };
  },
  "func-output": ({ functional }) => {
    if (!functional?.ran) return { status: "skipped", message: functional?.reason ?? "Functional calls did not run." };
    const ok = functional.calls.filter((c) => c.purpose === "smoke" && c.outcome.kind === "result" && !c.outcome.isError);
    if (!ok.length) return { status: "skipped", message: "No call returned a successful result to validate (tools may need credentials or real data; add test cases with real inputs)." };
    const bad = ok.map((c) => ({ tool: c.tool, problems: c.problems })).filter((c) => c.problems.length);
    return bad.length ? { status: "fail", subject: "tools", message: `${bad.length} of ${ok.length} successful result(s) are malformed or break their declared output schema: ${describe(bad)}.` }
      : { status: "pass", message: `${ok.length} successful result(s) are well-formed and match any declared output schema.` };
  },
  "func-invalid": ({ functional }) => {
    if (!functional?.ran) return { status: "skipped", message: functional?.reason ?? "Functional calls did not run." };
    const probes = functional.calls.filter((c) => c.purpose === "invalid-args");
    if (!probes.length) return notEligible;
    const bad = probes.filter((c) => c.problems.length);
    return bad.length ? { status: "fail", subject: "tools", message: `${bad.length} of ${probes.length} tool(s) handled invalid arguments badly: ${describe(bad)}.` }
      : { status: "pass", message: `${probes.length} tool(s) rejected invalid arguments gracefully.` };
  },
  "func-survives": ({ functional }) => {
    if (!functional?.ran) return { status: "skipped", message: functional?.reason ?? "Functional calls did not run." };
    if (functional.survived === undefined) return notEligible;
    return functional.survived ? { status: "pass", message: "The server kept responding after all functional calls." }
      : { status: "fail", message: "The server stopped responding after the functional calls." };
  }
};

export const FUNCTIONAL_NEEDS = { "func-respond": "session" as const, "func-output": "session" as const, "func-invalid": "session" as const, "func-survives": "session" as const };
