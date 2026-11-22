import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as Ajv2020Module from "ajv/dist/2020.js";
import * as Ajv2019Module from "ajv/dist/2019.js";
import * as AjvDraft7Module from "ajv";
import * as addFormatsModule from "ajv-formats";
import type { ValidateFunction } from "ajv";
import { EMBEDDED_CONTRACTS } from "./embedded.js";

// Interop for CommonJS default exports under NodeNext.
type AjvLike = { addSchema(s: object, k: string): void; getSchema(k: string): ValidateFunction | undefined; compile(s: object): ValidateFunction };
type AjvCtor = new (o: Record<string, unknown>) => AjvLike;
const pick = (m: unknown): unknown => { let x = m as { default?: unknown }; while (x && typeof x !== "function" && x.default) x = x.default as { default?: unknown }; return x; };
const Ajv2020 = pick(Ajv2020Module) as AjvCtor;
const Ajv2019 = pick(Ajv2019Module) as AjvCtor;
const AjvDraft7 = pick(AjvDraft7Module) as AjvCtor;
const addFormats = pick(addFormatsModule) as (a: AjvLike) => void;

export const contractsDir = fileURLToPath(new URL("../../../contracts/", import.meta.url));
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
/** Contracts come from the repository when present, otherwise from the embedded copy (single-file bundle). */
export function contractText(f: string): string {
  if (existsSync(contractsDir + f)) return readFileSync(contractsDir + f, "utf8");
  const t = EMBEDDED_CONTRACTS[f];
  if (!t) throw new Error(`contract ${f} not found`);
  return t;
}
for (const f of ["envelope.schema.json", "receipt.schema.json", "pack.schema.json", "result.schema.json", "test-cases.schema.json"]) {
  ajv.addSchema(JSON.parse(contractText(f)), f);
}

export function compileContract(file: string): ValidateFunction {
  const v = ajv.getSchema(file);
  if (!v) throw new Error(`unknown contract ${file}`);
  return v;
}

/** The JSON Schema dialect a schema declares. MCP does not mandate one; generators commonly emit draft-07. */
export function schemaDialect(schema: unknown): "draft-04" | "draft-06" | "draft-07" | "2019-09" | "2020-12" | "unknown" {
  const id = schema && typeof schema === "object" ? (schema as { $schema?: unknown }).$schema : undefined;
  if (id === undefined) return "2020-12";
  const s = String(id);
  if (/draft-04/.test(s)) return "draft-04";
  if (/draft-06/.test(s)) return "draft-06";
  if (/draft-07/.test(s)) return "draft-07";
  if (/2019-09/.test(s)) return "2019-09";
  if (/2020-12/.test(s)) return "2020-12";
  return "unknown";
}

/** A separate validator for JSON Schemas supplied by tested servers (untrusted), chosen by the declared dialect.
 *  The $schema keyword is removed before compiling, so a dialect URI never triggers a remote fetch or a lookup error. */
export function compileUntrustedSchema(schema: unknown): { ok: true } | { ok: false; error: string } {
  try {
    if (!schema || typeof schema !== "object" || Array.isArray(schema)) return { ok: false, error: "the schema is not a JSON object" };
    const dialect = schemaDialect(schema);
    if (dialect === "unknown") return { ok: false, error: `unrecognised $schema dialect ${JSON.stringify((schema as { $schema?: unknown }).$schema).slice(0, 80)}` };
    const { $schema: _ignored, ...body } = schema as Record<string, unknown>;
    const Ctor = dialect === "2020-12" ? Ajv2020 : dialect === "2019-09" ? Ajv2019 : AjvDraft7;
    new Ctor({ strict: false, allErrors: false, validateSchema: true, logger: false }).compile(body);
    return { ok: true };
  } catch (e) { return { ok: false, error: (e as Error).message }; }
}

/** Compile an untrusted schema (dialect-aware, as above) and return a validator for data, with readable errors.
 *  Formats are checked where ajv-formats knows them; unknown keywords and formats are ignored, never fetched. */
export function compileUntrustedSchemaValidator(schema: unknown):
  | { ok: true; validate: (data: unknown) => boolean; errors: () => string }
  | { ok: false; error: string } {
  try {
    if (!schema || typeof schema !== "object" || Array.isArray(schema)) return { ok: false, error: "the schema is not a JSON object" };
    const dialect = schemaDialect(schema);
    if (dialect === "unknown") return { ok: false, error: "unrecognised $schema dialect" };
    const { $schema: _ignored, ...body } = schema as Record<string, unknown>;
    const Ctor = dialect === "2020-12" ? Ajv2020 : dialect === "2019-09" ? Ajv2019 : AjvDraft7;
    const ajv = new Ctor({ strict: false, allErrors: false, validateSchema: true, logger: false });
    const fn = ajv.compile(body);
    return { ok: true, validate: (d) => Boolean(fn(d)), errors: () => (fn.errors ?? []).map((e) => `${e.instancePath || "/"} ${e.message ?? ""}`).join("; ") };
  } catch (e) { return { ok: false, error: (e as Error).message }; }
}
