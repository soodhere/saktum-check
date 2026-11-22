import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { canonicalize, sha256Tag, verifyDocument } from "@saktum/sign";
import { compileContract } from "./contracts.js";
import { EMBEDDED_PACKS } from "./embedded.js";
import type { LoadedPack, Pack } from "./types.js";

const validatePack = compileContract("pack.schema.json");

export class PackError extends Error {}

/** Load one pack (YAML or JSON), validate it against the pack contract, hash it, and verify its signature if present or required. */
export function loadPack(path: string, opts: { requireSignature?: boolean; trustedKids?: string[] } = {}): LoadedPack {
  return loadPackText(readFileSync(path, "utf8"), path, opts);
}

/** Load a pack from text (used for embedded packs in the single-file bundle). */
export function loadPackText(text: string, path: string, opts: { requireSignature?: boolean; trustedKids?: string[] } = {}): LoadedPack {
  const data = (path.endsWith(".json") ? JSON.parse(text) : parseYaml(text)) as Pack;
  if (!validatePack(data)) throw new PackError(`${path}: invalid pack: ${JSON.stringify(validatePack.errors?.slice(0, 3))}`);
  let signedBy: string | undefined;
  if (data.signature || opts.requireSignature) {
    const v = verifyDocument(data as Pack & { signature?: Pack["signature"] });
    if (!v.valid) throw new PackError(`${path}: pack signature invalid (${v.reason})`);
    if (opts.trustedKids && !opts.trustedKids.includes(v.kid!)) throw new PackError(`${path}: pack signed by an untrusted key`);
    signedBy = v.kid;
  }
  const { signature: _s, ...body } = data;
  const ids = new Set<string>();
  for (const c of data.checks) { if (ids.has(c.id)) throw new PackError(`${path}: duplicate check id ${c.id}`); ids.add(c.id); }
  return { pack: data, hash: sha256Tag(canonicalize(body)), signedBy };
}

export function loadPackDir(dir: string, opts?: Parameters<typeof loadPack>[1]): LoadedPack[] {
  return readdirSync(dir).filter((f) => /\.(ya?ml|json)$/.test(f)).sort().map((f) => loadPack(join(dir, f), opts));
}

/** The packs embedded at build time (identical to packs/; a test enforces it). */
export function loadEmbeddedPacks(opts?: Parameters<typeof loadPack>[1]): LoadedPack[] {
  return Object.keys(EMBEDDED_PACKS).sort().map((f) => loadPackText(EMBEDDED_PACKS[f]!, `embedded:${f}`, opts));
}
