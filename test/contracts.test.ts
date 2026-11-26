import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { compileContract, contractsDir, loadPackDir } from "@saktum/testkit-core";
import { root } from "./helpers.js";

describe("contracts", () => {
  it("every contract compiles and every example validates", () => {
    const pairs: [string, string][] = [["pack.example.json", "pack.schema.json"], ["test-cases.example.json", "test-cases.schema.json"], ["envelope.example.json", "envelope.schema.json"], ["policy.example.json", "policy.schema.json"], ["mandate.example.json", "mandate.schema.json"]];
    for (const [ex, schema] of pairs) {
      const v = compileContract(schema);
      const ok = v(JSON.parse(readFileSync(contractsDir + "examples/" + ex, "utf8")));
      expect(ok, `${ex}: ${JSON.stringify(v.errors)}`).toBe(true);
    }
    expect(readdirSync(contractsDir).filter((f) => f.endsWith(".schema.json")).length).toBe(11);
  });
  it("all bundled packs validate against the pack contract", () => {
    const packs = loadPackDir(root + "packs");
    expect(packs.map((p) => p.pack.id).sort()).toEqual(["agent-experience", "auth", "conformance", "functional", "performance", "security"]);
    for (const p of packs) expect(p.hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

import { compileUntrustedSchema, schemaDialect } from "@saktum/testkit-core";
describe("untrusted tool schemas", () => {
  it("accept draft-07, 2019-09 and 2020-12 schemas, which MCP servers commonly use", () => {
    expect(compileUntrustedSchema({ $schema: "http://json-schema.org/draft-07/schema#", type: "object", properties: { a: { type: "string" } }, definitions: { x: { type: "number" } } })).toEqual({ ok: true });
    expect(compileUntrustedSchema({ $schema: "https://json-schema.org/draft/2019-09/schema", type: "object" })).toEqual({ ok: true });
    expect(compileUntrustedSchema({ type: "object", properties: {} })).toEqual({ ok: true });
    expect(schemaDialect({ $schema: "http://json-schema.org/draft-07/schema#" })).toBe("draft-07");
  });
  it("still reject schemas that are genuinely invalid", () => {
    expect(compileUntrustedSchema({ type: "object", properties: { a: { type: "strin" } } }).ok).toBe(false);
    expect(compileUntrustedSchema("not a schema").ok).toBe(false);
    expect(compileUntrustedSchema({ $schema: "https://example.com/made-up", type: "object" }).ok).toBe(false);
  });
});
