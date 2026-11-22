import { describe, expect, it } from "vitest";
import { escapeHtml, maxDepth, sanitizeText } from "@saktum/testkit-core";

describe("untrusted text", () => {
  it("strips terminal escape sequences and control characters", () => {
    const evil = "ok\u001b[2J\u001b[H\u001b[1;32mALL CHECKS PASSED\u001b[0m\u001b]0;pwned\u0007\u0007\u0008";
    const out = sanitizeText(evil);
    expect(out).toBe("okALL CHECKS PASSED");
    expect(out).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/);
  });
  it("reveals invisible and bidirectional characters instead of hiding them", () => {
    expect(sanitizeText("a\u200bb\u202ec")).toBe("a<U+200B>b<U+202E>c");
  });
  it("caps length", () => { expect(sanitizeText("x".repeat(1000), 10)).toHaveLength(10); });
  it("escapes HTML", () => { expect(escapeHtml(`<img src=x onerror="alert(1)">`)).toBe("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;"); });
  it("rejects absurdly nested values", () => {
    let v: unknown = 1; for (let i = 0; i < 100; i++) v = [v];
    expect(() => maxDepth(v, 64)).toThrow();
  });
});

import { minimalEnv } from "@saktum/transports";
describe("minimal environment for local servers", () => {
  it("passes network plumbing but never credentials", () => {
    const saved = { ...process.env };
    Object.assign(process.env, { HTTPS_PROXY: "http://proxy:8080", NODE_EXTRA_CA_CERTS: "/certs.pem", NPM_CONFIG_REGISTRY: "https://r.example", NPM_CONFIG__AUTHTOKEN: "s3cr3t", GITHUB_TOKEN: "ghp_x", OPENAI_API_KEY: "sk-x", MY_SECRET: "x" });
    const env = minimalEnv({ EXPLICIT: "1" });
    process.env = saved;
    expect(env["HTTPS_PROXY"]).toBe("http://proxy:8080");
    expect(env["NODE_EXTRA_CA_CERTS"]).toBe("/certs.pem");
    expect(env["NPM_CONFIG_REGISTRY"]).toBe("https://r.example");
    for (const k of ["NPM_CONFIG__AUTHTOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY", "MY_SECRET"]) expect(env[k], k).toBeUndefined();
    expect(env["EXPLICIT"]).toBe("1");
  });
});
