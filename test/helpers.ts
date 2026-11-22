import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import type { Target } from "@saktum/transports";

export const root = fileURLToPath(new URL("../", import.meta.url));
export type FixtureName = "good" | "broken" | "malicious" | "leaky" | "empty" | "faulty" | "raw-init" | "raw-list";
export const fixture = (name: FixtureName): Target => name.startsWith("raw-")
  ? { kind: "stdio", command: process.execPath, args: ["--import", "tsx", "fixtures/src/raw-protocol.ts", "--mode", name.slice(4)], cwd: root }
  : { kind: "stdio", command: process.execPath, args: ["--import", "tsx", `fixtures/src/${name}.ts`], cwd: root };

/** Start a fixture over Streamable HTTP on a free port; returns its URL and a stop function. */
export function startHttpFixture(name: "good" | "broken" | "malicious" | "oauth-good" | "oauth-broken"): Promise<{ url: string; stop: () => void }> {
  return new Promise((resolve, reject) => {
    const args = name.startsWith("oauth-") ? ["fixtures/src/oauth.ts", "--mode", name.slice(6)] : [`fixtures/src/${name}.ts`];
    const p = spawn(process.execPath, ["--import", "tsx", ...args, "--http", "0"], { cwd: root, stdio: ["ignore", "pipe", "inherit"] });
    p.stdout.on("data", (d: Buffer) => { const m = d.toString().match(/listening (\d+)/); if (m) resolve({ url: `http://127.0.0.1:${m[1]}/mcp`, stop: () => p.kill() }); });
    p.on("error", reject);
    setTimeout(() => reject(new Error("fixture did not start")), 15000);
  });
}
