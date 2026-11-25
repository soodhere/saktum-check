import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
const p = (s: string) => fileURLToPath(new URL(s, import.meta.url));
export default defineConfig({
  resolve: {
    alias: {
      "@saktum/sign": p("./packages/sign/src/index.ts"),
      "@saktum/transports": p("./packages/transports/src/index.ts"),
      "@saktum/testkit-core": p("./packages/testkit-core/src/index.ts"),
      "@saktum/report": p("./packages/report/src/index.ts")
    }
  },
  // Many tests start real server processes. Windows starts processes slowly (antivirus scans each one), so run fewer
  // test files at once there and allow more time; CI and other systems keep full parallelism.
  test: { include: ["test/**/*.test.ts"], testTimeout: process.platform === "win32" ? 60000 : 30000, hookTimeout: process.platform === "win32" ? 60000 : 30000,
    ...(process.platform === "win32" ? { maxWorkers: 2, minWorkers: 1 } : {}) }
});
