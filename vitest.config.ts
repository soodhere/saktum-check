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
  test: { include: ["test/**/*.test.ts"], testTimeout: 30000, hookTimeout: 30000 }
});
