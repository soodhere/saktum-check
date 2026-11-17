# Contributing

1. Every new check needs a passing fixture and a failing fixture before it merges (see `test/packs.test.ts`).
2. Packs are data, not code. If a check needs logic, add a named analyser in `packages/testkit-core/src/analysers.ts`, versioned with the engine.
3. No raw server text reaches a terminal or report without `sanitizeText` or `escapeHtml`.
4. Run `pnpm typecheck && pnpm test` before opening a pull request.
5. Contributions are under the Apache License 2.0; a contributor licence agreement will be required before the first public release.
