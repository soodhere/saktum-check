# Contributing

1. Every new check needs a passing fixture and a failing fixture before it merges (see `test/packs.test.ts`).
2. Packs are data, not code. If a check needs logic, add a named analyser in `packages/testkit-core/src/analysers.ts`, versioned with the engine.
3. No raw server text reaches a terminal or report without `sanitizeText` or `escapeHtml`.
4. Run `pnpm typecheck && pnpm test` before opening a pull request.
5. Contributions are under the Apache License 2.0; a contributor licence agreement will be required before the first public release.

## Ways to contribute (most valuable first)

1. **Report a false positive** (issue template "Something looked wrong"). Every one we fix makes the tool more trustworthy.
2. **Add a test vector:** a small fixture server in `fixtures/src/` that captures a real-world problem, plus the verdicts it
   should produce (regenerate `test-vectors/expected.json`). See `test-vectors/README.md`.
3. **Add a check:** checks are data in `packs/*.yaml` (with `normative` references to the specification clause or OWASP
   item they test) plus an analyser. Every scored check needs a fixture it passes on and a fixture it fails on; the test
   suite enforces this.
4. **Share test cases for your own server** (`saktum.tests.yaml`, see `docs/TESTS.md`) as examples for others.

Rules for checks: deterministic (models may advise, never decide), conservative (no finding without clear evidence),
explained in plain words with a fix, and traced to a standard where one exists.
