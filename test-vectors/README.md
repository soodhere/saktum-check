# MCP test vectors

Known-good and known-bad MCP servers (`fixtures/src/`) with the verdict expected for every check
(`expected.json`). Like web-platform-tests or the OpenID conformance suites, they give the MCP community a shared,
neutral definition of what each check should conclude, so any testing tool (not only Saktum Check) can validate itself.

| Fixture | What it represents |
| --- | --- |
| `good.ts` | A well-behaved server: valid schemas, annotations, structured output matching its `outputSchema`, graceful errors |
| `broken.ts` | Common mistakes: invalid schemas and names, success for unknown tools, no annotations or descriptions |
| `malicious.ts` | Tool poisoning: hidden instructions, invisible and bidirectional characters, terminal escape sequences |
| `leaky.ts` | A hard-coded key in a schema default; stack traces and source paths in errors |
| `faulty.ts` | Tools that break their own `outputSchema`, reject valid arguments, and crash on invalid ones |
| `empty.ts` | A server that lists no tools |
| `oauth.ts` | Remote sign-in done right (`--mode good`) and wrong (`--mode broken`) |

Run a fixture: `node --import tsx fixtures/src/good.ts` (stdio) or `node --import tsx fixtures/src/oauth.ts --mode good --http 0`.
Regenerate the expected verdicts after changing packs or fixtures: `pnpm build && node --import tsx scripts/test-vectors.mjs`.

**Contributions welcome:** a new fixture that captures a real-world problem (with the verdicts it should produce) is one
of the most useful things you can add. See [CONTRIBUTING.md](../CONTRIBUTING.md).
