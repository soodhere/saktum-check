# Writing test cases for your MCP server

Saktum Check runs generic checks on any server. Test cases add what only you know: **what your tools should actually
return.** Put them in `saktum.tests.yaml` and run them on every change, locally and in CI.

```
npx saktum test -- node ./build/index.js            # runs saktum.tests.yaml plus every check
npx saktum check --tests my.tests.yaml https://your-server.example/mcp
```

## Format

```yaml
testsFormat: "0.1"
tests:
  - id: forecast-toronto            # unique name, shown in reports
    tool: get_forecast              # the tool to call
    input: { city: Toronto }        # arguments
    expect:
      isError: false                # success expected (true: an error result is expected)
      textContains: "Toronto"       # the text content must contain this
      structured: { city: Toronto } # structuredContent must contain these values (extra fields are fine)
      outputSchema: true            # structuredContent must match the tool's declared outputSchema
      latencyMs: { lt: 2000 }       # must answer in under 2 seconds

  - id: forecast-needs-city         # test your error handling too
    tool: get_forecast
    input: {}
    expect: { isError: true, textContains: "city is required" }

  - id: save-note                   # tests that change data
    tool: save_note
    input: { text: "hello" }
    sideEffects: true               # runs only with --active (against a server you own)
    expect: { isError: false }
```

The file is validated against `contracts/test-cases.schema.json`; a mistake is reported before anything runs.

## Good test cases

- **One happy path per tool,** with realistic input, checking the parts of the result agents rely on (`structured` or `textContains`).
- **One error path per tool:** missing or invalid arguments should give a short, helpful error.
- **The risky paths:** anything that deletes, pays or sends, marked `sideEffects: true` and run against a staging server.
- **A latency budget** for tools on interactive paths.

## Generic functional checks (no test file needed)

With `--active`, Saktum also calls your **read-only** tools (annotated `readOnlyHint: true`) with arguments generated from
their input schemas, checks that results are well-formed and match any declared `outputSchema`, sends invalid arguments to
check they are rejected gracefully, and confirms the server keeps working. Name other tools with `--call <tool>` to include
them. Destructive tools are never called automatically. An error *result* on generated arguments (for example because a
tool needs real data or credentials) is not counted as a failure; test cases with real inputs give you the full picture.
