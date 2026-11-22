# Saktum Check 0.1 validation on real servers (16 Nov 2026)

Run with the beta file (saktum.mjs) in passive mode against public MCP servers from npm and PyPI, with placeholder credentials where a server needs them to start. Internal document: individual results are not published (consent rule).

## Summary
- **Servers tried:** 37 (npm and Python). **Assessed:** 31. **Graded:** 30 (28 A, 2 B); 1 withheld (listed no tools without valid credentials).
- **Could not start in the test environment:** 6 (need a credentials file, a running database, a browser download, or network at start-up; doctor explains each).
- **Missing danger annotations:** 13 of 31. **Non-standard unknown-tool error codes:** 9. **Unknown tool reported as success:** 1. **Invalid input schemas:** 1. **Secrets or leaked internals:** 0 (no false positives after fixes).
- **Context cost of tool definitions:** 32 to 81,566 tokens per turn (median 1,910).

## Saktum bugs found and fixed by this validation (before any beta user saw them)
1. Valid draft-07 tool schemas were flagged as invalid on 6 of 10 servers, including reference servers. The validator now follows each schema's declared dialect.
2. Memory measured the npx launcher instead of the server. It is now summed over the whole process tree; CPU is reported as an average since start-up and never judged.
3. npx hung behind custom certificates and proxies. Network-plumbing variables are now passed; credentials never are.
4. A server's installed browser path was reported as leaked internals. Only application code paths now count.
5. A server whose tool list failed received a grade from two checks. Grades are now withheld when tools could not be examined, with the reason shown.
6. Doctor hints improved for credentials, missing services, crashes inside the server's own code, and closed connections.

## Results
| Server | Grade | Tools | Context tokens | Failed checks |
| --- | --- | --- | --- | --- |
| aws-kb-archived | A | 1 | 117 | ax.annotations |
| brave-archived | A | 2 | 362 | ax.annotations |
| browserbase | A | 9 | 1,334 | ax.annotations |
| context7 | A | 2 | 1,304 | none |
| desktop-cmd | A | 25 | 13,302 | none |
| elasticsearch | A | 4 | 445 | ax.annotations |
| everart-archived | A | 1 | 223 | ax.annotations, conf.tools.unknown-error-code |
| everything | A | 13 | 1,910 | none |
| exa | A | 2 | 534 | none |
| figma | A | 2 | 973 | none |
| filesystem | A | 14 | 3,275 | none |
| firecrawl | A | 28 | 22,831 | conf.tools.unknown-error-code |
| gdrive-archived | could not start here | - | - | see doctor |
| github-archived | A | 26 | 3,960 | ax.annotations, conf.tools.unknown-error-code |
| gitlab-archived | B | 9 | 355 | ax.annotations, conf.tools.schema-valid, conf.tools.unknown-error-code |
| heroku | A | 33 | 5,606 | ax.annotations |
| hubspot | A | 21 | 10,058 | none |
| kubernetes | A | 23 | 5,963 | ax.annotations, conf.tools.unknown-error-code |
| memory | A | 9 | 2,766 | none |
| mongodb | A | 27 | 19,496 | none |
| neon | could not start here | - | - | see doctor |
| notion | A | 24 | 19,051 | conf.tools.unknown-error-code |
| playwright | A | 25 | 5,069 | ax.short-descriptions |
| postgres-archived | A | 1 | 32 | ax.annotations, conf.tools.unknown-error-code |
| puppeteer-archived | could not start here | - | - | see doctor |
| py-awsdocs | A | 5 | 5,809 | ax.annotations |
| py-fetch | A | 1 | 362 | none |
| py-git | A | 14 | 1,907 | ax.short-descriptions |
| py-sqlite | could not start here | - | - | see doctor |
| py-time | A | 3 | 1,072 | none |
| redis-archived | could not start here | - | - | see doctor |
| sentry | A | 73 | 81,566 | none |
| seq-thinking | A | 1 | 1,160 | none |
| slack-archived | B | 8 | 777 | ax.annotations, conf.tools.unknown-not-success, conf.tools.unknown-error-code |
| stripe | could not start here | - | - | see doctor |
| supabase | no grade | 0 | - | none |
| tavily | A | 5 | 1,923 | ax.annotations, conf.tools.unknown-error-code |

Remote (HTTP) sign-in checks were validated against the OAuth fixtures only: this environment cannot reach remote MCP servers. Run a few real remote servers, with and without a token, before the beta.


## v0.1.4 re-run: trust and agent readiness (22 Nov 2026)

v0.1.4 adds a second grade, **agent readiness** (annotations 30%, descriptions 40%, context cost 30%, with partial credit; full credit for context cost up to 10,000 tokens per turn, falling to zero at 60,000), and shows coverage beside the trust grade. Re-run on 28 servers that started (three others needed network or downloads unavailable in this environment that day).

- **Trust:** 25 A, 2 B, 1 withheld (no tools without valid credentials). v0.1 trust checks are hygiene checks; well-maintained servers rightly pass them, and the report now says what v0.1 covers.
- **Agent readiness:** 15 A, 12 C. Every C is either a server that declares no danger annotations at all, or one whose tool definitions cost about 69,000 tokens per turn. Each gets one concrete improvement. Partial credit is fairer than the old pass/fail check: a server annotating 22 of 23 tools now scores 99 instead of failing.

| Server | Trust | Agent readiness | Annotated tools | Context tokens | Top improvement |
| --- | --- | --- | --- | --- | --- |
| aws-kb-archived | A | C (70) | 0/1 | 117 | declare danger annotations (readOnlyHint, destructiveHint) on 1 of 1 tools |
| brave-archived | A | C (70) | 0/2 | 362 | declare danger annotations (readOnlyHint, destructiveHint) on 2 of 2 tools |
| context7 | A | A (100) | 2/2 | 1,304 | none |
| elasticsearch | A | C (70) | 0/4 | 445 | declare danger annotations (readOnlyHint, destructiveHint) on 4 of 4 tools |
| everart-archived | A | C (70) | 0/1 | 223 | declare danger annotations (readOnlyHint, destructiveHint) on 1 of 1 tools |
| everything | A | A (100) | 13/13 | 1,910 | none |
| exa | A | A (100) | 2/2 | 534 | none |
| figma | A | A (100) | 2/2 | 973 | none |
| filesystem | A | A (100) | 14/14 | 3,275 | none |
| firecrawl | A | A (92) | 28/28 | 22,831 | trim tool definitions: agents read 22,831 tokens of them on every turn |
| github-archived | A | C (70) | 0/26 | 3,960 | declare danger annotations (readOnlyHint, destructiveHint) on 26 of 26 tools |
| gitlab-archived | B | C (70) | 0/9 | 355 | declare danger annotations (readOnlyHint, destructiveHint) on 9 of 9 tools |
| heroku | A | C (70) | 0/33 | 5,606 | declare danger annotations (readOnlyHint, destructiveHint) on 33 of 33 tools |
| hubspot | A | A (100) | 21/21 | 10,058 | none |
| kubernetes | A | A (99) | 22/23 | 5,963 | declare danger annotations (readOnlyHint, destructiveHint) on 1 of 23 tools |
| memory | A | A (100) | 9/9 | 2,766 | none |
| notion | A | A (95) | 24/24 | 19,051 | trim tool definitions: agents read 19,051 tokens of them on every turn |
| playwright | A | A (95) | 25/25 | 5,069 | write usable descriptions for 3 of 25 tools |
| postgres-archived | A | C (70) | 0/1 | 32 | declare danger annotations (readOnlyHint, destructiveHint) on 1 of 1 tools |
| py-awsdocs | A | C (70) | 0/5 | 5,809 | declare danger annotations (readOnlyHint, destructiveHint) on 5 of 5 tools |
| py-fetch | A | A (100) | 1/1 | 362 | none |
| py-git | A | A (94) | 14/14 | 1,926 | write usable descriptions for 2 of 14 tools |
| py-time | A | A (100) | 3/3 | 1,072 | none |
| sentry | A | C (70) | 74/74 | 68,975 | trim tool definitions: agents read 68,975 tokens of them on every turn |
| seq-thinking | A | A (100) | 1/1 | 1,160 | none |
| slack-archived | B | C (70) | 0/8 | 777 | declare danger annotations (readOnlyHint, destructiveHint) on 8 of 8 tools |
| supabase | no grade | - | - | - | none |
| tavily | A | C (70) | 0/5 | 1,923 | declare danger annotations (readOnlyHint, destructiveHint) on 5 of 5 tools |

## v0.2.0: functional testing, capability profile, load (22 Nov 2026)

**Passive, 30 servers:** trust 30 A (the unknown-tool error code is now informational); agent readiness 17 A and 13 C.
**Capability profile:** first draft inference produced false labels (a Git checkout as "moves money", a knowledge-graph
search as "untrusted content", a lethal-trifecta warning on a well-built monitoring server). Rules were made conservative
(declared, two agreeing signals, or unambiguous first-sentence wording; ambiguous words removed) and re-reviewed on all
30 servers until every label was defensible.

**Active, 7 local-resource servers** (reference servers, a scratch folder, a scratch Git repository, time, and one docs
service): **no false failures.** Structured output was validated against a real declared `outputSchema`; generated
arguments often produced error results (paths or repositories that do not exist), correctly not counted as failures;
destructive tools were never called and unannotated tools were skipped with reasons; every server was fast at p95 and
handled 20 concurrent callers with no errors.
