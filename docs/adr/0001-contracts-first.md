# 0001 Contracts first
**Decision:** every data format (pack, result, test cases, call envelope, receipt) is a versioned JSON Schema in `contracts/`, written and agreed before code. Code validates against the contracts at runtime.
**Why:** the same formats serve Trust Check, hosted certification, bounties and the gateway; changing them later is the most expensive kind of rework.
**Consequences:** contract changes need examples, tests and a version decision (additive within a minor version).
