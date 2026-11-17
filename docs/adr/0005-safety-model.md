# 0005 Safety model
**Decision:** passive checks only by default; active checks and side-effect tests need `--active` and an owned target. Local servers start with a minimal environment (no user secrets unless passed with `--env`); a Docker sandbox arrives in v0.1. Public servers are checked politely (timeouts, low concurrency, identifying user agent).
**Why:** protects users, server owners and Saktum legally and ethically.
