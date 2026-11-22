# 0002 Packs are data, logic lives in named analysers
**Decision:** packs are YAML/JSON with a closed set of step actions. Any logic is a named analyser in the engine.
**Why:** community and bounty packs must be safe to load; reviewing data is far easier than reviewing code.
**Consequences:** new kinds of checks may need a new analyser and an engine release; pack schema stays small.
