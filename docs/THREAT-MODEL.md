# Threat model (STRIDE summary)

**System:** the `saktum` command running on a customer's machine or CI; optional proxy between an agent and MCP
servers (local, or remote through `saktum bridge`); local files for keys, mandates, approvals, revocations, receipts.
**Assets:** private keys; mandates and approvals; receipts; the integrity of decisions. **Trust boundaries:** the agent
(untrusted input: it may be manipulated by prompt injection), MCP servers (untrusted: their outputs and tool
descriptions are data), the network to remote servers, the local file system.

| Threat | Example | Mitigation | Residual risk |
| --- | --- | --- | --- |
| Spoofing | An agent claims another agent's identity | Each call is signed with the agent's key; mandates are signed by the owner and optionally countersigned by the operator; identity chains verified link by link | A stolen agent key: use keychain or environment keys, revoke and rotate |
| Tampering | Receipts edited after the fact | Hash-chained, signed receipts; `receipts verify` and the combined view detect changes and removals | An attacker with the key and file access can append new entries; ship receipts off-host |
| Repudiation | "The agent never did that" | Signed receipts with reason codes; approvals name the approver | Receipts are signed by the agent side until the gateway co-signs |
| Information disclosure | Secrets in logs or reports | Secrets never printed; argument digests only; headers never logged; data sharing enforced per recipient | Values passed to tools are visible to those tools by design |
| Denial of service | A flood of calls | Daily limits, token metering, insufficient-credit refusal | The proxy runs locally: protect the host |
| Elevation of privilege | A manipulated agent attempts a payment or deploy outside its mandate | Every call is decided before it reaches the tool: tools, action classes, rules, autonomy, approvals, revocation | Saktum governs MCP tool calls, not raw shell commands: use a sandbox for agents with shell access |

**Out of scope:** detecting prompt injection inside models; securing the MCP servers themselves (Saktum Check tests
them); governing agents inside SaaS platforms (planned with the gateway).
