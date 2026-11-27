# Data flow

Nothing leaves your environment unless you send it (for example to your own OpenTelemetry collector or webhook).

```mermaid
flowchart LR
  A[Agent] -->|MCP call| P[saktum proxy<br/>on your machine or server]
  P -->|decide: mandate, agreement,<br/>approvals, revocation| P
  P -->|allowed calls only| S[MCP server<br/>local, or remote via saktum bridge]
  P -->|signed receipt| R[(receipts file<br/>your folder)]
  P -.->|optional| O[your OpenTelemetry collector]
  P -.->|optional approval request| W[your Slack, Teams or email webhook]
  W -.-> H[owner approves in saktum approvals serve<br/>with their key]
  H -->|signed approval| AP[(approvals file)]
  AP --> P
```

| Data | Where it lives | Leaves your environment? |
| --- | --- | --- |
| Private keys | Owner-only files, environment variables, or the OS keychain | Never |
| Mandates, approvals, revocations, agreements | Local files you control | Only if you share them |
| Receipts | Local file (or shared folder you choose); argument digests, not values | Only to your collector, if configured |
| Tool arguments and results | Between the agent and the MCP server | Only to the MCP server you chose |
| Census and ledger | Public, published by Saktum | Contains no customer data |
