# Deployment hardening guide

1. **Separate the proxy from the agent.** Run `saktum proxy` under its own OS user (or container). The agent's user must
   not be able to read the proxy's keys or write its revocations, approvals, receipts or wallet.
2. **Protect keys.** Use `--key keychain:NAME`, `--key env:VAR` or `--key exec:/path/to/signer` (for a cloud key service
   or hardware module). Never leave key files readable by others.
3. **Pin tools.** Start the proxy with `--pin <tools fingerprint>` from your approved check or allowlist; re-approve on
   intended changes. Run `saktum watch` daily.
4. **Keep receipts honest.** Use `--digest-key env:VAR`, `--checkpoint-every 100 --checkpoint-file <path elsewhere>`, and
   ship receipts to your collector (`receipts export --otel`).
5. **Revocation that sticks.** Sign revocations (`agent revoke --key ...`) and point proxies at a remote list
   (`--revocations-url`) the agent cannot change.
6. **Approvals.** Use `approvals serve --secret env:VAR` with the proxy's `--approval-secret env:VAR` for per-request
   links; add `--passkey` for phishing-resistant approvals. Keep the page on localhost or behind your own TLS.
7. **Remote tools.** `saktum bridge https://... --header-env Authorization=MCP_TOKEN`; never put tokens on the command line.
8. **Verify Saktum.** `npm audit signatures`; `npx saktum self-verify`; pin the version you deploy.
