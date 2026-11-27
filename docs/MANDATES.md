# Mandates: instructions agents must follow

A mandate is what a person (the principal) allows an agent to do on their behalf, signed by them. Since v0.7 it carries
**intent**, not just limits, written in domain terms that Saktum enforces on any server.

```
npx saktum agent create --name "Shopper" --autonomy act --intent examples/mandate-grocery.json --operator "My Grocer"
npx saktum proxy --mandate agent-mandate.json --enforce -- npx -y the-store-mcp-server
npx saktum passport --agent agent-mandate.json --receipts ~/.saktum/receipts.jsonl
```

## Parts of a mandate
| Part | Example |
| --- | --- |
| `purpose` | "Weekly groceries for the family" |
| `actions` | autonomy per action class: search, cart, substitute, pay, book, change, cancel, communicate (`notify`, `propose`, `act`) |
| `rules` (hard) | `{ "field": "commerce.item.quantity", "op": "max", "value": 2 }`; ops: max, min, eq, in, notIn |
| `preferences` (soft) | `{ "field": "commerce.item.brand", "prefer": "Usual Farms" }`, reported in receipts, never blocking |
| `substitution` | `{ "allowed": true, "maxPriceChangePct": 10, "neverFor": ["baby food"] }` |
| `upsell` | `never`, `ask` or `allowed` |
| `approvalTriggers` | `substitution`, `fee`, `upsell`, `sponsored`, `new-counterparty` |
| `counterparties`, `dataSharing` | allowed merchants; which data may go to whom |
| disclosures | operator, incentives, data use (`--operator`, `--incentives`, `--data-use`) |

## Vocabularies and bindings
Fields come from open, versioned vocabularies: **commerce** (order total and currency, item product, brand, category,
quantity, unit price, substitute for, reference price, upgrade, sponsored, counterparty) and **travel** (fare total,
currency and refundability, connections, arrival, carrier, seat, fee, upgrade). A server's tools bind their arguments to
these fields. Publishers declare bindings in each tool's `_meta`:

```json
"_meta": { "io.saktum/action": "cart", "io.saktum/bindings": { "quantity": "commerce.item.quantity", "brand": "commerce.item.brand" } }
```

Without declarations, Saktum infers bindings from argument names (marked inferred). See them, and the block to add, with
`npx saktum bindings -- <server>`.

## Receipts explain decisions
Every call's receipt records the decision code, the rules checked, the preferences matched or missed, and flags such as
a substitution, an upgrade or a sponsored option, so "did it buy what I asked for?" and "is it upselling me?" have answers.

## Parties, data, the stop button and the track record
- **Operator countersignature.** The principal signs the mandate; the operator (who runs the agent and is accountable)
  countersigns it: `npx saktum agent cosign agent-mandate.json --name "My Grocer" --key operator-key.json`.
  `npx saktum agent verify` checks both, and any change to the mandate breaks the operator's signature.
- **Data sharing is enforced.** Arguments bound to personal fields (email, phone, address, passport) may only go to the
  recipients named in `dataSharing`; anything else is blocked with `data-not-permitted`.
- **Stop an agent now.** `npx saktum agent revoke agent-mandate.json --reason "..."`: every proxy using that revocation
  list refuses the mandate's calls (`revoked`). `--revocations <file>` points a proxy at a shared list.
- **Even if the agent is tricked**, by a hidden instruction in a web page, document or tool output, the mandate still
  applies: the proxy checks every call before it reaches the service.
- **Track record.** `saktum passport --agent ... --receipts ...` shows a statement from the signed receipts: actions
  within the instructions, attempts stopped (by reason), preferences matched, and what was disclosed. Never a score.
- **Agent software.** `--software name@version` records what will act under the mandate.

## Signed approvals and enterprise data classes
- **Approve exactly one action.** When a call needs approval, the agent is told the request id (`apr_...`), which
  identifies this mandate, this tool and these exact arguments. The owner approves it with their key:
  `npx saktum agent approve apr_... --mandate agent-mandate.json --key owner-key.json` (valid 60 minutes by default,
  usable once). The agent's retry of the same action goes through, and its receipt records who approved it. Different
  arguments need a new approval. Example: `--approve-above amount=10000` with `examples/mandate-finance.json`.
- **Data classes.** Arguments bound to `enterprise.data_class` (`data_class`, `classification`, `sensitivity`) are
  enforced like personal data: anything above `public` may only go to recipients named for that class in
  `dataSharing`, for example `{ "data": "confidential", "to": "External Auditor" }`.

## Agent maturity (A1-A5)
Like the server levels (L1-L5), an agent's level is earned from evidence, one level at a time, never a score:
**A1 Identified** (its own identity and a valid mandate signed by its owner), **A2 Accountable** (an operator
countersignature or an identity chain to an organisation), **A3 Bounded** (explicit tools or action classes, no
sub-delegation, and caps or approvals when it can act irreversibly or spend), **A4 Explained** (signed, verified
receipts with a reason for every decision), **A5 Proven** (at least 10 actions, none outside its mandate, not revoked).
Every Agent Passport shows the level and which evidence is met.

## Coding agents (v0.9)
The `code` vocabulary (`code.repository`, `code.environment`) and the `deploy` action class let a mandate keep a coding
agent to its own repository and make production releases wait for approval: `actions` with `{ "cls": "deploy",
"autonomy": "propose" }`, plus a rule `{ "field": "code.repository", "op": "in", "value": ["payments-service"] }`.
Saktum governs the agent's tool calls (pull requests, secrets, deployments), not raw shell commands inside its machine:
use it with a sandbox. Try `npx saktum demo --story coding`.
