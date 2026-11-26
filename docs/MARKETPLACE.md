# From trust to a marketplace (v0.8)

Agents find tools, agree terms with their providers, and pay per call in prepaid tokens, with every party accountable
and every call on record. Everything runs locally and is open source; no money is handled (tokens are prepaid credits,
settled outside Saktum).

```
npx saktum demo --story marketplace        # the whole flow in one run
```

## 1. Identity chains: every agent traceable to a person and an organisation
```
npx saktum org init --name "Acme Corp" --domain acme.example --key org-key.json
npx saktum identity issue --from org-credential.json --key org-key.json --type member --name "Priya" --role "procurement lead" --subject-key priya-key.json --out priya.json
npx saktum identity issue --from priya.json --key priya-key.json --type agent --name "Acme shopping agent" --subject-key agent-key.json --out agent.json
npx saktum identity verify agent.json      # Acme Corp -> Priya (procurement lead) -> Acme shopping agent
npx saktum identity orphans agent.json --revoked revoked.json   # agents whose sponsor left, expired or was revoked
```
Each credential is signed by its issuer; the chain is verified link by link. Agents cannot issue credentials.

## 2. Manifests and the catalogue: find tools by intent
```
npx saktum manifest create --publisher "Demo Grocer" --key grocer-key.json --per-call 1 --rate pay_for_order=5 -- npx -y the-store-server
npx saktum catalog add saktum-manifest.json
npx saktum catalog search "buy weekly groceries for the office" --max-risk R4
```
A manifest is signed by its publisher: capabilities with action classes and domain fields (from semantic bindings),
intents such as `pay:commerce`, categories, rates in tokens, and the server's grades and risk tier.

## 3. Agreements: smart contracts as signed documents
```
npx saktum agreement draft --manifest saktum-manifest.json --invoker <acme-did> --invoker-name "Acme Corp" --purpose "Weekly office groceries" --term "Deliveries to the Acme office only" --key grocer-key.json
npx saktum agreement accept saktum-agreement.json --key org-key.json
npx saktum agreement verify saktum-agreement.json
```
Default terms (template `saktum-default-0.1`) plus specific terms, scope, rates, limits, data terms and a dispute
contact. The provider signs, the invoker countersigns; any change breaks the signatures.

## 4. Metering and the prepaid wallet
```
npx saktum wallet topup --account <acme-did> --tokens 500
npx saktum proxy --mandate agent-mandate.json --credential agent.json --agreement saktum-agreement.json --wallet saktum-wallet.json --enforce -- npx -y the-store-server
npx saktum usage --agreement saktum-agreement.json --key grocer-key.json
npx saktum kpi
```
The proxy checks the agent's accountability chain leads to the agreement's invoker (`identity-chain`), refuses calls
outside the agreement (`outside-agreement`) or without a valid one (`no-valid-agreement`), and charges each call
(double-entry: invoker debited, provider credited); with too little credit the call is refused (`insufficient-credit`).
Receipts record the tokens and balance; usage statements list calls and tokens per tool, with the receipt hashes.

## 5. Bounties (contract only)
`contracts/bounty.schema.json`: sponsor, target, intent, scope, prequalification, success and failure criteria, reward
in tokens, disclosure terms, status. `npx saktum bounty validate file.json`. Running bounties waits for legal review
(researcher terms, safe harbour, disclosure, payouts) and demand.
