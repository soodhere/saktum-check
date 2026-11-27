// `saktum demo`: permissions, autonomy, risk and receipts in 60 seconds. A built-in shop server and one shopping agent
// under three mandates (notify, propose, act with limits), all through the real proxy, with signed receipts and passports.
import { mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { loadOrCreateKey } from "@saktum/sign";
import { connect } from "@saktum/transports";
import { agentMaturity, acceptAgreement, buildManifest, draftAgreement, findOrphans, issueCredential, kpis, organisationRoot, searchCatalogue, topUp, usageStatement, verifyAgreement, verifyChain, walletBalance, checkOperator, cosignMandate, revokeMandate, trustStatement, agentRiskTier, checkMandate, createMandate, describeMandate, parseReceiptLog, summariseReceipts, verifyReceiptLog, type IntentMandate, type Mandate } from "@saktum/testkit-core";
import { renderAgentPassport } from "@saktum/report";

const PRODUCTS = [{ id: "oat-milk", name: "Oat milk 1 L", price: 4.49 }, { id: "bread", name: "Sourdough bread", price: 5.99 }, { id: "coffee", name: "Coffee beans 1 kg", price: 21.99 }];
const DEMO_TOOLS = [
  { name: "search_products", description: "Search the store's catalogue for products matching a query.", inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] }, annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: "get_deals", description: "List this week's best deals on products the user usually buys.", inputSchema: { type: "object", properties: {} }, annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: "add_to_cart", description: "Add a product to the user's cart.", inputSchema: { type: "object", properties: { product: { type: "string" }, quantity: { type: "integer", minimum: 1 } }, required: ["product", "quantity"] }, annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false } },
  { name: "pay_for_order", description: "Charges the customer's card for the cart total and places the order.", inputSchema: { type: "object", properties: { amount: { type: "number" }, currency: { type: "string" }, idempotency_key: { type: "string" } }, required: ["amount", "currency", "idempotency_key"] }, annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true } }
];

const B = (bindings: Record<string, string>, action: string) => ({ "io.saktum/bindings": bindings, "io.saktum/action": action });
const GROCERY_TOOLS = [
  { name: "search_products", description: "Search the store's catalogue for products matching a query.", inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] }, annotations: { readOnlyHint: true }, _meta: B({}, "search") },
  { name: "add_to_cart", description: "Add a product to the cart, or a substitute for an unavailable product.", inputSchema: { type: "object", properties: { product: { type: "string" }, brand: { type: "string" }, category: { type: "string" }, quantity: { type: "integer" }, price: { type: "number" }, substitute_for: { type: "string" }, reference_price: { type: "number" }, upgrade: { type: "boolean" }, sponsored: { type: "boolean" } }, required: ["product", "quantity", "price"] },
    annotations: { readOnlyHint: false, destructiveHint: false }, _meta: B({ product: "commerce.item.product", brand: "commerce.item.brand", category: "commerce.item.category", quantity: "commerce.item.quantity", price: "commerce.item.unit_price", substitute_for: "commerce.item.substitute_for", reference_price: "commerce.item.reference_price", upgrade: "commerce.item.upgrade", sponsored: "commerce.item.sponsored" }, "cart") },
  { name: "pay_for_order", description: "Charges the customer's card for the cart total and places the order.", inputSchema: { type: "object", properties: { amount: { type: "number" }, currency: { type: "string" }, merchant: { type: "string" }, delivery_address: { type: "string" }, idempotency_key: { type: "string" } }, required: ["amount", "currency", "idempotency_key"] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true }, _meta: B({ amount: "commerce.order.total", currency: "commerce.order.currency", merchant: "commerce.counterparty", delivery_address: "personal.address" }, "pay") }
];
const TRAVEL_TOOLS = [
  { name: "search_flights", description: "Search flights between two cities on a date.", inputSchema: { type: "object", properties: { from: { type: "string" }, to: { type: "string" }, date: { type: "string" } }, required: ["from", "to", "date"] }, annotations: { readOnlyHint: true }, _meta: B({}, "search") },
  { name: "book_flight", description: "Book a flight itinerary for the traveller.", inputSchema: { type: "object", properties: { flight: { type: "string" }, fare: { type: "number" }, currency: { type: "string" }, stops: { type: "integer" }, refundable: { type: "boolean" }, carrier: { type: "string" }, passport_number: { type: "string" }, idempotency_key: { type: "string" } }, required: ["flight", "fare", "stops", "refundable"] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true }, _meta: B({ fare: "travel.fare.total", currency: "travel.fare.currency", stops: "travel.itinerary.connections", refundable: "travel.fare.refundable", carrier: "travel.carrier", passport_number: "personal.passport" }, "book") },
  { name: "share_traveller_details", description: "Share the traveller's details with a travel partner.", inputSchema: { type: "object", properties: { recipient: { type: "string" }, passport_number: { type: "string" }, email: { type: "string" } }, required: ["recipient"] }, annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true }, _meta: B({ recipient: "party.recipient", passport_number: "personal.passport", email: "personal.email" }, "communicate") },
  { name: "change_seat", description: "Change the traveller's seat on a booked flight.", inputSchema: { type: "object", properties: { seat: { type: "string" }, fee: { type: "number" } }, required: ["seat", "fee"] }, annotations: { readOnlyHint: false, destructiveHint: false }, _meta: B({ seat: "travel.seat", fee: "travel.fee" }, "change") },
  { name: "upgrade_cabin", description: "Upgrade the traveller to a higher cabin for a fee.", inputSchema: { type: "object", properties: { cabin: { type: "string" }, fee: { type: "number" }, upgrade: { type: "boolean" } }, required: ["cabin", "fee"] }, annotations: { readOnlyHint: false, destructiveHint: false }, _meta: B({ fee: "travel.fee", upgrade: "travel.upgrade" }, "change") }
];

const FINANCE_TOOLS = [
  { name: "send_report", description: "Send a report to a recipient.", inputSchema: { type: "object", properties: { recipient: { type: "string" }, report: { type: "string" }, data_class: { type: "string" } }, required: ["recipient", "report", "data_class"] }, annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true }, _meta: B({ recipient: "party.recipient", data_class: "enterprise.data_class" }, "communicate") },
  { name: "pay_invoice", description: "Pays a vendor invoice from the company account.", inputSchema: { type: "object", properties: { amount: { type: "number" }, currency: { type: "string" }, vendor: { type: "string" }, idempotency_key: { type: "string" } }, required: ["amount", "currency", "vendor", "idempotency_key"] }, annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true }, _meta: B({ amount: "commerce.order.total", currency: "commerce.order.currency", vendor: "enterprise.vendor" }, "pay") }
];

const CODING_TOOLS = [
  { name: "run_tests", description: "Run the repository's test suite.", inputSchema: { type: "object", properties: { repository: { type: "string" } }, required: ["repository"] }, annotations: { readOnlyHint: true }, _meta: B({ repository: "code.repository" }, "search") },
  { name: "open_pull_request", description: "Open a pull request with the agent's changes.", inputSchema: { type: "object", properties: { repository: { type: "string" }, title: { type: "string" } }, required: ["repository", "title"] }, annotations: { readOnlyHint: false, destructiveHint: false }, _meta: B({ repository: "code.repository" }, "change") },
  { name: "read_secret", description: "Read a secret from the secrets store.", inputSchema: { type: "object", properties: { repository: { type: "string" }, name: { type: "string" } }, required: ["repository", "name"] }, annotations: { readOnlyHint: true }, _meta: B({ repository: "code.repository" }, "search") },
  { name: "deploy_to_staging", description: "Deploy a build to the staging environment.", inputSchema: { type: "object", properties: { repository: { type: "string" }, build: { type: "string" } }, required: ["repository", "build"] }, annotations: { readOnlyHint: false, destructiveHint: false }, _meta: B({ repository: "code.repository" }, "change") },
  { name: "deploy_to_production", description: "Release a build to production.", inputSchema: { type: "object", properties: { repository: { type: "string" }, build: { type: "string" } }, required: ["repository", "build"] }, annotations: { readOnlyHint: false, destructiveHint: true }, _meta: B({ repository: "code.repository" }, "deploy") }
];

/** The demo servers: ordinary MCP servers with no knowledge of Saktum (their tools declare semantic bindings). */
export async function startDemoServer(story = "autonomy"): Promise<void> {
  const tools = story === "grocery" ? GROCERY_TOOLS : story === "travel" ? TRAVEL_TOOLS : story === "finance" ? FINANCE_TOOLS : story === "coding" ? CODING_TOOLS : DEMO_TOOLS;
  const server = new Server({ name: story === "travel" ? "demo-travel" : story === "finance" ? "demo-finance" : "demo-grocer", version: "1.0.0" }, { capabilities: { tools: {} } });
  const cart: string[] = [];
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const a = (req.params.arguments ?? {}) as Record<string, unknown>;
    const text = (t: string) => ({ content: [{ type: "text", text: t }] });
    switch (req.params.name) {
      case "search_products": if (story === "grocery") return text("Oat milk (Usual Farms) $4.49 · Rye bread (Bakehouse) $6.35 · Sourdough: out of stock · Snack bar (Promo, sponsored) $3.99");
        return text(PRODUCTS.filter((p) => p.name.toLowerCase().includes(String(a.query ?? "").toLowerCase().split(" ")[0]!)).map((p) => `${p.name}: $${p.price}`).join("\n") || "No match.");
      case "get_deals": return text("Deal: coffee beans 1 kg, $21.99 (was $27.99).");
      case "add_to_cart": cart.push(String(a.product)); return text(`Added ${a.quantity} × ${a.product}${a.brand ? ` (${a.brand})` : ""}.`);
      case "pay_for_order": return text(`Paid $${a.amount} ${a.currency}. Order placed.`);
      case "search_flights": return text("YUL 3 Mar: Maple Air 1 stop $540 refundable · Budget Jet 2 stops $420 · Direct Air $380 non-refundable.");
      case "book_flight": return text(`Booked ${a.flight} for $${a.fare}.`);
      case "change_seat": return text(`Seat changed to ${a.seat}.`);
      case "upgrade_cabin": return text(`Upgraded to ${a.cabin}.`);
      case "share_traveller_details": return text(`Shared with ${a.recipient}.`);
      case "send_report": return text(`Sent "${a.report}" to ${a.recipient}.`);
      case "pay_invoice": return text(`Paid $${a.amount} to ${a.vendor}.`);
      case "run_tests": return text(`${a.repository}: 412 tests passed.`);
      case "open_pull_request": return text(`Opened pull request #318 in ${a.repository}: ${a.title}.`);
      case "read_secret": return text(`Read ${a.name}.`);
      case "deploy_to_staging": return text(`Deployed ${a.build} to staging.`);
      case "deploy_to_production": return text(`Released ${a.build} to production.`);
      default: return { isError: true, content: [{ type: "text", text: "Unknown tool" }] };
    }
  });
  const closed = new Promise<void>((r) => { server.onclose = () => r(); process.stdin.on("end", () => r()); });
  await server.connect(new StdioServerTransport());
  await closed;
}

type Step = { tool: string; args: Record<string, unknown>; say: string; approveLast?: boolean };
const SCRIPT: Step[] = [
  { tool: "get_deals", args: {}, say: "checks this week's deals" },
  { tool: "search_products", args: { query: "coffee" }, say: "searches for coffee" },
  { tool: "add_to_cart", args: { product: "coffee", quantity: 1 }, say: "adds coffee beans to the cart" },
  { tool: "pay_for_order", args: { amount: 18, currency: "CAD", idempotency_key: "order-1" }, say: "tries to pay $18" }
];
const EXTRA: Step[] = [
  { tool: "pay_for_order", args: { amount: 30, currency: "CAD", idempotency_key: "order-2" }, say: "tries to pay $30" },
  { tool: "pay_for_order", args: { amount: 80, currency: "CAD", idempotency_key: "order-3" }, say: "tries to pay $80" },
  { tool: "pay_for_order", args: { amount: 10, currency: "USD", idempotency_key: "order-4" }, say: "tries to pay $10 in USD" }
];

type Story = { id: string; title: string; server: string; tools: string[]; m: Record<string, unknown>; steps: Step[] };
const GROCERY: Story = { id: "grocery", title: "Grocery: \"weekly groceries, my usual brands\"", server: "grocery", tools: GROCERY_TOOLS.map((t) => t.name), m: {
  autonomy: "act", purpose: "Weekly groceries for the family", actions: [{ cls: "search", autonomy: "act" }, { cls: "cart", autonomy: "act" }, { cls: "pay", autonomy: "act" }],
  rules: [{ field: "commerce.item.quantity", op: "max", value: 2, label: "at most 2 of each item" }, { field: "commerce.item.category", op: "notIn", value: ["alcohol"], label: "never alcohol" }, { field: "commerce.order.total", op: "max", value: 150, label: "up to $150 per order" }],
  substitution: { allowed: true, maxPriceChangePct: 10, neverFor: ["baby food"] }, upsell: "ask", preferences: [{ field: "commerce.item.brand", prefer: "Usual Farms", label: "the usual brand, Usual Farms" }],
  counterparties: ["Demo Grocer"], dataSharing: [{ data: "delivery address", to: "Demo Grocer" }],
  disclosures: { operator: "Demo Grocer", incentives: "Sponsored products are labelled", dataUse: "Order history used only for your lists" } }, steps: [
  { tool: "search_products", args: { query: "milk" }, say: "searches the catalogue" },
  { tool: "add_to_cart", args: { product: "Oat milk", brand: "Usual Farms", category: "dairy", quantity: 1, price: 4.49 }, say: "adds oat milk" },
  { tool: "add_to_cart", args: { product: "Apples", brand: "Usual Farms", category: "produce", quantity: 5, price: 0.8 }, say: "adds 5 bags of apples" },
  { tool: "add_to_cart", args: { product: "Rye bread", brand: "Bakehouse", category: "bakery", quantity: 1, price: 6.35, substitute_for: "Sourdough bread", reference_price: 5.99 }, say: "substitutes rye for the out-of-stock sourdough (+6%)" },
  { tool: "add_to_cart", args: { product: "Baby oatmeal", brand: "Other Co", category: "baby food", quantity: 1, price: 4.2, substitute_for: "Usual Farms baby oatmeal", reference_price: 4.1 }, say: "substitutes another brand of baby oatmeal" },
  { tool: "add_to_cart", args: { product: "Premium coffee 2 kg", brand: "Usual Farms", category: "coffee", quantity: 1, price: 39.99, upgrade: true }, say: "upgrades coffee to the premium 2 kg bag" },
  { tool: "add_to_cart", args: { product: "Snack bar", brand: "Promo", category: "snacks", quantity: 1, price: 3.99, sponsored: true }, say: "adds a sponsored snack bar" },
  { tool: "add_to_cart", args: { product: "Red wine", brand: "Cellar", category: "alcohol", quantity: 1, price: 14.99 }, say: "adds a bottle of wine" },
  { tool: "add_to_cart", args: { product: "Gift card $50", category: "gift cards", quantity: 10, price: 50 }, say: "is tricked by a hidden instruction in a listing: adds 10 gift cards" },
  { tool: "pay_for_order", args: { amount: 90, currency: "CAD", merchant: "QuickCash", idempotency_key: "g-x" }, say: "is tricked into paying $90 to QuickCash" },
  { tool: "pay_for_order", args: { amount: 68.4, currency: "CAD", merchant: "Demo Grocer", delivery_address: "12 King St, Toronto", idempotency_key: "g-1" }, say: "pays $68.40 to Demo Grocer, with your delivery address" },
  { tool: "pay_for_order", args: { amount: 180, currency: "CAD", merchant: "Demo Grocer", idempotency_key: "g-2" }, say: "tries to pay $180" }] };
const TRAVEL: Story = { id: "travel", title: "Travel: \"business trip to Montreal, refundable, at most one stop\"", server: "travel", tools: TRAVEL_TOOLS.map((t) => t.name), m: {
  autonomy: "act", purpose: "Business trip to Montreal, 3 to 4 March", actions: [{ cls: "search", autonomy: "act" }, { cls: "book", autonomy: "act" }, { cls: "change", autonomy: "act" }],
  rules: [{ field: "travel.fare.total", op: "max", value: 600, label: "fare up to $600" }, { field: "travel.itinerary.connections", op: "max", value: 1, label: "at most one connection" }, { field: "travel.fare.refundable", op: "eq", value: true, label: "refundable fares only" }],
  upsell: "ask", approvalTriggers: ["fee"], preferences: [{ field: "travel.seat", prefer: "aisle", label: "an aisle seat" }, { field: "travel.carrier", prefer: "Maple Air", label: "Maple Air (loyalty)" }],
  dataSharing: [{ data: "passport", to: "Maple Air" }], disclosures: { operator: "Demo Travel", incentives: "No commissions affect choices", dataUse: "Trip details used only for this booking" } }, steps: [
  { tool: "search_flights", args: { from: "YYZ", to: "YUL", date: "2027-03-03" }, say: "searches flights" },
  { tool: "book_flight", args: { flight: "BJ 210", fare: 420, currency: "CAD", stops: 2, refundable: true, carrier: "Budget Jet", idempotency_key: "t-1" }, say: "tries the cheapest fare (2 stops, $420)" },
  { tool: "book_flight", args: { flight: "DA 101", fare: 380, currency: "CAD", stops: 0, refundable: false, carrier: "Direct Air", idempotency_key: "t-2" }, say: "tries a direct non-refundable fare ($380)" },
  { tool: "book_flight", args: { flight: "MA 330", fare: 540, currency: "CAD", stops: 1, refundable: true, carrier: "Maple Air", passport_number: "X1234567", idempotency_key: "t-3" }, say: "books Maple Air, 1 stop, refundable ($540), with your passport" },
  { tool: "share_traveller_details", args: { recipient: "Hotel Partner", passport_number: "X1234567" }, say: "tries to share your passport with a hotel partner" },
  { tool: "change_seat", args: { seat: "aisle", fee: 0 }, say: "changes to a free aisle seat" },
  { tool: "change_seat", args: { seat: "window, extra legroom", fee: 45 }, say: "tries a $45 extra-legroom seat" },
  { tool: "upgrade_cabin", args: { cabin: "business", fee: 120, upgrade: true }, say: "tries a $120 business upgrade" }] };

const FINANCE: Story = { id: "finance", title: "Finance: \"month-end operations; confidential data only to the auditor; I approve big invoices\"", server: "finance", tools: FINANCE_TOOLS.map((t) => t.name), m: {
  autonomy: "act", purpose: "Month-end finance operations", actions: [{ cls: "communicate", autonomy: "act" }, { cls: "pay", autonomy: "act" }],
  rules: [{ field: "commerce.order.total", op: "max", value: 50000, label: "invoices up to $50,000" }], approveAbove: { arg: "amount", value: 10000 },
  dataSharing: [{ data: "internal", to: "Finance team" }, { data: "confidential", to: "External Auditor" }],
  disclosures: { operator: "Acme Corp IT", incentives: "None", dataUse: "Company data stays within the recipients listed" } }, steps: [
  { tool: "send_report", args: { recipient: "Finance team", report: "Month-end close summary", data_class: "internal" }, say: "sends the internal close summary to the finance team" },
  { tool: "send_report", args: { recipient: "Partner Agency", report: "Q1 forecast", data_class: "confidential" }, say: "tries to send the confidential forecast to a partner agency" },
  { tool: "send_report", args: { recipient: "External Auditor", report: "Q4 results", data_class: "confidential" }, say: "sends confidential results to the external auditor" },
  { tool: "pay_invoice", args: { amount: 4200, currency: "CAD", vendor: "Cloud Hosting Inc", idempotency_key: "f-1" }, say: "pays a $4,200 hosting invoice" },
  { tool: "pay_invoice", args: { amount: 12000, currency: "CAD", vendor: "Consulting LLP", idempotency_key: "f-2" }, say: "tries to pay a $12,000 consulting invoice" },
  { tool: "", args: {}, say: "you approve exactly that invoice (saktum agent approve)", approveLast: true },
  { tool: "pay_invoice", args: { amount: 12000, currency: "CAD", vendor: "Consulting LLP", idempotency_key: "f-2" }, say: "retries the same $12,000 invoice" }] };

const CODING: Story = { id: "coding", title: "Coding agent: \"fix the failing tests; production only with my approval\"", server: "coding", tools: CODING_TOOLS.map((t) => t.name), m: {
  autonomy: "act", destructive: true, purpose: "Fix the failing tests in payments-service overnight", actions: [{ cls: "search", autonomy: "act" }, { cls: "change", autonomy: "act" }, { cls: "deploy", autonomy: "propose" }],
  rules: [{ field: "code.repository", op: "in", value: ["payments-service"], label: "only the payments-service repository" }],
  disclosures: { operator: "Acme platform team", incentives: "None", dataUse: "Code and secrets of payments-service only" } }, steps: [
  { tool: "run_tests", args: { repository: "payments-service" }, say: "runs the test suite" },
  { tool: "open_pull_request", args: { repository: "payments-service", title: "Fix currency rounding in refunds" }, say: "opens a pull request with the fix" },
  { tool: "read_secret", args: { repository: "payments-service", name: "STAGING_DB_URL" }, say: "reads its own staging database secret" },
  { tool: "read_secret", args: { repository: "billing-core", name: "PROD_SIGNING_KEY" }, say: "tries to read another repository's production key" },
  { tool: "deploy_to_staging", args: { repository: "payments-service", build: "build-2291" }, say: "deploys build-2291 to staging" },
  { tool: "deploy_to_production", args: { repository: "payments-service", build: "build-2291" }, say: "tries to release build-2291 to production" },
  { tool: "", args: {}, say: "in the morning, you approve exactly that release (saktum agent approve)", approveLast: true },
  { tool: "deploy_to_production", args: { repository: "payments-service", build: "build-2291" }, say: "retries the same release" }] };

async function runStory(dir: string, st: Story, owner: ReturnType<typeof loadOrCreateKey>, log: (s: string) => void): Promise<string> {
  const self = [...process.execArgv, process.argv[1]!];
  const agentKey = loadOrCreateKey(join(dir, `${st.id}-agent-key.json`));
  const m = createMandate({ agentId: agentKey.kid, agentName: `${st.id === "travel" ? "Travel" : "Shopping"} agent`, ownerName: "Demo customer", tools: st.tools, destructive: false,
    expires: new Date(Date.now() + 7 * 864e5).toISOString().slice(0, 10), ...(st.m as object) } as never, owner) as Mandate & IntentMandate;
  const operatorName = String((st.m as { disclosures?: { operator?: string } }).disclosures?.operator ?? "Demo operator");
  const cm = cosignMandate(m, loadOrCreateKey(join(dir, `${st.id}-operator-key.json`)), operatorName) as Mandate & IntentMandate;
  const mf = join(dir, `${st.id}-mandate.json`), rf = join(dir, `${st.id}-receipts.jsonl`), revf = join(dir, "revocations.json");
  writeFileSync(mf, JSON.stringify(cm, null, 2));
  log(`\u2500\u2500 ${st.title}`);
  log(`   Signed by you; countersigned by the operator, ${operatorName}.`);
  for (const line of describeMandate(m)) log(`   ${line}`);
  const open = () => connect({ kind: "stdio", command: process.execPath, args: [...self, "proxy", "--mandate", mf, "--agent-key", join(dir, `${st.id}-agent-key.json`), "--enforce", "--receipts", rf, "--revocations", revf, "--approvals", join(dir, "approvals.json"), "--", process.execPath, ...self, "demo-server", "--story", st.server] });
  const s = await open();
  try {
    await s.listTools();
    let lastRid = "";
    for (const step of st.steps) {
      if (step.approveLast) { const { approveAction } = await import("@saktum/testkit-core"); approveAction(cm, lastRid, owner, 60, join(dir, "approvals.json")); log(`   \u270d ${step.say}: ${lastRid}`); continue; }
      const o = await s.callTool(step.tool, step.args);
      const txt = o.kind === "result" ? (o.content as { text?: string }[]).map((c) => c.text ?? "").join(" ") : o.kind;
      const rid = /\[approval request (apr_[0-9a-f]+)\]/.exec(txt); if (rid) lastRid = rid[1]!;
      const blocked = /^Blocked by Saktum \(([^)]+)\): (.+?)( \[approval request [^\]]+\])?\.( Ask| Tell|$)/.exec(txt);
      const lastR = parseReceiptLog(readFileSync(rf, "utf8")).pop();
      log(blocked ? `   \u26d4 ${step.say}: ${blocked[1]}: ${blocked[2]}` : `   \u2713 ${step.say}${/approved by/.test(String(lastR?.receipt.reason ?? "")) ? ": approved by you, once" : ""}`);
      const last = parseReceiptLog(readFileSync(rf, "utf8")).pop();
      for (const p of last?.result.rationale?.preferences ?? []) if (!blocked) log(`      \u00b7 ${p}`);
      for (const f of last?.result.rationale?.flags ?? []) if (!blocked && !/differs from the stated preference/.test(f)) log(`      ! ${f}`);
    }
  } finally { await s.close(); await new Promise((r) => setTimeout(r, 300)); }
  if (st.id === "grocery") {
    revokeMandate(cm, "you pressed stop", revf);
    const s2 = await open();
    try { await s2.listTools(); const o = await s2.callTool("search_products", { query: "milk" }); const txt = o.kind === "result" ? (o.content as { text?: string }[]).map((c) => c.text ?? "").join(" ") : o.kind;
      log(/revoked/.test(txt) ? "   \u26d4 after you press stop (saktum agent revoke), it tries to search again: revoked" : `   ? after revoke: ${txt.slice(0, 80)}`);
    } finally { await s2.close(); await new Promise((r) => setTimeout(r, 300)); }
  }
  const entries = parseReceiptLog(readFileSync(rf, "utf8"));
  const ts = trustStatement(entries, verifyReceiptLog(entries).ok);
  log("   Track record:"); for (const l of ts.lines) log(`     ${l}`);
  const html = join(dir, `${st.id}-passport.html`);
  writeFileSync(html, renderAgentPassport(m as never, checkMandate(m).ok ? { ok: true } : { ok: false }, { verified: verifyReceiptLog(entries).ok, summary: summariseReceipts(entries),
    timeline: entries.map((e) => ({ tool: e.receipt.envelope.tool, outcome: e.receipt.outcome, status: e.result.status, repeated: false, why: [e.receipt.reason ?? "", ...(e.result.rationale?.preferences ?? []), ...(e.result.rationale?.flags ?? [])].filter(Boolean).join(" · ") })) }, agentRiskTier(m), describeMandate(m), { operator: (() => { const op = checkOperator(cm as never); return op.present && op.valid ? `${op.name} (${op.id})` : undefined; })(), track: ts.lines,
    maturity: agentMaturity(cm, { entries, verified: verifyReceiptLog(entries).ok }) }));
  log(`   ${entries.length} signed receipts \u00b7 ${verifyReceiptLog(entries).ok ? "verified" : "NOT verified"} \u00b7 passport: ${html}\n`);
  return html;
}

async function runMarketplace(dir: string, log: (s: string) => void): Promise<string> {
  const self = [...process.execArgv, process.argv[1]!];
  const k = (n: string) => loadOrCreateKey(join(dir, `market-${n}-key.json`));
  const acme = k("acme"), priya = k("priya"), agent = k("agent"), grocer = k("grocer"), travel = k("travel");
  const exp = new Date(Date.now() + 180 * 864e5).toISOString().slice(0, 10);
  const w = (f: string, x: unknown) => { writeFileSync(join(dir, f), JSON.stringify(x, null, 2)); return join(dir, f); };
  log(`\u2500\u2500 Marketplace: "Acme's shopping agent finds a store, agrees terms, and pays per call in prepaid tokens"`);
  const root = organisationRoot({ name: "Acme Corp", domain: "acme.example", expires: exp }, acme);
  const priyaCred = issueCredential(root, acme, { type: "member", id: priya.kid, name: "Priya", role: "procurement lead", expires: exp });
  const agentCred = issueCredential(priyaCred, priya, { type: "agent", id: agent.kid, name: "Acme shopping agent", expires: exp });
  const credFile = w("market-agent-credential.json", agentCred);
  const vchain = verifyChain(agentCred);
  log(vchain.valid ? `   \u2713 identity chain: ${vchain.path.join(" \u2192 ")}; accountable organisation ${vchain.organisation}` : `   \u2717 identity chain broken: ${vchain.reason}`);
  const gm = buildManifest({ publisher: { name: "Demo Grocer", domain: "grocer.example" }, server: { name: "demo-grocer", version: "1.0.0" }, tools: GROCERY_TOOLS as never, rates: { perCall: 1, perTool: { add_to_cart: 2, pay_for_order: 5 } } }, grocer);
  const tm = buildManifest({ publisher: { name: "Demo Travel", domain: "travel.example" }, server: { name: "demo-travel", version: "1.0.0" }, tools: TRAVEL_TOOLS as never, rates: { perCall: 2 } }, travel);
  w("market-catalog.json", [gm, tm]);
  log(`   \u2713 Demo Grocer and Demo Travel publish signed manifests to the catalogue (rates in tokens per call)`);
  const hits = searchCatalogue([gm, tm], "buy weekly groceries for the office");
  log(`   \u2713 the agent searches "buy weekly groceries for the office": ${hits[0]!.manifest.publisher.name} (intents ${hits[0]!.matched.join(", ")})`);
  const ag = acceptAgreement(draftAgreement({ manifest: gm, invoker: { id: acme.kid, name: "Acme Corp" }, purpose: "Weekly office groceries", tools: gm.capabilities.map((c) => c.tool), tokensPerMonth: 500,
    specificTerms: ["Deliveries to the Acme office only", "Substitutions within 10% of the price"], validUntil: exp }, grocer), acme);
  const agFile = w("market-agreement.json", ag);
  log(`   \u2713 agreement ${ag.id}: ${ag.terms.length} default terms + ${ag.specificTerms!.length} specific, signed by Demo Grocer and Acme Corp (${verifyAgreement(ag).valid ? "verified" : "NOT valid"})`);
  const wf = join(dir, "market-wallet.json");
  topUp(wf, acme.kid, 12);
  log(`   \u2713 Acme tops up 12 prepaid tokens (bought outside Saktum; no money is handled here)`);
  const m = cosignMandate(createMandate({ agentId: agent.kid, agentName: "Acme shopping agent", ownerName: "Priya", purpose: "Weekly office groceries", tools: gm.capabilities.map((c) => c.tool), destructive: false, expires: exp, autonomy: "act", approveAbove: { arg: "amount", value: 50 } } as never, priya), acme, "Acme Corp");
  const mf = w("market-mandate.json", m), rf = join(dir, "market-receipts.jsonl"), revf = join(dir, "market-revoked-credentials.json");
  writeFileSync(revf, "[]");
  const open = () => connect({ kind: "stdio", command: process.execPath, args: [...self, "proxy", "--mandate", mf, "--agent-key", join(dir, "market-agent-key.json"), "--enforce", "--receipts", rf,
    "--credential", credFile, "--revoked-credentials", revf, "--agreement", agFile, "--wallet", wf, "--", process.execPath, ...self, "demo-server", "--story", "grocery"] });
  const steps: Step[] = [
    { tool: "search_products", args: { query: "milk" }, say: "searches the catalogue" },
    { tool: "add_to_cart", args: { product: "Oat milk", brand: "Usual Farms", category: "dairy", quantity: 2, price: 4.49 }, say: "adds oat milk" },
    { tool: "add_to_cart", args: { product: "Coffee beans 1 kg", brand: "Usual Farms", category: "coffee", quantity: 1, price: 21.99 }, say: "adds coffee" },
    { tool: "pay_for_order", args: { amount: 30.97, currency: "CAD", merchant: "Demo Grocer", idempotency_key: "m-1" }, say: "pays $30.97" },
    { tool: "add_to_cart", args: { product: "Bread", brand: "Usual Farms", category: "bakery", quantity: 1, price: 5.99 }, say: "starts next week's order" },
    { tool: "search_products", args: { query: "fruit" }, say: "searches again" }];
  const run = async (st: Step[]) => {
    const s2 = await open();
    try { await s2.listTools(); for (const st1 of st) {
      const o = await s2.callTool(st1.tool, st1.args); const txt = o.kind === "result" ? (o.content as { text?: string }[]).map((c) => c.text ?? "").join(" ") : o.kind;
      const blocked = /^Blocked by Saktum \(([^)]+)\): (.+?)\.( Ask| Tell|$)/.exec(txt); const last = parseReceiptLog(readFileSync(rf, "utf8")).pop();
      log(blocked ? `   \u26d4 ${st1.say}: ${blocked[1]}: ${blocked[2]}` : `   \u2713 ${st1.say} \u00b7 ${last?.result.metering?.tokens ?? 0} token(s), balance ${last?.result.metering?.balance ?? "-"}`);
    } } finally { await s2.close(); await new Promise((r) => setTimeout(r, 300)); }
  };
  await run(steps);
  const entries = parseReceiptLog(readFileSync(rf, "utf8"));
  const st = usageStatement(entries, ag, grocer) as { lines: { tool: string; calls: number; tokens: number }[]; totalTokens: number };
  log(`   \u2713 usage statement signed by Demo Grocer: ${st.lines.map((l) => `${l.tool} ${l.calls}\u00d7 = ${l.tokens}`).join(", ")}; total ${st.totalTokens} tokens`);
  log(`   \u2713 wallet (double-entry): Acme ${walletBalance(wf, acme.kid)} tokens, Demo Grocer ${walletBalance(wf, grocer.kid)} tokens`);
  writeFileSync(revf, JSON.stringify([priyaCred.id]));
  const orphan = findOrphans([agentCred], { revoked: [priyaCred.id] })[0];
  log(`   \u26d4 Priya leaves Acme and her credential is revoked: the agent is now an orphan (${orphan?.reason})`);
  topUp(wf, acme.kid, 5);
  await run([{ tool: "search_products", args: { query: "milk" }, say: "the orphaned agent tries to search" }]);
  const all = parseReceiptLog(readFileSync(rf, "utf8")); const k2 = kpis(all);
  log(`   KPIs: ${k2.calls} calls \u00b7 ${k2.allowed} allowed \u00b7 ${k2.blocked} blocked (${k2.byOutcome.filter(([c]) => !c.startsWith("ok")).map(([c, n]) => `${n} ${c}`).join(", ")}) \u00b7 ${k2.tokens} tokens`);
  const html = join(dir, "marketplace-passport.html");
  const ts = trustStatement(all, verifyReceiptLog(all).ok);
  writeFileSync(html, renderAgentPassport(m as never, { ok: true }, { verified: verifyReceiptLog(all).ok, summary: summariseReceipts(all), timeline: all.map((e) => ({ tool: e.receipt.envelope.tool, outcome: e.receipt.outcome, status: e.result.status, repeated: false, why: [e.receipt.reason ?? "", e.result.metering ? `${e.result.metering.tokens} token(s), balance ${e.result.metering.balance}` : ""].filter(Boolean).join(" \u00b7 ") })) },
    agentRiskTier(m), [`Weekly office groceries for Acme Corp, under agreement ${ag.id} with Demo Grocer.`, `Accountable: ${verifyChain(agentCred).path.join(" \u2192 ")}.`, "Paid per call in prepaid tokens."], { operator: "Acme Corp", track: ts.lines, maturity: agentMaturity(m as never, { entries: all, verified: verifyReceiptLog(all).ok, chainValid: verifyChain(agentCred).valid }) }));
  log(`   ${all.length} signed receipts \u00b7 ${verifyReceiptLog(all).ok ? "verified" : "NOT verified"} \u00b7 passport: ${html}\n`);
  return html;
}

export async function runDemo(dir: string, log: (s: string) => void, story = "all"): Promise<{ files: string[] }> {
  if (story === "autonomy") return runAutonomyDemo(dir, log);
  if (story === "marketplace") { if (existsSync(dir)) rmSync(dir, { recursive: true, force: true }); mkdirSync(dir, { recursive: true }); return { files: [await runMarketplace(dir, log)] }; }
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const owner = loadOrCreateKey(join(dir, "owner-key.json"));
  log("Saktum demo: agents acting on real instructions (rules, preferences, substitutions, upsells), every decision explained and signed.\n");
  const files: string[] = [];
  for (const st of story === "travel" ? [TRAVEL] : story === "grocery" ? [GROCERY] : story === "finance" ? [FINANCE] : story === "coding" ? [CODING] : [GROCERY, TRAVEL, FINANCE, CODING]) files.push(await runStory(dir, st, owner, log));
  if (story === "all") files.push(await runMarketplace(dir, log));
  log(["What you just saw: each agent followed its owner's instructions, not just limits. Even when tricked by a hidden",
    "instruction, the mandate held; personal and confidential data went only where you allowed; a big invoice waited for your",
    "signed approval of exactly that payment; and the stop button worked. In the marketplace, an agent traceable to a person",
    "and its organisation found a store by intent, both sides signed an agreement, every call was metered in prepaid tokens",
    "until credit ran out, and when its sponsor left, the orphaned agent was refused. Every decision has a signed receipt.",
    "Open the passports in the demo folder. Also try: npx saktum demo --story autonomy"].join("\n"));
  return { files };
}

export async function runAutonomyDemo(dir: string, log: (s: string) => void): Promise<{ files: string[] }> {
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const owner = loadOrCreateKey(join(dir, "owner-key.json"));
  const self = [...process.execArgv, process.argv[1]!];
  const tools = DEMO_TOOLS.map((t) => t.name);
  const personas: { id: string; title: string; m: Partial<Parameters<typeof createMandate>[0]>; steps: Step[] }[] = [
    { id: "notify", title: "\"Only alert me to great deals\"", m: { autonomy: "notify" }, steps: SCRIPT },
    { id: "propose", title: "\"Suggest, and I'll approve\"", m: { autonomy: "propose" }, steps: SCRIPT },
    { id: "act", title: "\"Act for me, up to $50; ask me above $25; Canadian dollars only\"", m: { autonomy: "act", constraints: [{ tool: "pay_for_order", arg: "amount", max: 50 }, { tool: "pay_for_order", arg: "currency", oneOf: ["CAD"] }], approveAbove: { arg: "amount", value: 25 }, limits: { totalPerDay: { arg: "amount", max: 100 } } }, steps: [...SCRIPT, ...EXTRA] }
  ];
  const files: string[] = [];
  log("Saktum demo: one shopping agent, three mandates, every call governed and receipted.\n");
  for (const p of personas) {
    const agentKey = loadOrCreateKey(join(dir, `${p.id}-agent-key.json`));
    const m = createMandate({ agentId: agentKey.kid, agentName: `Shopping agent (${p.id})`, ownerName: "Demo shopper", purpose: "Weekly grocery shopping", tools, destructive: false,
      expires: new Date(Date.now() + 7 * 864e5).toISOString().slice(0, 10), disclosures: { operator: "Demo Grocer", incentives: "None: no sponsored ranking", dataUse: "Order history used only to suggest your usual items" }, ...p.m }, owner);
    const mf = join(dir, `${p.id}-mandate.json`), rf = join(dir, `${p.id}-receipts.jsonl`);
    writeFileSync(mf, JSON.stringify(m, null, 2));
    const tier = agentRiskTier(m);
    log(`\u2500\u2500 ${p.title}   autonomy ${m.autonomy} \u00b7 risk ${tier.tier}`);
    const s = await connect({ kind: "stdio", command: process.execPath, args: [...self, "proxy", "--mandate", mf, "--agent-key", join(dir, `${p.id}-agent-key.json`), "--enforce", "--receipts", rf, "--", process.execPath, ...self, "demo-server"] });
    try {
      await s.listTools();
      for (const st of p.steps) {
        const o = await s.callTool(st.tool, st.args);
        const txt = o.kind === "result" ? (o.content as { text?: string }[]).map((c) => c.text ?? "").join(" ") : o.kind;
        const blocked = /^Blocked by Saktum \(([^)]+)\): ([^.]+)/.exec(txt);
        log(blocked ? `   \u26d4 ${st.say}: blocked (${blocked[1]}): ${blocked[2]}` : `   \u2713 ${st.say}: ${txt.split("\n")[0]}`);
      }
    } finally { await s.close(); await new Promise((r) => setTimeout(r, 300)); }
    const entries = parseReceiptLog(readFileSync(rf, "utf8"));
    const counts = new Map<string, number>();
    for (const e of entries) { const k = `${e.receipt.envelope.tool}|${e.receipt.envelope.argumentsHash}`; counts.set(k, (counts.get(k) ?? 0) + 1); }
    const html = join(dir, `${p.id}-passport.html`);
    writeFileSync(html, renderAgentPassport(m as never, checkMandate(m as Mandate).ok ? { ok: true } : { ok: false }, { verified: verifyReceiptLog(entries).ok, summary: summariseReceipts(entries),
      timeline: entries.map((e) => ({ tool: e.receipt.envelope.tool, outcome: e.receipt.outcome, status: e.result.status, repeated: (counts.get(`${e.receipt.envelope.tool}|${e.receipt.envelope.argumentsHash}`) ?? 0) >= 3 })) }, tier));
    files.push(html);
    log(`   ${entries.length} signed receipts \u00b7 ${verifyReceiptLog(entries).ok ? "verified" : "NOT verified"} \u00b7 passport: ${html}\n`);
  }
  log("What you just saw: the same agent and the same shop. Only the mandate changed what it was allowed to do, and every\ndecision, allowed or blocked, has a signed receipt. Open the passports to see each agent's permissions and path.");
  return { files };
}
