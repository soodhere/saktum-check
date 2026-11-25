// v0.7: domain vocabularies and semantic bindings. A mandate speaks in domain terms (commerce.order.total,
// travel.itinerary.connections); a tool's arguments are bound to those terms, either declared by the publisher in the
// tool's _meta ("io.saktum/bindings", "io.saktum/action") or proposed from argument names (marked inferred). Open and
// versioned, like the maturity model.
export interface VocabField { path: string; type: "number" | "string" | "boolean" | "string[]"; description: string }
export const VOCABULARIES: Record<string, { version: string; fields: VocabField[] }> = {
  commerce: { version: "0.1", fields: [
    { path: "commerce.order.total", type: "number", description: "Total amount of the order or payment" },
    { path: "commerce.order.currency", type: "string", description: "Currency of the order" },
    { path: "commerce.item.product", type: "string", description: "Product identifier or name" },
    { path: "commerce.item.brand", type: "string", description: "Brand of the item" },
    { path: "commerce.item.category", type: "string", description: "Category of the item (for example dairy, baby food, alcohol)" },
    { path: "commerce.item.quantity", type: "number", description: "Quantity of the item" },
    { path: "commerce.item.unit_price", type: "number", description: "Price of one unit" },
    { path: "commerce.item.substitute_for", type: "string", description: "The item this one replaces (a substitution)" },
    { path: "commerce.item.reference_price", type: "number", description: "Price of the item being replaced" },
    { path: "commerce.item.upgrade", type: "boolean", description: "A larger or premium option than requested (an upsell)" },
    { path: "commerce.item.sponsored", type: "boolean", description: "The option was sponsored or promoted" },
    { path: "commerce.counterparty", type: "string", description: "The merchant or seller" }
  ] },
  travel: { version: "0.1", fields: [
    { path: "travel.fare.total", type: "number", description: "Total fare" },
    { path: "travel.fare.currency", type: "string", description: "Currency of the fare" },
    { path: "travel.fare.refundable", type: "boolean", description: "Whether the fare is refundable" },
    { path: "travel.itinerary.connections", type: "number", description: "Number of connections (stops)" },
    { path: "travel.itinerary.arrive_by", type: "string", description: "Latest arrival time" },
    { path: "travel.carrier", type: "string", description: "Airline, rail or other carrier" },
    { path: "travel.seat", type: "string", description: "Seat or seat type (aisle, window)" },
    { path: "travel.fee", type: "number", description: "Any extra fee (seat, change, baggage)" },
    { path: "travel.upgrade", type: "boolean", description: "A paid upgrade (an upsell)" }
  ] }
};
VOCABULARIES.personal = { version: "0.1", fields: [
  { path: "personal.email", type: "string", description: "The principal's email address" }, { path: "personal.phone", type: "string", description: "The principal's phone number" },
  { path: "personal.address", type: "string", description: "The principal's postal or delivery address" }, { path: "personal.passport", type: "string", description: "The principal's passport or identity document number" },
  { path: "party.recipient", type: "string", description: "Who receives the data or the action" }
] };
VOCABULARIES.enterprise = { version: "0.1", fields: [
  { path: "enterprise.data_class", type: "string", description: "Classification of the data: public, internal, confidential or restricted" },
  { path: "enterprise.vendor", type: "string", description: "The supplier or vendor" }
] };
export const KNOWN_FIELDS = new Set(Object.values(VOCABULARIES).flatMap((v) => v.fields.map((f) => f.path)));

export type ActionClass = "search" | "cart" | "substitute" | "pay" | "book" | "change" | "cancel" | "communicate" | "other";
type ToolLike = { name: string; description?: string; inputSchema?: unknown; _meta?: Record<string, unknown> };

const NAME_RULES: [RegExp, ActionClass][] = [
  [/(^|[_-])(search|find|list|get|lookup|deals|browse)([_-]|$)/i, "search"], [/(^|[_-])(substitute|replace|swap)([_-]|$)/i, "substitute"],
  [/(^|[_-])(add_to_cart|cart|basket)([_-]|$)|add_to_cart/i, "cart"], [/(^|[_-])(pay|payment|checkout|purchase|charge)([_-]|$)/i, "pay"],
  [/(^|[_-])(book|reserve|hold)([_-]|$)/i, "book"], [/(^|[_-])(change|modify|update|seat|upgrade)([_-]|$)/i, "change"],
  [/(^|[_-])(cancel|refund|void)([_-]|$)/i, "cancel"], [/(^|[_-])(send|email|message|notify|post)([_-]|$)/i, "communicate"]
];
export function actionClass(t: ToolLike): { cls: ActionClass; basis: "declared" | "inferred" } {
  const declared = t._meta?.["io.saktum/action"];
  if (typeof declared === "string") return { cls: declared as ActionClass, basis: "declared" };
  for (const [re, c] of NAME_RULES) if (re.test(t.name)) return { cls: c, basis: "inferred" };
  return { cls: "other", basis: "inferred" };
}

const ARG_RULES: [RegExp, string][] = [
  [/^(amount|total|order_total|price_total|grand_total)$/i, "commerce.order.total"], [/^currency$/i, "commerce.order.currency"],
  [/^(product|product_id|item|sku)$/i, "commerce.item.product"], [/^brand$/i, "commerce.item.brand"], [/^category$/i, "commerce.item.category"],
  [/^(quantity|qty|count)$/i, "commerce.item.quantity"], [/^(price|unit_price)$/i, "commerce.item.unit_price"],
  [/^(substitute_for|replaces|replacement_for)$/i, "commerce.item.substitute_for"], [/^(reference_price|original_price)$/i, "commerce.item.reference_price"],
  [/^(upgrade|premium|upsell)$/i, "commerce.item.upgrade"], [/^(sponsored|promoted)$/i, "commerce.item.sponsored"], [/^(merchant|seller|store)$/i, "commerce.counterparty"],
  [/^(fare|fare_total)$/i, "travel.fare.total"], [/^refundable$/i, "travel.fare.refundable"], [/^(stops|connections|max_stops)$/i, "travel.itinerary.connections"],
  [/^(email|email_address)$/i, "personal.email"], [/^(phone|phone_number|mobile)$/i, "personal.phone"], [/^(address|delivery_address|shipping_address)$/i, "personal.address"],
  [/^(passport|passport_number|id_number|document_number)$/i, "personal.passport"], [/^(recipient|partner|share_with)$/i, "party.recipient"],
  [/^(data_class|classification|sensitivity)$/i, "enterprise.data_class"], [/^(vendor|supplier|payee)$/i, "enterprise.vendor"],
  [/^(arrive_by|arrival)$/i, "travel.itinerary.arrive_by"], [/^(carrier|airline)$/i, "travel.carrier"], [/^seat$/i, "travel.seat"], [/^(fee|seat_fee|change_fee)$/i, "travel.fee"]
];
/** Argument-to-field bindings for a tool: declared by the publisher, else proposed from argument names. */
export function bindingsFor(t: ToolLike): { bindings: Record<string, string>; basis: "declared" | "inferred" } {
  const declared = t._meta?.["io.saktum/bindings"];
  if (declared && typeof declared === "object") return { bindings: Object.fromEntries(Object.entries(declared as Record<string, string>).filter(([, f]) => KNOWN_FIELDS.has(f))), basis: "declared" };
  const props = Object.keys(((t.inputSchema ?? {}) as { properties?: Record<string, unknown> }).properties ?? {});
  const domainHint = /flight|seat|fare|trip|travel|hotel/i.test(`${t.name} ${t.description ?? ""}`) ? "travel" : "commerce";
  const out: Record<string, string> = {};
  for (const p of props) for (const [re, f] of ARG_RULES) if (re.test(p)) {
    out[p] = domainHint === "travel" && f === "commerce.order.total" ? "travel.fare.total" : domainHint === "travel" && f === "commerce.order.currency" ? "travel.fare.currency" : f; break;
  }
  return { bindings: out, basis: "inferred" };
}
/** The call's values in domain terms. */
export function semanticValues(t: ToolLike, args: Record<string, unknown>): Record<string, unknown> {
  const { bindings } = bindingsFor(t);
  return Object.fromEntries(Object.entries(bindings).filter(([a]) => args[a] !== undefined).map(([a, f]) => [f, args[a]]));
}
