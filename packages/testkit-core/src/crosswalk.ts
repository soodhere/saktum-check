// v0.9: Saktum's evidence mapped to the frameworks organisations are held to. Saktum SUPPORTS EVIDENCE for these
// obligations; it never establishes compliance, which depends on the organisation's own assessment (and, for the EU AI
// Act, on whether a system is high-risk). Coverage is stated honestly: covered, partly covered, or not covered.
export type Coverage = "covered" | "partial" | "gap";
export interface CrosswalkItem { ref: string; obligation: string; coverage: Coverage; evidence: string; commands: string[] }
export interface Framework { id: string; name: string; note: string; items: CrosswalkItem[] }

const I = (ref: string, obligation: string, coverage: Coverage, evidence: string, commands: string[]): CrosswalkItem => ({ ref, obligation, coverage, evidence, commands });

export const FRAMEWORKS: Framework[] = [
  { id: "eu-ai-act", name: "EU AI Act", note: "Most obligations apply to high-risk AI systems; whether a system is high-risk is the organisation's assessment.", items: [
    I("Art. 9", "Risk management", "partial", "Risk tiers R0\u2013R4 for servers and agents, policy ceilings, the executive assessment", ["saktum check", "saktum assess"]),
    I("Art. 12", "Record-keeping (automatic logging)", "covered", "Signed, hash-chained receipts of every agent tool call, with the decision and its reason", ["saktum proxy", "saktum receipts verify"]),
    I("Art. 13", "Transparency and information to deployers", "partial", "Passports, manifests and plain-language mandates", ["saktum passport", "saktum manifest create"]),
    I("Art. 14", "Human oversight", "covered", "Autonomy levels, signed approvals of exact actions, revocation (the stop button)", ["saktum agent approve", "saktum agent revoke"]),
    I("Art. 15", "Accuracy, robustness and cybersecurity", "partial", "Conformance and security checks of tools; containment of manipulated agents by mandates (not model accuracy)", ["saktum check", "saktum demo"]),
    I("Art. 26", "Obligations of deployers (monitoring, logs)", "covered", "Monitoring of approved tools, receipts retained by the deployer, OpenTelemetry export", ["saktum watch", "saktum receipts export --otel"]),
    I("Art. 50", "Transparency for certain AI systems", "gap", "Not in scope: disclosure to people interacting with AI is the deployer's interface", [])] },
  { id: "nist-ai-rmf", name: "NIST AI RMF 1.0", note: "Voluntary framework; functions Govern, Map, Measure, Manage.", items: [
    I("GOVERN", "Policies, accountability, third-party risk", "covered", "Policy as code with exceptions; identity chains to accountable people and organisations; operator countersignatures", ["saktum fleet --policy", "saktum identity verify"]),
    I("MAP", "Context, inventory and risk categorisation", "partial", "Inventory of MCP servers across machines, capability profiles, risk tiers (agent inventory planned)", ["saktum scan-config", "saktum fleet"]),
    I("MEASURE", "Testing, evaluation and monitoring", "partial", "Conformance, security, functional and readiness checks; track records from receipts (no model evaluation)", ["saktum check", "saktum kpi"]),
    I("MANAGE", "Risk treatment, response and recovery", "covered", "Mandates, approvals, allowlists, monitoring alerts, revocation", ["saktum allowlist", "saktum watch", "saktum agent revoke"])] },
  { id: "iso-42001", name: "ISO/IEC 42001", note: "AI management system standard; certification is by accredited bodies.", items: [
    I("6.1", "Actions to address risks and opportunities", "partial", "Risk tiers, policy, assessment with recommendations", ["saktum assess"]),
    I("8", "Operation: planning and control", "covered", "Mandates and agreements enforced before every call", ["saktum proxy --enforce"]),
    I("9.1", "Monitoring, measurement, analysis and evaluation", "covered", "Receipts, KPIs, usage statements, monitoring", ["saktum kpi", "saktum usage", "saktum watch"]),
    I("9.2", "Internal audit", "partial", "Independently verifiable ledger, receipts and passports for auditors", ["saktum ledger verify", "saktum receipts verify"]),
    I("A.10", "Third-party and customer relationships", "covered", "Passports, manifests, signed agreements, Verifiable Credentials", ["saktum attest --vc", "saktum agreement verify"])] },
  { id: "owasp-llm", name: "OWASP Top 10 for LLM Applications (2025)", note: "Mapped for agents' tool use; model-level risks are out of scope.", items: [
    I("LLM01", "Prompt injection", "partial", "Hidden-instruction checks on tools; mandates contain a manipulated agent (detection inside models is out of scope)", ["saktum check", "saktum demo"]),
    I("LLM02", "Sensitive information disclosure", "partial", "Personal and classified data enforced per recipient; secrets never printed; argument digests only", ["saktum proxy --enforce"]),
    I("LLM03", "Supply chain", "covered", "Provenance and install-script checks, maturity levels, SBOMs, the census", ["saktum check", "saktum passport"]),
    I("LLM06", "Excessive agency", "covered", "Least-privilege mandates, autonomy levels, approvals, revocation", ["saktum agent create --intent", "saktum agent approve"]),
    I("LLM10", "Unbounded consumption", "covered", "Daily limits, prepaid token metering, context-cost and ROI analysis", ["saktum proxy --wallet", "saktum roi"])] },
  { id: "dora-nis2", name: "DORA and NIS2", note: "EU financial-sector (DORA) and critical-sector (NIS2) resilience rules.", items: [
    I("DORA Art. 28", "ICT third-party risk and the register of information", "partial", "Inventory of AI tools, passports, agreements, monitoring of third-party servers", ["saktum fleet", "saktum watch"]),
    I("NIS2 Art. 21", "Risk-management measures incl. supply-chain security", "partial", "Supply-chain checks, allowlists pinned to tool fingerprints, incident evidence", ["saktum allowlist", "saktum check"])] },
  { id: "gdpr-dpdp", name: "GDPR and India's DPDP Act", note: "Data protection; lawful basis and notices are the controller's responsibility.", items: [
    I("GDPR Art. 5(1)(b)", "Purpose limitation", "partial", "Mandates state the purpose; personal data goes only to permitted recipients", ["saktum agent create --intent"]),
    I("GDPR Art. 30", "Records of processing", "partial", "Receipts record which personal-data fields went to whom (digests, not values)", ["saktum receipts summary"]),
    I("GDPR Art. 32 / DPDP", "Security of processing; reasonable safeguards", "partial", "Enforcement before each call, signed evidence, revocation", ["saktum proxy --enforce"])] }
];

export function crosswalk(id = "all"): Framework[] { return id === "all" ? FRAMEWORKS : FRAMEWORKS.filter((f) => f.id === id); }
export function coverageSummary(f: Framework) { const n = (c: Coverage) => f.items.filter((i) => i.coverage === c).length; return { covered: n("covered"), partial: n("partial"), gap: n("gap"), total: f.items.length }; }
export const DISCLAIMER = "Saktum supports evidence for these obligations; it does not establish compliance, which depends on your own assessment and advisers.";
