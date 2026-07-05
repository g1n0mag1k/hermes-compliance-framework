/* ---------------------------------------------------------------------------
 * Pricing — simple two-tier table. Pilot + Production.
 * Positioned before the CTA so buyers see a number before they're asked
 * to request access.
 * ------------------------------------------------------------------------- */

type Tier = {
  label: string;
  price: string;
  period: string;
  description: string;
  items: readonly string[];
  cta: string;
  highlight: boolean;
};

const TIERS: readonly Tier[] = [
  {
    label: "PILOT",
    price: "$2,000",
    period: "30 days",
    description: "Full production deployment in your environment. No shared infrastructure.",
    items: [
      "Zero-egress deployment in your environment",
      "Hash-chained audit trail from day one",
      "SSN, PAN, name, date, phone detection",
      "API key + integration support",
      "Direct access to the engineer who built it",
    ],
    cta: "Request the Pilot",
    highlight: true,
  },
  {
    label: "PRODUCTION",
    price: "$500",
    period: "/ month",
    description: "After pilot. Month-to-month. No enterprise contract required.",
    items: [
      "Everything in Pilot, ongoing",
      "Expanding identifier coverage",
      "CFR citation updates as regulations change",
      "Priority support via direct channel",
    ],
    cta: "Starts after pilot",
    highlight: false,
  },
];

function TierCard({ tier }: { tier: Tier }) {
  return (
    <div className={`flex flex-col px-8 py-8 border-2 ${tier.highlight ? "border-signal bg-surface" : "border-border bg-surface"}`}>
      <p className="font-mono text-mono text-signal uppercase tracking-[0.1em]">{tier.label}</p>
      <div className="mt-5 flex items-baseline gap-2">
        <span className="font-display text-h1 text-ink">{tier.price}</span>
        <span className="font-mono text-mono text-muted">{tier.period}</span>
      </div>
      <p className="font-body text-body text-muted mt-4">{tier.description}</p>
      <ul className="mt-8 flex flex-col gap-3">
        {tier.items.map((item) => (
          <li key={item} className="flex items-start gap-3 font-mono text-[12px] text-muted">
            <span className="text-signal mt-0.5 shrink-0">{"→"}</span>
            <span>{item}</span>
          </li>
        ))}
      </ul>
      <div className="mt-10">
        {tier.highlight ? (
          <a
            href="#pilot"
            className="inline-block w-full text-center bg-signal text-void font-display font-bold text-body px-6 py-4 border-2 border-signal hover:bg-ink hover:border-ink transition-colors"
          >
            {tier.cta}
          </a>
        ) : (
          <p className="font-mono text-mono text-muted text-center border border-border px-6 py-4">
            {tier.cta}
          </p>
        )}
      </div>
    </div>
  );
}

export function Pricing() {
  return (
    <section
      id="pricing"
      data-section="pricing"
      className="px-6 sm:px-8 lg:px-10 py-section"
    >
      <div className="w-full max-w-content mx-auto">
        <p className="font-mono text-mono text-muted uppercase tracking-[0.1em]">Pricing</p>
        <h2 className="font-display text-h2 text-ink mt-8 max-w-[22ch]">
          No enterprise contract.
          <br />
          No security team required.
        </h2>
        <p className="font-body text-body text-muted mt-6 max-w-[55ch]">
          Hermes is built for the MSP managing 15 HIPAA-covered clients and the
          10-person billing company — not the Fortune 500 with a six-month
          procurement cycle.
        </p>

        <div className="mt-16 grid gap-6 md:grid-cols-2 max-w-[800px]">
          {TIERS.map((tier) => (
            <TierCard key={tier.label} tier={tier} />
          ))}
        </div>

        <p className="font-mono text-caption text-muted mt-8">
          {"→"} Pilot pricing is fixed for current design partners. Production pricing locks at pilot rate for the first 12 months.
        </p>
        <p className="font-mono text-caption text-muted mt-3">
          {"→"} Business Associate Agreement (BAA) available upon request. Required for HIPAA-covered deployments.
        </p>
      </div>
    </section>
  );
}
