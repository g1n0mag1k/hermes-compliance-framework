/* ---------------------------------------------------------------------------
 * Differentiators — three-row comparison that closes the door on every
 * adjacent category. The argument runs in the same direction each row:
 *
 *   Left column   short bold label naming the category being contrasted
 *   Right column  body copy explaining why that category cannot do what
 *                 Hermes does
 *
 * The first two rows use muted body text (problem framing); the final
 * row — Hermes — uses ink (the answer). A 2px border-border line caps the
 * top of every row, including the first, so the block reads as a single
 * structured table rather than a list of cards.
 * ------------------------------------------------------------------------- */

type Row = {
  label: string;
  body: string;
  /** When true, render body in ink instead of muted — used for the Hermes row. */
  isAnswer?: boolean;
};

const ROWS: readonly Row[] = [
  {
    label: "Cloud-ML competitors",
    body:
      "Nightfall, Strac, Private AI, AWS Comprehend Medical, Azure Text Analytics — all transit your PHI through external infrastructure. They can produce a log. They cannot produce a truthful attestation that data never left your environment. The BAVR they would generate would be a false statement.",
  },
  {
    label: "Open-source alternatives",
    body:
      "Microsoft Presidio, spaCy pipelines, CliniDeID — powerful detection, zero compliance layer. No audit chain, no CFR citations, no BAA support, no evidence artifact. A library is not a compliance system.",
  },
  {
    label: "Hermes",
    body:
      "Deterministic architecture means every decision is explainable. Zero-egress means every attestation is accurate. Hash-chained audit trail means every record is independently verifiable. Built by a founder with genuine HIPAA, DSCSA, and 21 CFR Part 11 regulatory depth — not a checklist.",
    isAnswer: true,
  },
];

function DifferentiatorRow({ row }: { row: Row }) {
  return (
    <div className="grid gap-6 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)] border-t-2 border-border py-8">
      <div className="font-display font-bold text-ink text-h3">
        {row.label}
      </div>
      <p
        className={`font-body text-body ${
          row.isAnswer ? "text-ink" : "text-muted"
        }`}
      >
        {row.body}
      </p>
    </div>
  );
}

export function Differentiators() {
  return (
    <section
      data-section="differentiators"
      className="px-6 sm:px-8 lg:px-10 py-section"
    >
      <div className="w-full max-w-content mx-auto">
        <p className="font-mono text-mono text-muted uppercase tracking-[0.1em]">
          Why competitors cannot replicate this
        </p>

        <h2 className="font-display text-h2 text-ink mt-8 max-w-[22ch]">
          The attestation is only
          <br />
          legally accurate if the
          <br />
          architecture is zero-egress.
        </h2>

        <div className="mt-16 flex flex-col">
          {ROWS.map((row) => (
            <DifferentiatorRow key={row.label} row={row} />
          ))}
        </div>
      </div>
    </section>
  );
}
