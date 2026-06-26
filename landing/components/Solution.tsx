/* ---------------------------------------------------------------------------
 * Solution — unified "How Hermes Works" section.
 *
 * Combines what would otherwise be two separate sections (Solution +
 * Architecture) into one cohesive block, because the product *is* the
 * architecture. The three pillars line up 1:1 with the three claims in the
 * h2 ("Deterministic. Zero-egress. Court-defensible by design.") so the
 * eye can map headline → evidence at a glance.
 *
 * Layout:
 *   1. Section label (mono, muted, uppercase) — eyebrow.
 *   2. h2 headline (Space Grotesk) split across three lines so each claim
 *      stands alone.
 *   3. Three pillar cards in a horizontal row on desktop, stacked on
 *      mobile. Each card has a 2px signal top border (visually ties them
 *      back to the signal-colored hero ticker chrome), a short mono
 *      label, an h3 headline, and two sentences of body copy.
 * ------------------------------------------------------------------------- */

type Pillar = {
  label: string;
  headline: string;
  body: string;
};

const PILLARS: readonly Pillar[] = [
  {
    label: "ARCHITECTURE",
    headline: "Zero-egress",
    body:
      "Hermes runs entirely inside your environment. PHI never transits external infrastructure — making your attestations technically accurate, not just aspirational.",
  },
  {
    label: "METHOD",
    headline: "Deterministic",
    body:
      "Every classification is driven by rule-based regex and a fixed-version spaCy model — never a hosted LLM. The same input produces the same output, every run, with the same CFR citation attached.",
  },
  {
    label: "EVIDENCE",
    headline: "Court-defensible",
    body:
      "Each decision is recorded as a per-token, CFR-cited event and sealed into a SHA-256 hash chain. The result is an unbroken, tamper-evident record an OCR investigator can verify byte by byte.",
  },
];

function PillarCard({ pillar }: { pillar: Pillar }) {
  return (
    <div className="bg-surface border-t-2 border-signal px-6 py-7 flex flex-col">
      <p className="font-mono text-mono text-signal uppercase tracking-[0.1em]">
        {pillar.label}
      </p>
      <h3 className="font-display text-h3 text-ink mt-5">{pillar.headline}</h3>
      <p className="font-body text-body text-muted mt-4">{pillar.body}</p>
    </div>
  );
}

export function Solution() {
  return (
    <section
      data-section="solution"
      className="px-6 sm:px-8 lg:px-10 py-section"
    >
      <div className="w-full max-w-content mx-auto">
        <p className="font-mono text-mono text-muted uppercase tracking-[0.1em]">
          How Hermes Works
        </p>

        <h2 className="font-display text-h2 text-ink mt-8 max-w-[22ch]">
          Deterministic. Zero-egress.
          <br />
          Court-defensible by design.
        </h2>

        <div className="mt-16 grid gap-6 md:grid-cols-3">
          {PILLARS.map((pillar) => (
            <PillarCard key={pillar.label} pillar={pillar} />
          ))}
        </div>
      </div>
    </section>
  );
}
