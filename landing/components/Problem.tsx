/* ---------------------------------------------------------------------------
 * Problem — frames the documentation-gap thesis that motivates Hermes.
 *
 * Layout:
 *   1. Section label (mono, muted, uppercase) — eyebrow.
 *   2. h2 headline (Space Grotesk) with hard line breaks for rhythm.
 *   3. Body paragraph (Inter, muted, ~640px measure for readability).
 *   4. Three-column comparison — stacked on mobile, side-by-side on lg.
 *      Each column is a top-bordered card in the warn accent color with a
 *      label, content paragraph, and a mono caption citing the source.
 *   5. Bottom callout — full-width, signal-dim background with a 2px
 *      signal left border, hammering the legal/financial stakes home.
 * ------------------------------------------------------------------------- */

type Column = {
  label: string;
  content: string;
  source: string;
};

const COLUMNS: readonly Column[] = [
  {
    label: "What carriers ask",
    content:
      "Is MFA enforced for privileged access? How many PHI records do you handle? Can you document what was found and how it was handled?",
    source: "Coalition Application Q4, Q6 — verbatim",
  },
  {
    label: "What OCR demands",
    content:
      "Produce documentation of your de-identification method, the specific identifiers found, and the regulatory basis for each classification decision.",
    source: "45 CFR §164.514(b) — Safe Harbor standard",
  },
  {
    label: "What MSPs cannot produce",
    content:
      "A per-token, CFR-cited, cryptographically signed record that proves Safe Harbor compliance was actively maintained — not just assumed.",
    source: "OCR Risk Analysis Initiative — 2026",
  },
];

function ComparisonColumn({ column }: { column: Column }) {
  return (
    <div className="bg-surface border-t-2 border-warn px-6 py-7 flex flex-col">
      <h3 className="font-display text-h3 text-warn">{column.label}</h3>
      <p className="font-body text-body text-ink mt-4">{column.content}</p>
      <p className="font-mono text-caption text-muted mt-6">{column.source}</p>
    </div>
  );
}

export function Problem() {
  return (
    <section
      data-section="problem"
      className="px-6 sm:px-8 lg:px-10 py-section"
    >
      <div className="w-full max-w-content mx-auto">
        <p className="font-mono text-mono text-muted uppercase tracking-[0.1em]">
          The Documentation Gap
        </p>

        <h2 className="font-display text-h2 text-ink mt-8 max-w-[20ch]">
          Every tool detects PHI.
          <br />
          None of them can prove
          <br />
          what they did with it.
        </h2>

        <p className="font-body text-body text-muted mt-8 max-w-[640px]">
          When OCR investigates a business associate, they do not ask whether
          you had a scrubbing tool. They ask you to produce the evidence —
          exactly what was found, under which regulation, by which method, in
          an unbroken chain from scan to audit. Cloud-based competitors run ML
          models that cannot answer that question. Their architecture makes
          honest attestation impossible.
        </p>

        <div className="mt-16 grid gap-6 md:grid-cols-3">
          {COLUMNS.map((column) => (
            <ComparisonColumn key={column.label} column={column} />
          ))}
        </div>

        <div className="mt-12 bg-signal-dim border-l-2 border-signal px-8 py-7">
          <p className="font-body text-body text-ink">
            OCR issued seven resolution agreements against business associates
            in 2025 alone — the highest enforcement total against business
            associates since 2013. For MSPs serving healthcare clients, the
            documentation gap is not a hypothetical compliance problem. It is
            an active enforcement trend.
          </p>
        </div>
      </div>
    </section>
  );
}
