/* ---------------------------------------------------------------------------
 * SocialProof — interim enforcement context block while pilot case study
 * is in progress. No fabricated quotes. Regulatory data only.
 * Replace with pilot case study quote once available.
 * ------------------------------------------------------------------------- */

const STATS: readonly { figure: string; label: string; source: string }[] = [
  {
    figure: "7",
    label: "OCR resolution agreements against business associates in 2025 alone",
    source: "HHS Office for Civil Rights — 2025 Enforcement Report",
  },
  {
    figure: "$7.42M",
    label: "Average cost of a healthcare data breach — the costliest industry for the 15th consecutive year",
    source: "IBM Cost of a Data Breach Report 2025",
  },
  {
    figure: "18",
    label: "Safe Harbor identifier categories OCR expects documented per incident",
    source: "45 CFR §164.514(b)(2) — HIPAA Safe Harbor Standard",
  },
];

export function SocialProof() {
  return (
    <section
      data-section="social-proof"
      className="px-6 sm:px-8 lg:px-10 py-section border-t-2 border-border"
    >
      <div className="w-full max-w-content mx-auto">

        <p className="font-mono text-mono text-muted uppercase tracking-[0.1em]">
          The enforcement context
        </p>
        <h2 className="font-display text-h2 text-ink mt-8 max-w-[28ch]">
          The documentation gap has a
          <br />
          dollar figure attached to it.
        </h2>

        <div className="mt-16 grid gap-6 md:grid-cols-3">
          {STATS.map((stat) => (
            <div
              key={stat.figure}
              className="border-t-2 border-signal pt-8 flex flex-col gap-4"
            >
              <span className="font-display text-hero text-signal leading-none">
                {stat.figure}
              </span>
              <p className="font-body text-body text-ink">
                {stat.label}
              </p>
              <p className="font-mono text-caption text-muted mt-auto">
                {stat.source}
              </p>
            </div>
          ))}
        </div>

      </div>
    </section>
  );
}
