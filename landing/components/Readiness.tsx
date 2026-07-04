/* ---------------------------------------------------------------------------
 * Readiness — PHI AI Readiness Assessment. $750 flat, 5-day turnaround.
 * Sits between Pricing and the pilot CTA.
 * ------------------------------------------------------------------------- */

export function Readiness() {
  return (
    <section
      data-section="readiness"
      className="px-6 sm:px-8 lg:px-10 py-section border-t border-border"
    >
      <div className="w-full max-w-content mx-auto">
        <p className="font-mono text-mono text-muted uppercase tracking-[0.1em]">
          Not ready for a full pilot?
        </p>
        <h2 className="font-display text-h2 text-ink mt-8 max-w-[28ch]">
          PHI AI Readiness Assessment
        </h2>
        <p className="font-body text-body text-muted mt-6 max-w-[58ch]">
          Before committing to a pilot, understand exactly where you stand.
          You receive a written gap analysis, remediation priorities, and an
          attestation readiness score your insurer or auditor can read —
          delivered in five business days.
        </p>

        <ul className="mt-10 flex flex-col gap-3 max-w-[520px]">
          {[
            "Written gap analysis against 45 CFR §164.514(b) Safe Harbor",
            "Remediation priorities ranked by risk exposure",
            "Attestation readiness score formatted for insurers and auditors",
            "Five business day turnaround — flat fee, no hourly billing",
          ].map((item) => (
            <li key={item} className="flex items-start gap-3 font-mono text-[12px] text-muted">
              <span className="text-signal mt-0.5 shrink-0">{"→"}</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>

        <div className="mt-10 flex flex-col sm:flex-row items-start sm:items-center gap-6">
          <div>
            <span className="font-display text-h1 text-ink">$750</span>
            <span className="font-mono text-mono text-muted ml-3">flat fee</span>
          </div>
          
            href="mailto:andrew@hermesrelay.dev?subject=PHI AI Readiness Assessment"
            className="inline-block bg-signal text-void font-display font-bold text-body px-8 py-4 border-2 border-signal hover:bg-ink hover:border-ink transition-colors"
          >
            Book an Assessment
          </a>
        </div>
      </div>
    </section>
  );
}
