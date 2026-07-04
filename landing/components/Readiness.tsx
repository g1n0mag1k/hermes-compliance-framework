/* ---------------------------------------------------------------------------
 * Readiness — PHI AI Readiness Assessment. $750 flat, 5-day turnaround.
 * Sits between Pricing and the pilot CTA.
 * ------------------------------------------------------------------------- */

export function Readiness() {
  return (
    <section
      data-section="readiness"
      id="readiness"
      className="px-6 sm:px-8 lg:px-10 py-section border-t-2 border-border"
    >
      <div className="w-full max-w-content mx-auto">

        <p className="font-mono text-mono text-signal uppercase tracking-[0.1em]">
          Know your exposure before your insurer asks
        </p>

        <h2 className="font-display text-h2 text-ink mt-8 max-w-[28ch]">
          PHI AI Readiness Assessment
        </h2>

        <p className="font-body text-body text-muted mt-6 max-w-[58ch]">
          A written gap analysis of your current AI tooling against the
          45 CFR §164.514(b) Safe Harbor standard — with remediation
          priorities and an attestation readiness score your insurer or
          auditor can read. Delivered in five business days. The $750 fee
          applies in full toward the pilot if you proceed.
        </p>

        <ul className="mt-10 flex flex-col gap-3 max-w-[560px]">
          {[
            "Gap analysis against 45 CFR §164.514(b) Safe Harbor — all 18 identifier categories",
            "Remediation priorities ranked by enforcement exposure, not theoretical risk",
            "Attestation readiness score formatted for cyber insurers and OCR auditors",
            "Written report delivered within five business days of intake",
            "$750 fee credited in full toward the pilot program if you proceed",
          ].map((item) => (
            <li key={item} className="flex items-start gap-3 font-mono text-[12px] text-muted">
              <span className="text-signal mt-0.5 shrink-0">{"→"}</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>

        <div className="mt-12 bg-signal-dim border-l-2 border-signal px-8 py-7 max-w-[640px]">
          <p className="font-body text-body text-ink">
            The process: you complete a 15-minute intake questionnaire covering
            your current AI tooling, PHI workflows, and existing controls.
            Andrew reviews it against the Safe Harbor standard and delivers
            a written report. No calls required unless you want one.
          </p>
        </div>

        <div className="mt-10 flex flex-col sm:flex-row items-start sm:items-center gap-6">
          <div className="flex flex-col">
            <div className="flex items-baseline gap-3">
              <span className="font-display text-h1 text-ink">$750</span>
              <span className="font-mono text-mono text-muted">flat fee</span>
            </div>
            <span className="font-mono text-caption text-muted mt-1">
              5-day turnaround · credited toward pilot
            </span>
          </div>

          <div className="flex flex-col gap-2">
            <a
              href="mailto:andrew@hermesrelay.dev?subject=PHI AI Readiness Assessment"
              className="inline-block bg-signal text-void font-display font-bold text-body px-8 py-4 border-2 border-signal hover:bg-ink hover:border-ink transition-colors"
            >
              Book an Assessment
            </a>
            <span className="font-mono text-caption text-muted">
              or email directly:{" "}
              <a
                href="mailto:andrew@hermesrelay.dev"
                className="text-signal hover:text-ink transition-colors"
              >
                andrew@hermesrelay.dev
              </a>
            </span>
          </div>
        </div>

      </div>
    </section>
  );
}
