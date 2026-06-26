/* ---------------------------------------------------------------------------
 * CTA — single focused conversion section.
 *
 * Full-width void background, centered content, one anchor-tag CTA pointing
 * at the founder's mailto. Trust-signal row sits below the button, mono
 * caption scale, dot-separated, communicating the four most important
 * compliance properties at a glance.
 * ------------------------------------------------------------------------- */

const TRUST_SIGNALS: readonly string[] = [
  "Zero-egress architecture",
  "Data never leaves your environment",
  "SHA-256 independently verifiable",
  "HIPAA Safe Harbor 45 CFR §164.514(b)",
];

export function CTA() {
  return (
    <section
      data-section="cta"
      className="bg-void px-6 sm:px-8 lg:px-10 py-section"
    >
      <div className="w-full max-w-content mx-auto flex flex-col items-center text-center">
        <h2 className="font-display text-h2 text-ink">
          One pilot.
          <br />
          Your environment.
          <br />
          Your audit chain.
        </h2>

        <p className="font-body text-body text-muted mt-8 max-w-[500px]">
          Hermes is currently accepting one design partner in the East
          Tennessee market. 30-day pilot, your infrastructure, full
          compliance evidence record output from day one.
        </p>

        <a
          href="mailto:andrew@hermesrelay.dev"
          className="mt-10 inline-block bg-signal text-void font-display font-bold text-h3 px-10 py-5 border-2 border-signal hover:bg-ink hover:border-ink transition-colors"
        >
          Request the Pilot Program
        </a>

        <p className="font-mono text-caption text-muted mt-10">
          {TRUST_SIGNALS.join("  ·  ")}
        </p>
      </div>
    </section>
  );
}
