/* ---------------------------------------------------------------------------
 * SocialProof — intentionally minimal placeholder while the pilot is in
 * flight. A single full-width strip in the signal-dim accent tint with one
 * centered mono line. Will be replaced with a real case study quote once
 * the East Tennessee MSP pilot is complete.
 * ------------------------------------------------------------------------- */

export function SocialProof() {
  return (
    <section
      data-section="social-proof"
      className="bg-signal-dim px-6 sm:px-8 lg:px-10 py-section"
    >
      <div className="w-full max-w-content mx-auto">
        {/* Replace with case study quote once pilot is complete */}
        <p className="font-mono text-mono text-muted text-center uppercase tracking-[0.1em]">
          Pilot program — East Tennessee MSPs serving HIPAA-covered entities
        </p>
      </div>
    </section>
  );
}
