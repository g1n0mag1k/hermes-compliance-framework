/* ---------------------------------------------------------------------------
 * Founder — establishes who built Hermes and why the "direct access to the
 * engineer" claim in Pricing is backed by something concrete.
 * ------------------------------------------------------------------------- */

import Image from "next/image";

export function Founder() {
  return (
    <section
      data-section="founder"
      className="px-6 sm:px-8 lg:px-10 py-section border-t-2 border-border"
    >
      <div className="w-full max-w-content mx-auto">

        <p className="font-mono text-mono text-muted uppercase tracking-[0.1em]">
          Who built this
        </p>
        <h2 className="font-display text-h2 text-ink mt-8 max-w-[26ch]">
          Compliance background first.
          <br />
          Engineering second.
          <br />
          That order matters.
        </h2>

        <div className="mt-16 grid gap-10 md:grid-cols-[minmax(0,220px)_minmax(0,1fr)] md:gap-16 items-start">

          <div className="flex flex-col gap-4">
            <div className="w-full aspect-square border-2 border-border bg-surface overflow-hidden">
              <Image
                src="/andrew-rogers.jpg"
                alt="Andrew Rogers, Founder & Engineer at Hermes Relay"
                width={440}
                height={440}
                className="w-full h-full object-cover"
              />
            </div>
            <div className="flex flex-col gap-1">
              <span className="font-display font-bold text-ink">Andrew Rogers</span>
              <span className="font-mono text-caption text-muted">Founder &amp; Engineer</span>
            </div>
          </div>

          <div className="flex flex-col gap-5">
            <p className="font-body text-body text-ink">
              Before writing a line of Hermes, I spent years in manufacturing
              and construction trades, then moved into systems engineering —
              building self-directed expertise in HIPAA, DSCSA, 21 CFR Part 11,
              ALCOA+, and GAMP 5 through hands-on pharmaceutical supply chain
              compliance work, not a classroom.
            </p>
            <p className="font-body text-body text-muted">
              That order — regulatory depth before the code — is why Hermes is
              built the way it is. The CFR citations attached to every scrubbing
              decision aren&apos;t decorative. They come from actually having sat
              with the standard long enough to know which subsection applies to
              which identifier, in the same way a compliance officer would.
            </p>
            <p className="font-body text-body text-muted">
              Hermes is built and operated by one person. When you request a
              pilot, the person who architected the attestation chain is the
              person on the call.
            </p>
          </div>

        </div>

      </div>
    </section>
  );
}
