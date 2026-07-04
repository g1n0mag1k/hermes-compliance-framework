/* ---------------------------------------------------------------------------
 * Architecture — technical deployment diagram in prose + spec table.
 * Answers the question every MSP's technical contact will ask:
 * "What actually runs, where, and what does it touch?"
 * ------------------------------------------------------------------------- */

const SPECS: readonly { label: string; value: string }[] = [
  { label: "Deployment target", value: "Customer environment — Docker, bare metal, or VM" },
  { label: "External network calls", value: "None during scrubbing. Zero-egress by design." },
  { label: "Detection method", value: "Regex + fixed-version spaCy NER + Microsoft Presidio" },
  { label: "PHI categories covered", value: "8 of 18 Safe Harbor identifiers today — expanding" },
  { label: "Audit record format", value: "SHA-256 hash-chained JSON — independently verifiable" },
  { label: "CFR citation per token", value: "Yes — 45 CFR §164.514(b)(2)(i) subcategory attached" },
  { label: "LLM dependency", value: "None. Deterministic pipeline only." },
  { label: "Signing", value: "HMAC-SHA256 per audit record — HERMES_SIGNING_KEY" },
  { label: "API surface", value: "REST — /v1/scrub, /v1/attest, /v1/health" },
  { label: "Language / runtime", value: "Python 3.12 — uvicorn ASGI" },
];

export function Architecture() {
  return (
    <section
      data-section="architecture"
      className="px-6 sm:px-8 lg:px-10 py-section border-t-2 border-border"
    >
      <div className="w-full max-w-content mx-auto">

        <p className="font-mono text-mono text-muted uppercase tracking-[0.1em]">
          Technical architecture
        </p>
        <h2 className="font-display text-h2 text-ink mt-8 max-w-[26ch]">
          What runs. Where it runs.
          <br />
          What it touches.
        </h2>
        <p className="font-body text-body text-muted mt-6 max-w-[58ch]">
          Hermes deploys as a single Python service inside the customer
          environment. No external classifier. No data in transit. The
          scrubbing pipeline is fully deterministic — the same input
          produces the same output, every run, with a cryptographic record
          to prove it.
        </p>

        <div className="mt-16 border-2 border-border">
          <div className="border-b-2 border-border px-6 py-4">
            <span className="font-mono text-mono text-signal uppercase tracking-[0.1em]">
              Deployment specification
            </span>
          </div>
          <div className="divide-y-2 divide-border">
            {SPECS.map((spec) => (
              <div
                key={spec.label}
                className="grid md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)] px-6 py-4 gap-2 md:gap-8"
              >
                <span className="font-mono text-caption text-muted uppercase tracking-[0.05em]">
                  {spec.label}
                </span>
                <span className="font-mono text-caption text-ink">
                  {spec.value}
                </span>
              </div>
            ))}
          </div>
        </div>

        <p className="font-mono text-caption text-muted mt-6">
          {"→"} Full technical documentation and API reference available to pilot partners upon request.
        </p>

      </div>
    </section>
  );
}
