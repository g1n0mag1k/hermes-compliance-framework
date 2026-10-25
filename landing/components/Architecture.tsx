/* ---------------------------------------------------------------------------
 * Architecture — technical deployment diagram in prose + spec table.
 * Answers the question every buyer's technical contact will ask:
 * "What actually runs, where, and what does it touch?"
 * ------------------------------------------------------------------------- */

const SPECS: readonly { label: string; value: string }[] = [
  { label: "Deployment target", value: "Customer environment — Docker, bare metal, or VM" },
  {
    label: "External network calls",
    value: "None on the /v1/scrub return path. Splunk HEC and other webhooks only when you configure them.",
  },
  { label: "Detection method", value: "Regex + fixed-version spaCy NER + Microsoft Presidio" },
  {
    label: "Coverage",
    value:
      "16 of 18 HIPAA Safe Harbor categories detected in text; biometric identifiers (P) and full-face photos (Q) are reference-only.",
  },
  {
    label: "What a receipt proves",
    value:
      "The receipt body wasn't altered between the runner and whoever verifies it with the same HMAC-SHA256 key.",
  },
  {
    label: "What a receipt does NOT prove",
    value:
      "PHI didn't leave by an untested path (stdout, log agents, trace attributes, dead-letter queues).",
  },
  {
    label: "Egress sinks tested",
    value:
      "Sentry DSN (via before_send) and Splunk HEC webhook when configured. Other sinks not tested unless explicitly configured.",
  },
  {
    label: "Signing",
    value:
      "HMAC-SHA256 over canonical receipt body. Shared signing key — verifier and signer hold the same secret.",
  },
  {
    label: "Time source",
    value: "Host or CI runner clock. Not independently timestamped.",
  },
  {
    label: "Chain integrity",
    value: "Each receipt links the previous receipt's hash; verifier replays the chain.",
  },
  { label: "CFR citation per token", value: "Yes — 45 CFR §164.514(b)(2)(i) subcategory attached" },
  { label: "LLM dependency", value: "None. Deterministic pipeline only." },
  { label: "API surface", value: "REST — /v1/scrub, /v1/review, /v1/status, /v1/workspaces" },
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
          produces the same output, every run, with hash-chained
          HMAC-SHA256 receipts for each run.
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
