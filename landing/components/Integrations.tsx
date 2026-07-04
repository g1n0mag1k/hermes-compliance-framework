/* ---------------------------------------------------------------------------
 * Integrations -- vendor-agnostic positioning section.
 *
 * The argument: Hermes is not a competitor to your existing DLP or SIEM.
 * It is the deterministic PHI layer none of them can provide internally.
 * It exports clean, hash-chained evidence into whatever the customer already
 * runs -- Splunk, Sentinel, Purview, Datadog, or any webhook-capable platform.
 *
 * Layout: eyebrow + headline + subhead, then a two-column grid of integration
 * targets, then a closing note on the architecture. Each integration block
 * shows the platform category, a one-line role description, and a mono
 * status badge showing the integration method. No logos -- no licensing
 * surface, no maintenance burden, and logos would soften the technical tone.
 * --------------------------------------------------------------------------- */

type Integration = {
  category: string;
  platforms: string;
  role: string;
  method: string;
};

const INTEGRATIONS: readonly Integration[] = [
  {
    category: "Generic Webhook Export",
    platforms: "Any HTTP JSON webhook receiver",
    role: "Every scrubbing decision fires a structured JSON event to a URL you configure, with an optional auth header for token-based intake. This is a real, tested capability today -- not a mockup.",
    method: "POST + configurable auth header",
  },
  {
    category: "Splunk (HTTP Event Collector)",
    platforms: "Splunk Cloud - Splunk Enterprise",
    role: "Point the webhook at your HEC endpoint and set the auth header to your HEC token. Every scrub call lands as a structured event -- CFR citation, field type, hash chain ID, timestamp -- with no custom parser required.",
    method: "HEC-compatible JSON POST",
  },
  {
    category: "SIEM / DLP -- Broader Landscape",
    platforms: "Datadog - CrowdStrike - Azure Sentinel - Purview - Netskope - Zscaler",
    role: "Platforms that accept a generic webhook or HTTP intake can consume Hermes' event stream today. Platforms requiring signed requests -- Sentinel's Data Collector API, for example -- are not yet supported; that is roadmap work, not a shipped connector.",
    method: "Compatible where webhook intake exists",
  },
  {
    category: "AI Pipelines",
    platforms: "OpenAI - Azure OpenAI - Anthropic - Any LLM endpoint",
    role: "Call /v1/scrub before your LLM request in your own pipeline code. Core identifiers are scrubbed and the audit record is sealed before payload content reaches the model. Today this is a direct API call you wire in, not an automatic transparent proxy.",
    method: "Direct API call, ahead of your LLM request",
  },
];

function IntegrationBlock({ integration }: { integration: Integration }) {
  return (
    <div className="border-2 border-border bg-surface p-6 flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <span className="font-mono text-mono text-signal uppercase tracking-[0.1em]">
          {integration.category}
        </span>
        <p className="font-mono text-caption text-muted">
          {integration.platforms}
        </p>
      </div>
      <p className="font-body text-body text-muted flex-1">
        {integration.role}
      </p>
      <div className="border-t border-border pt-4">
        <span className="font-mono text-caption text-verify">
          {"-> "}{integration.method}
        </span>
      </div>
    </div>
  );
}

export function Integrations() {
  return (
    <section
      data-section="integrations"
      className="px-6 sm:px-8 lg:px-10 py-section"
    >
      <div className="w-full max-w-content mx-auto">

        {/* ---- Section header ---- */}
        <p className="font-mono text-mono text-signal uppercase tracking-[0.1em]">
          Vendor-agnostic architecture
        </p>
        <h2 className="font-display text-h2 text-ink mt-8 max-w-[28ch]">
          Hermes is not a replacement
          <br />
          for your stack. It is the layer
          <br />
          your stack cannot provide.
        </h2>
        <p className="font-body text-body text-muted mt-6 max-w-[60ch]">
          No DLP platform -- Purview, Netskope, Nightfall -- can produce a
          zero-egress, deterministic, CFR-cited audit record on its own.
          Hermes fills that gap and exports the evidence as a generic JSON
          webhook, ready for anything that accepts one today, with
          platform-specific connectors as ongoing work.
        </p>

        {/* ---- Integration grid ---- */}
        <div className="mt-16 grid gap-4 md:grid-cols-2">
          {INTEGRATIONS.map((integration) => (
            <IntegrationBlock
              key={integration.category}
              integration={integration}
            />
          ))}
        </div>

        {/* ---- Closing architecture note ---- */}
        <div className="mt-10 border-t-2 border-border pt-10">
          <div className="grid gap-6 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)] md:gap-16">
            <div className="flex flex-col gap-2">
              <span className="font-mono text-mono text-signal uppercase tracking-[0.1em]">
                How it works
              </span>
              <p className="font-display font-semibold text-ink text-[1.0625rem] leading-snug">
                One generic JSON event exporter. Any destination.
              </p>
            </div>
            <p className="font-body text-body text-muted">
              Hermes emits a structured event for every scrubbing decision:
              field type, CFR citation, hash chain ID, payload ID, and
              timestamp. That event is platform-agnostic JSON over a
              configurable webhook, with an optional auth header for
              token-based intake like Splunk&apos;s HTTP Event Collector.
              Platforms requiring signed requests are on the roadmap,
              not yet shipped.
            </p>
          </div>
        </div>

      </div>
    </section>
  );
}
