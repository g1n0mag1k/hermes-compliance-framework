/* ---------------------------------------------------------------------------
 * Differentiators -- three structural advantages framed as an argument, not
 * a feature list. Each differentiator is a full-width block with:
 *
 *   - A terminal-style index prefix (01 / 02 / 03) in text-signal
 *   - A bold category label naming the advantage
 *   - A one-line verdict in text-ink -- the claim in its sharpest form
 *   - Body copy that makes the argument precisely
 *   - A left border in border-signal (Hermes side) vs border-border
 *     (competitor framing embedded in copy)
 *
 * The section closes with a single line that lands the competitive argument
 * before the next section begins.
 *
 * Layout: single-column on mobile, two-column (index+label / verdict+body)
 * on md+. The 2px left border on each block runs the full height of the
 * content, so the signal color reads as a structural rail, not decoration.
 * --------------------------------------------------------------------------- */

type Differentiator = {
  index: string;
  label: string;
  verdict: string;
  body: string;
};

const DIFFERENTIATORS: readonly Differentiator[] = [
  {
    index: "01",
    label: "Zero-Egress Architecture",
    verdict: "Your PHI never leaves your environment. Every competitor's does.",
    body:
      "Nightfall, Strac, Private AI, AWS Comprehend Medical, Azure Text Analytics -- all transit PHI through external infrastructure to classify it. That transit is the violation. Their compliance attestation is technically a false statement: data left the environment to produce it. Hermes runs entirely inside the customer's environment. No external classifier. No data in transit. Every attestation Hermes produces is legally accurate in a way no cloud-ML competitor can match.",
  },
  {
    index: "02",
    label: "Deterministic, CFR-Cited Audit Trail",
    verdict: "Every token. Every citation. Every block. Cryptographically sealed.",
    body:
      "ML classifiers are powerful and non-deterministic. The same input can produce different outputs on different runs. There is no per-token record. There is no CFR citation attached to each decision. There is no cryptographic proof the log was not tampered with after the fact. Hermes produces a SHA-256 hash-chained, per-token, CFR-cited record of every single scrubbing decision. An OCR investigator can verify it byte-by-byte. No competitor -- open-source or commercial -- can make that statement.",
  },
  {
    index: "03",
    label: "Built for MSPs and SMB Healthcare",
    verdict: "The customers who need this most are the ones no competitor serves.",
    body:
      "Nightfall costs $20,000-$60,000 per year and requires enterprise procurement, a security team, and a multi-month sales cycle. The 10-person billing company in Knoxville, the regional clinic, the MSP managing 15 HIPAA-covered clients -- none of them will ever see a Nightfall contract. Hermes is priced, packaged, and deployed for exactly those customers. Self-hostable. Operational in a week. No enterprise contract, no security team required.",
  },
];

function DifferentiatorBlock({ diff }: { diff: Differentiator }) {
  return (
    <div className="border-t-2 border-border pt-10 pb-12">
      <div className="grid gap-8 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)] md:gap-16">
        {/* ---- LEFT: index + label ---- */}
        <div className="flex flex-col gap-3">
          <span className="font-mono text-mono text-signal uppercase tracking-[0.12em]">
            {diff.index}
          </span>
          <h3 className="font-display text-h3 text-ink">
            {diff.label}
          </h3>
        </div>

        {/* ---- RIGHT: verdict + body, signal rail on left ---- */}
        <div className="border-l-2 border-signal pl-6 flex flex-col gap-4">
          <p className="font-display font-semibold text-ink leading-snug text-[1.0625rem]">
            {diff.verdict}
          </p>
          <p className="font-body text-body text-muted">
            {diff.body}
          </p>
        </div>
      </div>
    </div>
  );
}

export function Differentiators() {
  return (
    <section
      data-section="differentiators"
      className="px-6 sm:px-8 lg:px-10 py-section"
    >
      <div className="w-full max-w-content mx-auto">

        {/* ---- Section header ---- */}
        <p className="font-mono text-mono text-signal uppercase tracking-[0.1em]">
          Structural differentiation
        </p>
        <h2 className="font-display text-h2 text-ink mt-8 max-w-[26ch]">
          Three things competitors
          <br />
          cannot replicate without
          <br />
          rebuilding from scratch.
        </h2>

        {/* ---- Differentiator blocks ---- */}
        <div className="mt-16 flex flex-col">
          {DIFFERENTIATORS.map((diff) => (
            <DifferentiatorBlock key={diff.index} diff={diff} />
          ))}
        </div>

        {/* ---- Closing statement ---- */}
        <div className="border-t-2 border-border pt-10 mt-2">
          <p className="font-mono text-mono text-muted max-w-[72ch]">
            <span className="text-signal">-></span>{" "}
            No funded competitor produces token-level, CFR-cited,
            cryptographically-signed scrubbing decision records.
            That is not a roadmap gap. It is an architectural one.
          </p>
        </div>

      </div>
    </section>
  );
}
