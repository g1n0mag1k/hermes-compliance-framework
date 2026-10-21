import { Footer } from "@/components/Footer";

export default function SecurityPage() {
  return (
    <main className="flex flex-col min-h-screen">
      <section className="px-6 sm:px-8 lg:px-10 py-section flex-1">
        <div className="w-full max-w-content mx-auto max-w-[720px]">
          <p className="font-mono text-mono text-signal uppercase tracking-[0.1em]">Trust</p>
          <h1 className="font-display text-h2 text-ink mt-8">Security</h1>
          <p className="font-mono text-caption text-muted mt-4">Effective: September 2026 · Sui-Generis LLC</p>

          <div className="mt-12 flex flex-col gap-10 font-body text-body text-muted">
            <div>
              <h2 className="font-display text-h3 text-ink mb-4">Architecture &amp; Data Handling</h2>
              <p>
                Hermes Relay is a self-hosted tool that runs in the customer&apos;s environment. Sui-Generis does not receive customer PHI on its infrastructure. After redaction, the gateway forwards traffic to the AI provider the customer configures. Attestation receipts and audit data remain in the customer&apos;s deployment.
              </p>
            </div>
            <div>
              <h2 className="font-display text-h3 text-ink mb-4">Encryption</h2>
              <p>
                All attestation receipts are signed with Ed25519 keys. The vault uses AES-256-GCM encryption. TLS 1.2+ in transit.
              </p>
            </div>
            <div>
              <h2 className="font-display text-h3 text-ink mb-4">Signing Key Integrity</h2>
              <p>
                Each deployment generates its own Ed25519 signing key pair. Keys are non-exportable from the deployment environment by design. Receipt signatures are verifiable without trusting our infrastructure.
              </p>
            </div>
            <div>
              <h2 className="font-display text-h3 text-ink mb-4">Vulnerability Disclosure</h2>
              <p>
                Responsible disclosure contact:{" "}
                <a href="mailto:andrew@hermesrelay.dev" className="text-signal hover:text-ink transition-colors">
                  andrew@hermesrelay.dev
                </a>
                . We aim to respond within 48 hours.
              </p>
            </div>
            <div>
              <h2 className="font-display text-h3 text-ink mb-4">SOC 2</h2>
              <p>
                Sui-Generis does not currently hold a SOC 2 report. Because Hermes is self-hosted, the product does not process customer PHI on Sui-Generis infrastructure.
              </p>
            </div>
            <div>
              <h2 className="font-display text-h3 text-ink mb-4">Privacy Policy</h2>
              <p>
                See our{" "}
                <a href="/privacy" className="text-signal hover:text-ink transition-colors">
                  Privacy Policy
                </a>
                .
              </p>
            </div>
          </div>
        </div>
      </section>
      <Footer />
    </main>
  );
}
