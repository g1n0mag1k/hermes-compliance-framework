import { Footer } from "@/components/Footer";

export default function PrivacyPage() {
  return (
    <main className="flex flex-col min-h-screen">
      <section className="px-6 sm:px-8 lg:px-10 py-section flex-1">
        <div className="w-full max-w-content mx-auto max-w-[720px]">
          <p className="font-mono text-mono text-signal uppercase tracking-[0.1em]">Legal</p>
          <h1 className="font-display text-h2 text-ink mt-8">Privacy Policy</h1>
          <p className="font-mono text-caption text-muted mt-4">Effective: July 2026 · Sui-Generis LLC</p>

          <div className="mt-12 flex flex-col gap-10 font-body text-body text-muted">
            <div>
              <h2 className="font-display text-h3 text-ink mb-4">What we collect</h2>
              <p>When you submit the pilot request or assessment booking form on this site, we collect your name, company name, and work email address. We do not collect payment information on this site. We do not use tracking pixels, advertising cookies, or behavioral analytics.</p>
            </div>
            <div>
              <h2 className="font-display text-h3 text-ink mb-4">How we use it</h2>
              <p>Your contact information is used solely to respond to your inquiry and administer the pilot or assessment engagement. It is not sold, shared with third parties, or used for marketing without your explicit consent.</p>
            </div>
            <div>
              <h2 className="font-display text-h3 text-ink mb-4">PHI and the Hermes product</h2>
              <p>The Hermes Relay API operates on a zero-egress, zero-PHI-retention architecture. PHI processed through the API never transits or is stored on Sui-Generis LLC infrastructure. Customers deploy Hermes inside their own environment. Sui-Generis LLC does not receive, process, or retain any PHI from customer deployments. Business Associate Agreements are available upon request for HIPAA-covered deployments.</p>
            </div>
            <div>
              <h2 className="font-display text-h3 text-ink mb-4">Cookies</h2>
              <p>This site uses no advertising or tracking cookies. Session-level cookies may be set by the hosting infrastructure (Netlify) for security purposes only.</p>
            </div>
            <div>
              <h2 className="font-display text-h3 text-ink mb-4">Contact</h2>
              <p>Questions about this policy: <a href="mailto:andrew@hermesrelay.dev" className="text-signal hover:text-ink transition-colors">andrew@hermesrelay.dev</a></p>
            </div>
          </div>
        </div>
      </section>
      <Footer />
    </main>
  );
}
