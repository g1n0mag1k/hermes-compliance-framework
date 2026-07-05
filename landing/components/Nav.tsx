/* ---------------------------------------------------------------------------
 * Nav -- sticky top navigation. Pure CSS sticky positioning, no client-side
 * JS -- just anchor links to existing section IDs, plus a persistent
 * pilot-request CTA so a returning evaluator never has to scroll to act.
 * ------------------------------------------------------------------------- */

const LINKS: readonly { label: string; href: string }[] = [
  { label: "How it works", href: "#audit-chain" },
  { label: "Pricing", href: "#pricing" },
  { label: "Assessment", href: "#readiness" },
  { label: "FAQ", href: "#faq" },
];

export function Nav() {
  return (
    <header className="sticky top-0 z-50 bg-void/95 backdrop-blur border-b-2 border-border">
      <div className="w-full max-w-content mx-auto px-6 sm:px-8 lg:px-10 h-16 flex items-center justify-between">
        <a href="#top" className="font-display font-bold text-ink text-[1.0625rem] tracking-tight">
          Hermes
        </a>
        <nav className="hidden md:flex items-center gap-8">
          {LINKS.map((link) => (
            
            <a
              key={link.href}
              href={link.href}
              className="font-mono text-caption text-muted uppercase tracking-[0.05em] hover:text-signal transition-colors"
            >
              {link.label}
            </a>
          ))}
        </nav>
        
        <a
          href="#pilot"
          className="bg-signal text-void font-display font-bold text-[13px] px-5 py-2.5 border-2 border-signal hover:bg-ink hover:border-ink transition-colors whitespace-nowrap"
        >
          Request a Pilot
        </a>
      </div>
    </header>
  );
}
