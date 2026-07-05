import { Hero } from "@/components/Hero";
import { Problem } from "@/components/Problem";
import { Solution } from "@/components/Solution";
import { AuditChain } from "@/components/AuditChain";
import { Architecture } from "@/components/Architecture";
import { Differentiators } from "@/components/Differentiators";
import { Founder } from "@/components/Founder";
import { Integrations } from "@/components/Integrations";
import { SocialProof } from "@/components/SocialProof";
import { FAQ } from "@/components/FAQ";
import { Pricing } from "@/components/Pricing";
import { Readiness } from "@/components/Readiness";
import { CTA } from "@/components/CTA";
import { Footer } from "@/components/Footer";

export default function Page() {
  return (
    <main className="flex flex-col">
      <Hero />
      <Problem />
      <Solution />
      <AuditChain />
      <Architecture />
      <Differentiators />
      <Founder />
      <Integrations />
      <SocialProof />
      <FAQ />
      <Pricing />
      <Readiness />
      <CTA />
      <Footer />
    </main>
  );
}
