import { Hero } from "@/components/Hero";
import { Problem } from "@/components/Problem";
import { Solution } from "@/components/Solution";
import { AuditChain } from "@/components/AuditChain";
import { Architecture } from "@/components/Architecture";
import { Differentiators } from "@/components/Differentiators";
import { Integrations } from "@/components/Integrations";
import { SocialProof } from "@/components/SocialProof";
import { Pricing } from "@/components/Pricing";
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
      <Integrations />
      <SocialProof />
      <Pricing />
      <CTA />
      <Footer />
    </main>
  );
}
