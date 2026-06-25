import { Hero } from "@/components/Hero";
import { Problem } from "@/components/Problem";
import { Solution } from "@/components/Solution";
import { Architecture } from "@/components/Architecture";
import { Differentiators } from "@/components/Differentiators";
import { SocialProof } from "@/components/SocialProof";
import { CTA } from "@/components/CTA";
import { Footer } from "@/components/Footer";

export default function Page() {
  return (
    <main className="flex flex-col">
      <Hero />
      <Problem />
      <Solution />
      <Architecture />
      <Differentiators />
      <SocialProof />
      <CTA />
      <Footer />
    </main>
  );
}
