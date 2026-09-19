import { ShieldCheck, Waves } from "lucide-react";
import { GradeMark, Stat } from "./Primitives";

export interface ConfigurationVerdict { score: number | null; grade: string; reason?: string; critical: number; high: number; }
export interface TrafficVerdict { flows: number; mix: number; abstained: number; obfuscated: number; }

export function VerdictPair({ configuration, traffic }: { configuration: ConfigurationVerdict; traffic: TrafficVerdict }) {
  return (
    <section className="grid border-y border-rule lg:grid-cols-2">
      <div className="grid gap-4 py-5 lg:grid-cols-[auto_1fr] lg:pr-6">
        <ShieldCheck aria-hidden="true" className="size-5 text-accent" />
        <div className="grid gap-4 sm:grid-cols-[minmax(10rem,1fr)_repeat(2,auto)]">
          <div><GradeMark score={configuration.score} grade={configuration.grade} />{configuration.reason ? <p className="mt-2 max-w-sm text-sm text-muted">{configuration.reason}</p> : null}</div>
          <Stat label="Critical" value={configuration.critical} />
          <Stat label="High" value={configuration.high} />
        </div>
      </div>
      <div className="grid gap-4 border-t border-rule py-5 lg:grid-cols-[auto_1fr] lg:border-l lg:border-t-0 lg:pl-6">
        <Waves aria-hidden="true" className="size-5 text-accent" />
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
          <Stat label="Traffic verdict" value="ESP" detail="Statistical classifier" />
          <Stat label="Flows" value={traffic.flows} />
          <Stat label="Traffic mix" value={traffic.mix} />
          <Stat label="Abstained" value={traffic.abstained} />
          <Stat label="Traffic shaping" value={traffic.obfuscated ? "Detected" : "Not detected"} />
        </div>
      </div>
    </section>
  );
}
