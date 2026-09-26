import { useRef, useState, type DragEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Activity,
  ArrowRight,
  ChevronRight,
  GitCompare,
  Layers,
  LayoutGrid,
  LayoutList,
  Lock,
  Network,
  Play,
  Shield,
  ShieldCheck,
  UploadCloud,
} from "lucide-react";
import RiskBadge from "../components/RiskBadge";
import { analyzeSample, getAnalysisStatus } from "../api/client";
import { saveCaptureContext } from "../lib/capture-session";
import { cn } from "../lib/cn";
import type { RiskLevel } from "../types";

interface TestbedScenarioCard {
  id: string;
  sampleId: string;
  title: string;
  filename: string;
  category: string;
  type: "COMPLIANT" | "VULNERABLE" | "REFERENCE";
  risk: RiskLevel;
  esp: string;
  dh: string;
  score: number;
  grade: string;
  description: string;
}

const TESTBED_SCENARIOS: TestbedScenarioCard[] = [
  {
    id: "scenario_01_hardened",
    sampleId: "scenario_01_hardened",
    title: "RFC 9347 IP-TFS Hardened Tunnel",
    filename: "scenario_01_hardened.pcap",
    category: "CNSA 2.0 / Post-Quantum Ready",
    type: "COMPLIANT",
    risk: "LOW",
    esp: "ChaCha20-Poly1305",
    dh: "Group 31 (Curve25519)",
    score: 100,
    grade: "A",
    description: "Constant packet pacing and dummy burst injection (IP-TFS AGGFRAG) providing full traffic-flow confidentiality.",
  },
  {
    id: "wireshark_ikev2_aes_gcm",
    sampleId: "wireshark_ikev2_aes_gcm",
    title: "Site-to-Site IKEv2 Production Tunnel",
    filename: "wireshark_ikev2_aes_gcm.pcap",
    category: "Compliant Production VPN",
    type: "COMPLIANT",
    risk: "LOW",
    esp: "AES-256-GCM-16",
    dh: "Group 19 (NIST P-256)",
    score: 96,
    grade: "A",
    description: "Standard strongSwan site-to-site IPsec tunnel with modern AEAD AES-GCM and Perfect Forward Secrecy enabled.",
  },
  {
    id: "wireshark_ikev2_multi_suite",
    sampleId: "wireshark_ikev2_multi_suite",
    title: "Multi-Suite IKEv2 Benchmark",
    filename: "wireshark_ikev2_multi_suite.pcapng",
    category: "Multi-Cipher Benchmark",
    type: "COMPLIANT",
    risk: "LOW",
    esp: "AES-GCM / CTR / CBC",
    dh: "Group 19 & Group 14",
    score: 88,
    grade: "B",
    description: "Three consecutive IKEv2 tunnels demonstrating modern AES-GCM, AES-CTR, and legacy AES-CBC over UDP 4500.",
  },
  {
    id: "scenario_04_weak_3des",
    sampleId: "scenario_04_weak_3des",
    title: "Legacy Enterprise (Sweet32 3DES + MD5)",
    filename: "scenario_04_weak_3des.pcap",
    category: "Vulnerable / Deprecated Suite",
    type: "VULNERABLE",
    risk: "CRITICAL",
    esp: "3DES-CBC (64-bit blocks)",
    dh: "Group 2 (1024-bit MODP)",
    score: 25,
    grade: "F",
    description: "Exposed to CVE-2016-2183 Sweet32 collision attacks, weak MD5-HMAC integrity, and missing Perfect Forward Secrecy.",
  },
  {
    id: "wireshark_esp_tunnel_mode",
    sampleId: "wireshark_esp_tunnel_mode",
    title: "High-Volume ESP Flow Trace",
    filename: "wireshark_esp_tunnel_mode.pcap",
    category: "Sustained Tunnel Traffic",
    type: "REFERENCE",
    risk: "INFO",
    esp: "ESP Tunnel Mode",
    dh: "Pre-established SA",
    score: 85,
    grade: "B",
    description: "High packet density capture with rich statistical packet length and inter-arrival time variance for flow analysis.",
  },
  {
    id: "wireshark_http_sample",
    sampleId: "wireshark_http_sample",
    title: "Cleartext External Ingestion Test",
    filename: "wireshark_http_sample.pcap",
    category: "Non-IPsec Reference",
    type: "REFERENCE",
    risk: "INFO",
    esp: "Cleartext HTTP / TCP 80",
    dh: "None (Unencrypted)",
    score: 0,
    grade: "N/A",
    description: "Standard HTTP web traffic demonstrating system robustness and graceful handling of non-IPsec packet streams.",
  },
];

const PIPELINE_FLOW = [
  {
    step: "01",
    name: "Packet Ingestion",
    tech: "dpkt + tshark",
    desc: "Wire-speed extraction of .pcap / .pcapng files across any OS without container overhead.",
  },
  {
    step: "02",
    name: "Handshake Dissection",
    tech: "RFC 7296 · RFC 4303",
    desc: "Parses IKEv2 SA transforms, Diffie-Hellman groups, SPI keys, and SA lifetime boundaries.",
  },
  {
    step: "03",
    name: "Side-Channel Telemetry",
    tech: "FlowDeepNet (25D)",
    desc: "Extracts inter-arrival times, packet size entropy, and burst patterns strictly without IP/port leakage.",
  },
  {
    step: "04",
    name: "Deterministic Audit",
    tech: "RFC 8221 / 8247 & NIST",
    desc: "Evaluates cryptographic suites against authoritative RFC/NIST rules with CVE attack vector mapping.",
  },
  {
    step: "05",
    name: "Remediation & Export",
    tech: "swanctl.conf & PDF",
    desc: "Generates hardened strongSwan configuration policies, ATT&CK mitigations, and PDF audit reports.",
  },
];

export default function Dashboard() {
  const navigate = useNavigate();
  const [analyzingId, setAnalyzingId] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<"ALL" | "COMPLIANT" | "VULNERABLE" | "REFERENCE">("ALL");
  const [viewMode, setViewMode] = useState<"TABLE" | "CARDS">("TABLE");
  const [isDragActive, setIsDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const filteredScenarios = TESTBED_SCENARIOS.filter((sc) => {
    if (filterType === "ALL") return true;
    return sc.type === filterType;
  });

  function handleFileSelected(file: File) {
    navigate("/upload", { state: { preloadedFile: file } });
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setIsDragActive(false);
    const item = e.dataTransfer.files.item(0);
    if (item) handleFileSelected(item);
  }

  function onDragOver(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setIsDragActive(true);
  }

  function onDragLeave(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setIsDragActive(false);
  }

  async function handleQuickAnalyze(sampleId: string) {
    try {
      setAnalyzingId(sampleId);
      const res = await analyzeSample(sampleId);
      saveCaptureContext(res);

      // Wait for pipeline completion so target page renders immediately
      const maxWait = 25;
      for (let i = 0; i < maxWait; i++) {
        await new Promise((r) => setTimeout(r, 400));
        try {
          const st = await getAnalysisStatus(res.capture_id, res.capture_token ?? undefined);
          if (st.status === "DONE" || st.status === "ERROR") break;
        } catch {
          // ignore transient poll error
        }
      }
      navigate(`/compliance/${res.capture_id}`);
    } catch {
      navigate(`/analysis/${sampleId}?demo=1`);
    } finally {
      setAnalyzingId(null);
    }
  }

  return (
    <div className="space-y-12 motion-enter">
      {/* 1. Technical Hero Section with Embedded Intake Dropzone */}
      <section className="border-b border-rule pb-10">
        <div className="grid gap-8 lg:grid-cols-12 lg:items-start">
          {/* Left Column: Mission, Standards, and Action Triggers */}
          <div className="space-y-5 lg:col-span-7">
            <div className="flex items-center gap-2 text-xs text-muted">
              <Shield className="size-3.5 text-accent" aria-hidden="true" />
              <span>Auditing IPsec implementations against RFC 8221, RFC 8247, and NIST SP 800-77 Rev. 1</span>
            </div>

            <div className="space-y-2">
              <h1 className="text-2xl font-bold tracking-tight text-ink sm:text-3xl lg:text-4xl">
                IPsec Protocol Dissection &amp; Flow Telemetry
              </h1>
              <p className="text-sm leading-relaxed text-muted sm:text-base max-w-2xl">
                Deterministic IKEv2/ESP handshake parsing, automated RFC compliance grading, and 25-dimensional statistical side-channel flow classification without IP or port leakage.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <Link
                to="/upload"
                className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-accent px-4 text-xs font-semibold text-white shadow-sm hover:bg-accent-strong transition-all cursor-pointer"
              >
                <UploadCloud className="size-4" aria-hidden="true" />
                <span>Upload &amp; Analyze Capture</span>
              </Link>

              <Link
                to="/analysis/wireshark_ikev2_aes_gcm?demo=1"
                className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-rule bg-surface px-4 text-xs font-semibold text-ink hover:border-accent transition-all cursor-pointer"
              >
                <Activity className="size-4 text-pass" aria-hidden="true" />
                <span>View Demo Evaluation</span>
              </Link>

              <Link
                to="/compare"
                className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-rule bg-surface px-4 text-xs font-semibold text-muted hover:text-ink hover:border-accent transition-all cursor-pointer"
              >
                <GitCompare className="size-4 text-accent" aria-hidden="true" />
                <span>Compare Scenarios</span>
              </Link>

              <Link
                to="/method"
                className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-rule/60 bg-sunken/40 px-3 text-xs font-mono text-muted hover:text-ink hover:border-accent transition-all cursor-pointer"
              >
                <span>Methodology</span>
                <ChevronRight className="size-3" aria-hidden="true" />
              </Link>
            </div>
          </div>

          {/* Right Column: Instant Ingestion Dropzone */}
          <div className="lg:col-span-5">
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng,.cap,.dmp,.dump,.gz"
              className="sr-only"
              tabIndex={-1}
              aria-hidden="true"
              onChange={(e) => {
                const selected = e.target.files?.[0];
                if (selected) handleFileSelected(selected);
              }}
            />

            <div
              onDrop={onDrop}
              onDragOver={onDragOver}
              onDragLeave={onDragLeave}
              onClick={() => fileInputRef.current?.click()}
              className={cn(
                "group relative flex flex-col items-center justify-center border-2 border-dashed p-6 text-center transition-all cursor-pointer",
                isDragActive
                  ? "border-accent bg-accent/10 ring-2 ring-accent/30"
                  : "border-rule bg-sunken/30 hover:border-accent hover:bg-sunken/60"
              )}
            >
              <div className="mb-3 flex size-11 items-center justify-center rounded-lg border border-rule bg-surface text-accent group-hover:scale-105 transition-transform">
                <UploadCloud className="size-5" aria-hidden="true" />
              </div>

              <div className="space-y-1">
                <p className="text-xs font-semibold text-ink sm:text-sm">
                  {isDragActive ? "Drop capture to begin analysis" : "Drop .pcap or .pcapng file here"}
                </p>
                <p className="text-[11px] text-muted font-mono">
                  or click to select file from disk
                </p>
              </div>

              <p className="mt-3 text-[11px] font-mono text-muted">
                Accepts .pcap, .pcapng, and .gz captures (IKEv2 SA, ESP tunnel mode, UDP 4500)
              </p>
            </div>
          </div>
        </div>

        {/* System Capability Telemetry Ribbon: Instrument Layout */}
        <div className="mt-8 grid grid-cols-2 gap-4 border-t border-rule pt-6 sm:grid-cols-4">
          <div className="border-l border-rule pl-3.5 space-y-0.5">
            <h2 className="text-xs font-medium text-muted">Dissection engine</h2>
            <p className="font-mono text-xs font-semibold text-ink">dpkt ESP &amp; tshark JSON</p>
            <p className="text-[11px] text-muted">RFC 7296 and RFC 4303 protocol framing</p>
          </div>

          <div className="border-l border-rule pl-3.5 space-y-0.5">
            <h2 className="text-xs font-medium text-muted">Compliance rules</h2>
            <p className="font-mono text-xs font-semibold text-ink">RFC 8221 / 8247 &amp; NIST SP 800-77</p>
            <p className="text-[11px] text-muted">Deterministic scoring and CVE mapping</p>
          </div>

          <div className="border-l border-rule pl-3.5 space-y-0.5">
            <h2 className="text-xs font-medium text-muted">Statistical classifier</h2>
            <p className="font-mono text-xs font-semibold text-ink">FlowDeepNet 25D Ensemble</p>
            <p className="text-[11px] text-muted">Zero IP and port feature bias</p>
          </div>

          <div className="border-l border-rule pl-3.5 space-y-0.5">
            <h2 className="text-xs font-medium text-muted">Traffic obfuscation</h2>
            <p className="font-mono text-xs font-semibold text-ink">RFC 9347 IP-TFS &amp; AGGFRAG</p>
            <p className="text-[11px] text-muted">Fixed-rate packet padding verification</p>
          </div>
        </div>
      </section>

      {/* 2. Connected Pipeline Sequence Track */}
      <section className="space-y-4">
        <div>
          <h2 className="text-base font-semibold text-ink flex items-center gap-2">
            <Layers className="size-4 text-accent" aria-hidden="true" />
            <span>Dissection &amp; Verification Pipeline</span>
          </h2>
          <p className="text-xs text-muted mt-0.5">
            Five-stage sequential processing from raw wire capture to deterministic RFC compliance scoring and policy remediation.
          </p>
        </div>

        {/* Connected pipeline rail */}
        <div className="relative grid gap-0 border border-rule bg-surface sm:grid-cols-5 divide-y sm:divide-y-0 sm:divide-x divide-rule">
          {PIPELINE_FLOW.map((stage) => (
            <div
              key={stage.step}
              className="p-4 space-y-2.5 hover:bg-sunken/40 transition-colors"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-accent">{stage.step}</span>
                <span className="font-mono text-[11px] text-muted">{stage.tech}</span>
              </div>
              <div>
                <h3 className="text-xs font-bold text-ink">{stage.name}</h3>
                <p className="mt-1 text-[11px] leading-relaxed text-muted">{stage.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 3. Verified Testbed Scenarios (Informative, High-Density Table / Card Matrix) */}
      <section className="space-y-4">
        <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center border-b border-rule pb-3">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-ink">Verified Testbed Scenarios</h2>
              <span className="rounded bg-sunken px-2 py-0.5 font-mono text-xs font-semibold text-muted border border-rule">
                6 Reference Captures
              </span>
            </div>
            <p className="text-xs text-muted mt-0.5">
              Authoritative Wireshark public captures and adversarial scenario traces for benchmark validation.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Filter buttons */}
            <div className="inline-flex rounded-lg border border-rule bg-sunken p-0.5 text-xs font-mono">
              <button
                type="button"
                onClick={() => setFilterType("ALL")}
                className={cn(
                  "px-2.5 py-1 rounded-md transition-colors cursor-pointer",
                  filterType === "ALL" ? "bg-surface text-ink font-semibold shadow-xs" : "text-muted hover:text-ink"
                )}
              >
                All (6)
              </button>
              <button
                type="button"
                onClick={() => setFilterType("COMPLIANT")}
                className={cn(
                  "px-2.5 py-1 rounded-md transition-colors cursor-pointer",
                  filterType === "COMPLIANT" ? "bg-surface text-pass font-semibold shadow-xs" : "text-muted hover:text-ink"
                )}
              >
                Compliant (3)
              </button>
              <button
                type="button"
                onClick={() => setFilterType("VULNERABLE")}
                className={cn(
                  "px-2.5 py-1 rounded-md transition-colors cursor-pointer",
                  filterType === "VULNERABLE" ? "bg-surface text-critical font-semibold shadow-xs" : "text-muted hover:text-ink"
                )}
              >
                Vulnerable (1)
              </button>
              <button
                type="button"
                onClick={() => setFilterType("REFERENCE")}
                className={cn(
                  "px-2.5 py-1 rounded-md transition-colors cursor-pointer",
                  filterType === "REFERENCE" ? "bg-surface text-ink font-semibold shadow-xs" : "text-muted hover:text-ink"
                )}
              >
                Flow Ref (2)
              </button>
            </div>

            {/* View Mode Toggle */}
            <div className="inline-flex rounded-lg border border-rule bg-sunken p-0.5 text-xs">
              <button
                type="button"
                onClick={() => setViewMode("TABLE")}
                className={cn(
                  "p-1.5 rounded-md transition-colors cursor-pointer",
                  viewMode === "TABLE" ? "bg-surface text-ink shadow-xs" : "text-muted hover:text-ink"
                )}
                title="Table View"
                aria-label="Table View"
              >
                <LayoutList className="size-3.5" aria-hidden="true" />
              </button>
              <button
                type="button"
                onClick={() => setViewMode("CARDS")}
                className={cn(
                  "p-1.5 rounded-md transition-colors cursor-pointer",
                  viewMode === "CARDS" ? "bg-surface text-ink shadow-xs" : "text-muted hover:text-ink"
                )}
                title="Card View"
                aria-label="Card View"
              >
                <LayoutGrid className="size-3.5" aria-hidden="true" />
              </button>
            </div>

            <Link
              to="/compare"
              className="inline-flex items-center gap-1 font-mono text-xs font-semibold text-accent hover:underline ml-1"
            >
              <span>Compare Scenarios</span>
              <ArrowRight className="size-3" aria-hidden="true" />
            </Link>
          </div>
        </div>

        {/* View Option 1: High-Density Engineering Table (Default) */}
        {viewMode === "TABLE" ? (
          <div className="overflow-x-auto rounded-xl border border-rule bg-surface shadow-xs">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-rule bg-sunken/60 font-mono text-[11px] text-muted">
                  <th scope="col" className="px-4 py-3 font-semibold">Scenario &amp; Capture Target</th>
                  <th scope="col" className="px-3 py-3 font-semibold">Security Posture</th>
                  <th scope="col" className="px-3 py-3 font-semibold">Cryptographic Transforms</th>
                  <th scope="col" className="px-3 py-3 font-semibold">RFC Verdict</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Key Technical Characteristic</th>
                  <th scope="col" className="px-4 py-3 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-rule font-sans">
                {filteredScenarios.map((sc) => (
                  <tr key={sc.id} className="hover:bg-sunken/30 transition-colors">
                    {/* Scenario details */}
                    <td className="px-4 py-3.5 max-w-xs">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-ink">{sc.title}</span>
                        </div>
                        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
                          <span className="text-muted">{sc.filename}</span>
                          <span className="text-muted/60 font-sans">({sc.category})</span>
                        </div>
                      </div>
                    </td>

                    {/* Posture */}
                    <td className="px-3 py-3.5 whitespace-nowrap">
                      <RiskBadge level={sc.risk} size="sm" />
                    </td>

                    {/* Suite */}
                    <td className="px-3 py-3.5 font-mono text-[11px] text-ink whitespace-nowrap">
                      <div><span className="text-muted">ESP: </span>{sc.esp}</div>
                      <div><span className="text-muted">DH: </span>{sc.dh}</div>
                    </td>

                    {/* Score / Grade */}
                    <td className="px-3 py-3.5 whitespace-nowrap">
                      <div className="flex items-center gap-1.5 font-mono">
                        <span
                          className={cn(
                            "font-bold text-xs px-2 py-0.5 rounded border",
                            sc.score >= 80
                              ? "bg-pass/10 text-pass border-pass/30"
                              : sc.score >= 50
                              ? "bg-amber-500/10 text-amber-500 border-amber-500/30"
                              : sc.score > 0
                              ? "bg-critical/10 text-critical border-critical/30"
                              : "bg-sunken text-muted border-rule"
                          )}
                        >
                          Grade {sc.grade}
                        </span>
                        {sc.score > 0 && <span className="text-muted text-[11px]">({sc.score}/100)</span>}
                      </div>
                    </td>

                    {/* Technical characteristic */}
                    <td className="px-4 py-3.5 text-xs text-muted max-w-sm leading-relaxed">
                      {sc.description}
                    </td>

                    {/* Actions */}
                    <td className="px-4 py-3.5 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          type="button"
                          disabled={analyzingId === sc.sampleId}
                          onClick={() => handleQuickAnalyze(sc.sampleId)}
                          className="inline-flex items-center gap-1 rounded-md bg-accent px-2.5 py-1.5 font-mono text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50 transition-colors cursor-pointer shadow-xs"
                        >
                          <Play className="size-3 fill-current" aria-hidden="true" />
                          <span>{analyzingId === sc.sampleId ? "Evaluating…" : "Run Analysis"}</span>
                        </button>

                        <Link
                          to={`/analysis/${sc.id}?demo=1`}
                          className="inline-flex items-center gap-1 rounded-md border border-rule bg-surface px-2.5 py-1.5 font-mono text-xs font-semibold text-muted hover:text-ink hover:border-accent transition-colors cursor-pointer"
                        >
                          <span>Inspect</span>
                          <ArrowRight className="size-3" aria-hidden="true" />
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          /* View Option 2: Clean Structured Cards */
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {filteredScenarios.map((sc) => (
              <div
                key={sc.id}
                className="flex flex-col justify-between rounded-xl border border-rule bg-surface p-5 space-y-4 interactive-card hover:border-accent shadow-xs"
              >
                <div className="space-y-2.5">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <h3 className="text-sm font-bold text-ink">{sc.title}</h3>
                      <p className="font-mono text-[10px] text-muted">{sc.filename} ({sc.category})</p>
                    </div>
                    <RiskBadge level={sc.risk} size="sm" />
                  </div>

                  <p className="text-xs text-muted leading-relaxed">{sc.description}</p>

                  <div className="space-y-1 rounded-lg border border-rule/80 bg-sunken/60 p-2.5 font-mono text-xs">
                    <div className="flex justify-between">
                      <span className="text-muted">ESP Cipher:</span>
                      <span className="font-semibold text-ink">{sc.esp}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted">Key Exchange:</span>
                      <span className="font-semibold text-ink">{sc.dh}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center justify-between border-t border-rule pt-3">
                  <div className="flex items-center gap-1.5 font-mono text-xs">
                    <span className="text-muted">Verdict:</span>
                    <span
                      className={cn(
                        "font-bold",
                        sc.score >= 80 ? "text-pass" : sc.score >= 50 ? "text-amber-500" : sc.score > 0 ? "text-critical" : "text-muted"
                      )}
                    >
                      {sc.grade} {sc.score > 0 ? `(${sc.score}/100)` : ""}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={analyzingId === sc.sampleId}
                      onClick={() => handleQuickAnalyze(sc.sampleId)}
                      className="inline-flex items-center gap-1 rounded bg-accent px-2.5 py-1 text-xs font-medium text-white hover:bg-accent-strong transition-colors cursor-pointer"
                    >
                      <Play className="size-3 fill-current" aria-hidden="true" />
                      <span>{analyzingId === sc.sampleId ? "Evaluating…" : "1-Click Run"}</span>
                    </button>

                    <Link
                      to={`/analysis/${sc.id}?demo=1`}
                      className="inline-flex items-center gap-1 text-xs font-semibold text-accent hover:underline"
                    >
                      <span>Inspect</span>
                      <ArrowRight className="size-3" aria-hidden="true" />
                    </Link>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* 4. Standards Compliance & Cryptographic Framework */}
      <section className="space-y-4">
        <div>
          <h2 className="text-base font-semibold text-ink flex items-center gap-2">
            <Lock className="size-4 text-accent" aria-hidden="true" />
            <span>Cryptographic Standards &amp; Telemetry Coverage</span>
          </h2>
          <p className="text-xs text-muted mt-0.5">
            Deterministic rule engine criteria aligned with authoritative IETF specifications and NIST SP 800-77 Rev. 1 guidelines.
          </p>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          {/* Panel 1: RFC 8221 / RFC 8247 */}
          <div className="border-l-2 border-accent bg-surface p-5 space-y-2.5">
            <div className="flex items-center gap-2 text-xs font-semibold text-accent">
              <ShieldCheck className="size-4" aria-hidden="true" />
              <span>IETF RFC 8221 &amp; RFC 8247</span>
            </div>
            <h3 className="text-xs font-bold text-ink">Mandatory &amp; Deprecated Cryptographic Suites</h3>
            <p className="text-xs leading-relaxed text-muted">
              Evaluates AEAD vs legacy transforms. Detects deprecated 64-bit block ciphers (3DES, Blowfish) vulnerable to Sweet32 collision attacks (CVE-2016-2183), unauthenticated CBC modes, and DH groups with less than 2048-bit modulus.
            </p>
            <p className="pt-2 font-mono text-[11px] text-muted">
              <span className="text-ink font-medium">Evaluated suites: </span>AES-256-GCM, ChaCha20-Poly1305, Curve25519, NIST P-256
            </p>
          </div>

          {/* Panel 2: NIST SP 800-77 & PQC */}
          <div className="border-l-2 border-accent bg-surface p-5 space-y-2.5">
            <div className="flex items-center gap-2 text-xs font-semibold text-accent">
              <Lock className="size-4" aria-hidden="true" />
              <span>NIST SP 800-77 Rev. 1 &amp; CNSA 2.0</span>
            </div>
            <h3 className="text-xs font-bold text-ink">SA Lifetime &amp; Perfect Forward Secrecy</h3>
            <p className="text-xs leading-relaxed text-muted">
              Enforces Phase 2 Child SA rekey boundaries (&le; 28,800s / 8h) to prevent key exhaustion. Verifies ephemeral DH key exchanges on Child SAs (PFS) and maps quantum transition readiness (ML-KEM / Kyber, ML-DSA).
            </p>
            <p className="pt-2 font-mono text-[11px] text-muted">
              <span className="text-ink font-medium">Key invariants: </span>SA lifetime &le; 8h, ephemeral Child SA PFS, post-quantum ML-KEM mapping
            </p>
          </div>

          {/* Panel 3: RFC 9347 IP-TFS Side-Channel Defense */}
          <div className="border-l-2 border-accent bg-surface p-5 space-y-2.5">
            <div className="flex items-center gap-2 text-xs font-semibold text-accent">
              <Network className="size-4" aria-hidden="true" />
              <span>RFC 9347 &amp; FlowDeepNet</span>
            </div>
            <h3 className="text-xs font-bold text-ink">Traffic Flow Security &amp; Side-Channel Defense</h3>
            <p className="text-xs leading-relaxed text-muted">
              Analyzes packet length entropy, burst dynamics, and inter-arrival timing. Identifies constant-rate IP-TFS padding and AGGFRAG shaping to guarantee traffic confidentiality against eavesdropping and ML classifiers.
            </p>
            <p className="pt-2 font-mono text-[11px] text-muted">
              <span className="text-ink font-medium">Side-channel metrics: </span>RFC 9347 AGGFRAG padding, packet size entropy, 25-feature distributions
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
