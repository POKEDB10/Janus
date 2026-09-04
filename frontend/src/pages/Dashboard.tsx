/**
 * pages/Dashboard.tsx — Janus Home & Overview Dashboard
 */
import { useNavigate } from "react-router-dom";
import {
  Shield,
  Upload,
  Activity,
  Cpu,
  FileText,
  ArrowRight,
  Lock,
  EyeOff,
  Layers,
  GitCompare,
  Wifi,
} from "lucide-react";

import RiskBadge from "../components/RiskBadge";

const sampleScenarios = [
  {
    id: "scenario_01",
    title: "Scenario 1: Modern Hardened IKEv2 / ESP",
    esp: "AES-256-GCM-16",
    dh: "DH Group 19 (ECP-256)",
    score: 98,
    grade: "A",
    risk: "INFO" as const,
    description: "AEAD authenticated encryption, Elliptic Curve Diffie-Hellman, 1h SA rotation.",
  },
  {
    id: "scenario_04",
    title: "Scenario 4: Legacy 3DES + MD5 (Vulnerable)",
    esp: "3DES-CBC + HMAC-MD5-96",
    dh: "DH Group 2 (MODP-1024)",
    score: 25,
    grade: "F",
    risk: "CRITICAL" as const,
    description: "Vulnerable to SWEET32 (64-bit block collision) and Logjam precomputation attacks.",
  },
  {
    id: "scenario_07",
    title: "Scenario 7: RFC 9347 IP-TFS (Traffic Flow Security)",
    esp: "AES-256-GCM + IP-TFS",
    dh: "DH Group 20 (ECP-384)",
    score: 95,
    grade: "A",
    risk: "LOW" as const,
    description: "Constant-rate, uniform-size ESP stream neutralizing side-channel classifiers.",
  },
];

export default function Dashboard() {
  const navigate = useNavigate();

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Hero Section */}
      <section className="bg-gradient-to-r from-slate-900 via-slate-800 to-indigo-950 border border-white/10 rounded-2xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-20 -left-10 w-60 h-60 bg-indigo-700/10 rounded-full blur-3xl pointer-events-none" />
        <div className="max-w-3xl space-y-4 relative z-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/20 border border-blue-500/40 text-blue-300 text-xs font-semibold uppercase tracking-wider">
            <Shield size={14} className="text-blue-400" />
            Smart India Hackathon 2026 · Problem SIH26160 · Cipher Ops
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight leading-tight">
            Janus — AI-Powered IPsec Protocol Analyzer &amp; Compliance Engine
          </h1>
          <p className="text-gray-300 text-sm sm:text-base leading-relaxed">
            Autonomous dual-pipeline framework uniting deep deterministic handshake dissection
            (RFC 8221, RFC 8247, NIST SP 800-77 Rev. 1) with FlowDeepNet Ensemble side-channel
            classification and real-time SHAP explainability.
          </p>
          <div className="flex flex-wrap gap-3 pt-2">
            <button
              onClick={() => navigate("/upload")}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold shadow-lg shadow-blue-600/30 transition-all cursor-pointer"
            >
              <Upload size={16} />
              Analyze PCAP Capture
            </button>
            <button
              onClick={() => navigate("/compliance/scenario_04")}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-white/10 hover:bg-white/15 text-white border border-white/20 text-sm font-semibold transition-all cursor-pointer"
            >
              <Activity size={16} />
              View Demo Evaluation
              <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono ml-1">
                DEMO
              </span>
            </button>
            <button
              onClick={() => navigate("/compare")}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 border border-purple-500/30 text-sm font-semibold transition-all cursor-pointer"
            >
              <GitCompare size={16} />
              Compare Scenarios
            </button>
          </div>
        </div>
      </section>

      {/* Architecture Overview (5-Stage Pipeline) */}
      <section className="space-y-4">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <Layers size={18} className="text-blue-400" />
          5-Stage Autonomous Architecture
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {[
            {
              step: "01",
              name: "Network Capture",
              desc: "tcpdump / Wireshark .pcap/.pcapng — upload directly from any OS, no Docker required.",
              icon: <Wifi size={18} className="text-yellow-400" />,
            },
            {
              step: "02",
              name: "Hybrid Parsing",
              desc: "High-throughput dpkt ESP extraction + raw tshark JSON handshake dissection.",
              icon: <Activity size={18} className="text-cyan-400" />,
            },
            {
              step: "03",
              name: "AI Ensemble",
              desc: "FlowDeepNet + XGBoost 50/50 soft-vote on 25 statistical dims + live SHAP attribution.",
              icon: <Cpu size={18} className="text-purple-400" />,
            },
            {
              step: "04",
              name: "Compliance Audit",
              desc: "Deterministic rule engine against RFC 8221, RFC 8247 & NIST SP 800-77.",
              icon: <Lock size={18} className="text-emerald-400" />,
            },
            {
              step: "05",
              name: "Reporting",
              desc: "Interactive React dashboard + automated ReportLab Executive / Technical PDFs.",
              icon: <FileText size={18} className="text-pink-400" />,
            },
          ].map((item) => (
            <div
              key={item.step}
              className="bg-slate-900/80 border border-white/10 rounded-xl p-4 flex flex-col justify-between hover:border-blue-500/40 transition-colors duration-200"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono font-bold text-gray-400">STAGE {item.step}</span>
                  {item.icon}
                </div>
                <h3 className="text-sm font-semibold text-white mb-1">{item.name}</h3>
                <p className="text-xs text-gray-400 leading-relaxed">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Preconfigured Scenarios Matrix */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Shield size={18} className="text-blue-400" />
            Verified Testbed Scenarios
          </h2>
          <div className="flex items-center gap-3">
            <span className="text-xs text-gray-400 font-mono">12 Pre-generated Profiles</span>
            <button
              onClick={() => navigate("/compare")}
              className="inline-flex items-center gap-1.5 text-xs text-purple-400 hover:text-purple-300 font-semibold cursor-pointer transition-colors"
            >
              <GitCompare size={13} />
              Side-by-side compare
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {sampleScenarios.map((sc) => (
            <div
              key={sc.id}
              className="bg-slate-900 border border-white/10 rounded-xl p-5 hover:border-blue-500/50 transition-all duration-200 flex flex-col justify-between cursor-pointer"
              onClick={() => navigate(`/compliance/${sc.id}`)}
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between">
                  <h3 className="text-sm font-bold text-white">{sc.title}</h3>
                  <RiskBadge level={sc.risk} size="sm" />
                </div>
                <p className="text-xs text-gray-400">{sc.description}</p>
                <div className="bg-slate-950/60 rounded-lg p-2.5 border border-white/5 space-y-1 text-xs font-mono">
                  <div className="flex justify-between text-gray-300">
                    <span className="text-gray-500">ESP Cipher:</span>
                    <span>{sc.esp}</span>
                  </div>
                  <div className="flex justify-between text-gray-300">
                    <span className="text-gray-500">Key Exchange:</span>
                    <span>{sc.dh}</span>
                  </div>
                </div>
              </div>

              <div className="pt-4 mt-2 border-t border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-gray-400 font-medium">Compliance:</span>
                  <span
                    className={`text-sm font-bold font-mono ${
                      sc.score >= 80 ? "text-emerald-400" : "text-red-400"
                    }`}
                  >
                    {sc.score}/100 ({sc.grade})
                  </span>
                </div>
                <span className="text-xs font-semibold text-blue-400 hover:text-blue-300 inline-flex items-center gap-1">
                  Inspect <ArrowRight size={13} />
                </span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Key Features & Differentiators */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-900/60 border border-white/10 rounded-xl p-5 space-y-2">
          <div className="flex items-center gap-2 text-blue-400 font-semibold text-sm">
            <Lock size={16} />
            Deterministic RFC Rules
          </div>
          <p className="text-xs text-gray-400 leading-relaxed">
            Zero hallucinations. Evaluates cryptographic suites against RFC 8221 (ESP), RFC 8247
            (IKEv2), and NIST SP 800-77 Rev. 1 requirements with exact CVE and attack vector mappings.
          </p>
        </div>

        <div className="bg-slate-900/60 border border-white/10 rounded-xl p-5 space-y-2">
          <div className="flex items-center gap-2 text-purple-400 font-semibold text-sm">
            <Cpu size={16} />
            FlowDeepNet Ensemble + SHAP
          </div>
          <p className="text-xs text-gray-400 leading-relaxed">
            Dual-engine 50/50 soft-vote: XGBoost (speed) + 13 MB 4-layer MLP (depth). Strictly
            excludes IP/ports. Real-time SHAP attribution with anti-hallucination OOD guardrail.
          </p>
        </div>

        <div className="bg-slate-900/60 border border-white/10 rounded-xl p-5 space-y-2">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
            <EyeOff size={16} />
            RFC 9347 IP-TFS Detection
          </div>
          <p className="text-xs text-gray-400 leading-relaxed">
            Detects constant-rate, uniform-size packet obfuscation and AGGFRAG shaping, correctly
            identifying traffic flow security without misclassifying side-channel metadata.
          </p>
        </div>
      </section>
    </div>
  );
}
