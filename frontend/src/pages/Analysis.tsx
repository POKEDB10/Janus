/**
 * pages/Analysis.tsx — FlowDeepNet Ensemble AI Classifier & SHAP Explainability
 */
import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  PieChart as PieChartIcon,
  Activity,
  AlertTriangle,
  TrendingUp,
  Download,
  AlertCircle,
} from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  Legend,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";
import { getAnalysisResults } from "../api/client";
import type { FlowResult, TrafficType, AnalysisResults } from "../types";
import SHAPChart from "../components/SHAPChart";

const TRAFFIC_COLORS: Record<TrafficType, string> = {
  VoIP: "#10b981",       // emerald
  Video: "#3b82f6",      // blue
  Web: "#8b5cf6",        // purple
  Email: "#f59e0b",      // amber
  ICMP: "#06b6d4",       // cyan
  Obfuscated: "#ec4899", // pink
};

// ─── Demo data (fallback when backend is offline) ────────────────────────────

const DEMO_FLOWS: FlowResult[] = [
  {
    flow_id: "flow_0001",
    spi: "0x0c9f1a2b",
    src_ip: "172.20.1.1",
    dst_ip: "172.20.1.2",
    src_port: 4500,
    dst_port: 4500,
    protocol: "ESP",
    dscp: 46,
    duration_s: 18.4,
    packet_count: 920,
    byte_count: 174800,
    risk_level: "LOW",
    is_obfuscated: false,
    classification: {
      traffic_type: "VoIP",
      confidence: 0.96,
      shap: {
        base_value: 0.2,
        output_value: 0.96,
        shap_values: { iat_mean: 0.35, pkt_len_iqr: 0.24, burst_len_mean: 0.18, pkt_len_mean: -0.05, byte_rate_bps: -0.04 },
      },
    },
  },
  {
    flow_id: "flow_0002",
    spi: "0x3f4a8b1c",
    src_ip: "172.20.1.1",
    dst_ip: "172.20.1.2",
    src_port: 4500,
    dst_port: 4500,
    protocol: "ESP",
    dscp: 34,
    duration_s: 32.1,
    packet_count: 3840,
    byte_count: 4800000,
    risk_level: "LOW",
    is_obfuscated: false,
    classification: {
      traffic_type: "Video",
      confidence: 0.93,
      shap: {
        base_value: 0.2,
        output_value: 0.93,
        shap_values: { pkt_len_mean: 0.42, burst_len_max: 0.28, byte_rate_bps: 0.19, forward_byte_ratio: 0.12, iat_var: -0.08 },
      },
    },
  },
  {
    flow_id: "flow_0003",
    spi: "0x7e8d2c4b",
    src_ip: "172.20.1.1",
    dst_ip: "172.20.1.2",
    src_port: 4500,
    dst_port: 4500,
    protocol: "ESP",
    dscp: 0,
    duration_s: 12.6,
    packet_count: 240,
    byte_count: 145000,
    risk_level: "INFO",
    is_obfuscated: false,
    classification: {
      traffic_type: "Web",
      confidence: 0.88,
      shap: {
        base_value: 0.2,
        output_value: 0.88,
        shap_values: { pkt_len_iqr: 0.38, forward_packet_ratio: 0.22, iat_max: 0.15, burst_count: -0.07 },
      },
    },
  },
  {
    flow_id: "flow_0004",
    spi: "0x9a8b7c6d",
    src_ip: "172.20.1.1",
    dst_ip: "172.20.1.2",
    src_port: 4500,
    dst_port: 4500,
    protocol: "ESP",
    dscp: 0,
    duration_s: 45.0,
    packet_count: 4500,
    byte_count: 6480000,
    risk_level: "LOW",
    is_obfuscated: true,
    classification: {
      traffic_type: "Obfuscated",
      confidence: 0.99,
      shap: {
        base_value: 0.2,
        output_value: 0.99,
        shap_values: { pkt_len_var: 0.65, iat_cv: 0.32 },
      },
    },
  },
];

// ─── CSV export utility ──────────────────────────────────────────────────────

function exportFlowsAsCSV(flows: FlowResult[], captureId: string) {
  const headers = [
    "flow_id", "spi", "src_ip", "dst_ip", "packet_count", "duration_s",
    "byte_count", "predicted_class", "confidence_pct", "is_obfuscated",
  ];
  const rows = flows.map((f) => [
    f.flow_id,
    f.spi,
    f.src_ip,
    f.dst_ip,
    f.packet_count,
    f.duration_s.toFixed(2),
    f.byte_count,
    f.classification.traffic_type,
    (f.classification.confidence * 100).toFixed(1),
    f.is_obfuscated,
  ]);
  const csv = [headers, ...rows].map((r) => r.join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `janus_flows_${captureId.slice(0, 8)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Component ───────────────────────────────────────────────────────────────

export default function Analysis() {
  const { captureId = "scenario_01" } = useParams<{ captureId: string }>();
  const navigate = useNavigate();

  const [results, setResults] = useState<AnalysisResults | null>(null);
  const [flows, setFlows] = useState<FlowResult[]>([]);
  const [selectedFlow, setSelectedFlow] = useState<FlowResult | null>(null);
  const [isDemoMode, setIsDemoMode] = useState(false);

  useEffect(() => {
    async function loadData() {
      try {
        const res = await getAnalysisResults(captureId);
        setResults(res);
        setFlows(res.flows || []);
        if (res.flows && res.flows.length > 0) {
          setSelectedFlow(res.flows[0]);
        }
        setIsDemoMode(false);
      } catch {
        // Backend offline — load synthetic demo data transparently
        const synth: AnalysisResults = {
          capture_id: captureId,
          total_flows: DEMO_FLOWS.length,
          overall_risk: "LOW",
          traffic_distribution: { VoIP: 1, Video: 1, Web: 1, Email: 0, ICMP: 0, Obfuscated: 1 },
          flows: DEMO_FLOWS,
        };
        setResults(synth);
        setFlows(DEMO_FLOWS);
        setSelectedFlow(DEMO_FLOWS[0]);
        setIsDemoMode(true);
      }
    }
    loadData();
  }, [captureId]);

  const trafficPieData = Object.entries(results?.traffic_distribution || {})
    .filter(([_, count]) => count > 0)
    .map(([type, count]) => ({
      name: type,
      value: count,
      color: TRAFFIC_COLORS[type as TrafficType] || "#94a3b8",
    }));

  // Threat timeline: confidence score per flow (simulated time series)
  const timelineData = flows.map((f, idx) => ({
    name: f.flow_id,
    confidence: Math.round(f.classification.confidence * 100),
    index: idx + 1,
  }));

  const isOOD = (flow: FlowResult) =>
    flow.classification.traffic_type?.toLowerCase().includes("uncertain") ||
    flow.classification.traffic_type?.includes("⚠");

  return (
    <div className="space-y-6 animate-fadeIn">

      {/* DEMO MODE Banner */}
      {isDemoMode && (
        <div className="flex items-center gap-3 px-4 py-3 bg-amber-900/30 border border-amber-500/50 rounded-xl text-amber-300 text-sm">
          <AlertCircle size={18} className="shrink-0 text-amber-400" />
          <div>
            <span className="font-bold">DEMO MODE</span>
            {" — Showing pre-computed synthetic results. "}
            <button
              onClick={() => navigate("/upload")}
              className="underline hover:text-amber-100 cursor-pointer"
            >
              Upload a real PCAP to run live analysis.
            </button>
          </div>
        </div>
      )}

      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              AI Traffic Classifier &amp; Side-Channel Analysis
            </h1>
            {/* FIXED: reflects actual dual-engine architecture */}
            <span className="px-2.5 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/40 text-xs font-mono font-bold">
              FlowDeepNet Ensemble + SHAP
            </span>
          </div>
          <p className="text-gray-400 text-sm mt-1">
            Flow-level statistical feature extraction excluding IP/ports with local SHAP feature attribution.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => exportFlowsAsCSV(flows, captureId)}
            disabled={flows.length === 0}
            title="Download flow predictions as CSV"
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-gray-300 text-xs font-semibold border border-white/10 inline-flex items-center gap-1.5 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <Download size={14} />
            Export CSV
          </button>
          <button
            onClick={() => navigate(`/compliance/${captureId}`)}
            className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold cursor-pointer transition-colors"
          >
            View Compliance Audit
          </button>
        </div>
      </div>

      {/* Overview Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-white/10 rounded-xl p-4">
          <span className="text-xs text-gray-400 font-medium">Total Encrypted Flows</span>
          <p className="text-2xl font-bold text-white font-mono mt-1">{flows.length}</p>
        </div>
        <div className="bg-slate-900 border border-white/10 rounded-xl p-4">
          <span className="text-xs text-gray-400 font-medium">Feature Dimensions</span>
          <p className="text-2xl font-bold text-purple-400 font-mono mt-1">25 Statistical</p>
          <span className="text-[10px] text-gray-500">Zero IP/Port leakage</span>
        </div>
        <div className="bg-slate-900 border border-white/10 rounded-xl p-4">
          <span className="text-xs text-gray-400 font-medium">Explainability</span>
          <p className="text-2xl font-bold text-emerald-400 font-mono mt-1">SHAP Live</p>
          <span className="text-[10px] text-gray-500">TreeExplainer millisecond</span>
        </div>
        <div className="bg-slate-900 border border-white/10 rounded-xl p-4">
          <span className="text-xs text-gray-400 font-medium">IP-TFS Obfuscation</span>
          <p className="text-2xl font-bold text-pink-400 font-mono mt-1">
            {flows.filter((f) => f.is_obfuscated).length} Flows
          </p>
          <span className="text-[10px] text-gray-500">RFC 9347 Constant-Rate</span>
        </div>
      </div>

      {/* Main Analysis Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Traffic Distribution Chart */}
        <div className="bg-slate-900 border border-white/10 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <PieChartIcon size={16} className="text-blue-400" />
            Class Distribution
          </h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={trafficPieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {trafficPieData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <RechartsTooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    borderColor: "rgba(255,255,255,0.2)",
                    borderRadius: 8,
                    fontSize: 12,
                    color: "#ffffff",
                    boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.5)",
                  }}
                  itemStyle={{ color: "#38bdf8", fontWeight: "bold" }}
                  labelStyle={{ color: "#ffffff", fontWeight: "bold" }}
                />
                <Legend
                  formatter={(value) => {
                    const item = trafficPieData.find((p) => p.name === value);
                    return (
                      <span className="text-xs font-medium text-gray-200 ml-1">
                        {value} {item ? `(${item.value})` : ""}
                      </span>
                    );
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right: Flow List Table */}
        <div className="lg:col-span-2 bg-slate-900 border border-white/10 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Activity size={16} className="text-blue-400" />
              ESP Flows &amp; AI Predictions
            </h2>
            <span className="text-xs text-gray-400">Click a row to view SHAP explanation</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-white/10 text-gray-400 font-mono">
                  <th className="pb-2.5">Flow ID</th>
                  <th className="pb-2.5">SPI</th>
                  <th className="pb-2.5">Packets</th>
                  <th className="pb-2.5">Duration</th>
                  <th className="pb-2.5">Class</th>
                  <th className="pb-2.5">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {flows.map((flow) => {
                  const isSelected = selectedFlow?.flow_id === flow.flow_id;
                  const label = flow.classification.traffic_type;
                  const ood = isOOD(flow);
                  const color = ood
                    ? "#f59e0b"
                    : TRAFFIC_COLORS[label as TrafficType] || "#94a3b8";

                  return (
                    <tr
                      key={flow.flow_id}
                      onClick={() => setSelectedFlow(flow)}
                      className={`cursor-pointer transition-colors duration-100 ${
                        isSelected ? "bg-blue-600/20 text-white" : "hover:bg-white/5 text-gray-300"
                      }`}
                    >
                      <td className="py-2.5 font-mono font-medium">{flow.flow_id}</td>
                      <td className="py-2.5 font-mono text-gray-400">{flow.spi}</td>
                      <td className="py-2.5 font-mono">{flow.packet_count}</td>
                      <td className="py-2.5 font-mono">{flow.duration_s.toFixed(1)}s</td>
                      <td className="py-2.5">
                        <span
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold"
                          style={{
                            backgroundColor: `${color}20`,
                            color: color,
                            border: `1px solid ${color}40`,
                          }}
                          title={ood ? "Anti-hallucination OOD guardrail fired: shows raw prediction intent" : undefined}
                        >
                          {ood && <AlertTriangle size={11} className="shrink-0" />}
                          <span>{ood ? "OOD" : label}</span>
                        </span>
                      </td>
                      <td className="py-2.5 font-mono font-semibold">
                        {(flow.classification.confidence * 100).toFixed(1)}%
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Threat Timeline — Confidence vs. Flow Index */}
      {flows.length > 1 && (
        <div className="bg-slate-900 border border-white/10 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <TrendingUp size={16} className="text-emerald-400" />
            Live Prediction Confidence Timeline
            <span className="text-xs text-gray-500 font-normal ml-1">— per-flow ensemble confidence %</span>
          </h2>
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timelineData} margin={{ top: 4, right: 16, left: 0, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis
                  dataKey="name"
                  tick={{ fill: "#94a3b8", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fill: "#94a3b8", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(v) => `${v}%`}
                />
                <RechartsTooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    borderColor: "rgba(255,255,255,0.2)",
                    borderRadius: 8,
                    fontSize: 12,
                    color: "#ffffff",
                    boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.5)",
                  }}
                  itemStyle={{ color: "#38bdf8", fontWeight: "bold" }}
                  labelStyle={{ color: "#ffffff", fontWeight: "bold" }}
                  formatter={(value: number) => [`${value}%`, "Confidence"]}
                />
                <Line
                  type="monotone"
                  dataKey="confidence"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  dot={{ fill: "#3b82f6", r: 4 }}
                  activeDot={{ r: 6, fill: "#60a5fa" }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Selected Flow SHAP Local Explainability Drawer */}
      {selectedFlow && (
        <div className="bg-slate-900 border border-white/10 rounded-xl p-6 space-y-6 shadow-2xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
            <div>
              <span className="text-xs font-mono uppercase tracking-wider text-purple-400">
                SHAP Local Feature Attribution
              </span>
              <h3 className="text-lg font-bold text-white font-mono mt-0.5">
                Flow: {selectedFlow.flow_id} (SPI {selectedFlow.spi})
              </h3>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-400">Classified as:</span>
              <span
                className="px-3 py-1 rounded-full text-xs font-bold"
                style={{
                  backgroundColor: `${TRAFFIC_COLORS[selectedFlow.classification.traffic_type as TrafficType] || "#94a3b8"}20`,
                  color: TRAFFIC_COLORS[selectedFlow.classification.traffic_type as TrafficType] || "#94a3b8",
                  border: `1px solid ${TRAFFIC_COLORS[selectedFlow.classification.traffic_type as TrafficType] || "#94a3b8"}50`,
                }}
              >
                {selectedFlow.classification.traffic_type} ({(selectedFlow.classification.confidence * 100).toFixed(1)}%)
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
            <div className="lg:col-span-2">
              <h4 className="text-xs font-mono text-gray-400 uppercase tracking-wider mb-2">
                Top Contributing Statistical Side-Channel Features
              </h4>
              <SHAPChart
                shap_values={selectedFlow.classification.shap.shap_values}
                base_value={selectedFlow.classification.shap.base_value}
              />
            </div>

            <div className="bg-slate-950/60 border border-white/5 rounded-xl p-4 space-y-3 text-xs">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                Why was this flow classified as {selectedFlow.classification.traffic_type}?
              </h4>
              <p className="text-gray-400 leading-relaxed">
                The SHAP TreeExplainer decomposed the FlowDeepNet Ensemble decision into exact
                additive feature attributions:
              </p>
              <ul className="space-y-2 text-gray-300 font-mono">
                {Object.entries(selectedFlow.classification.shap.shap_values)
                  .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
                  .slice(0, 3)
                  .map(([feat, val]) => (
                    <li
                      key={feat}
                      className="flex justify-between items-center bg-slate-900/80 p-2 rounded border border-white/5"
                    >
                      <span className="text-gray-400">{feat}</span>
                      <span className={val > 0 ? "text-red-400 font-bold" : "text-blue-400 font-bold"}>
                        {val > 0 ? `+${val.toFixed(3)}` : val.toFixed(3)}
                      </span>
                    </li>
                  ))}
              </ul>

              {/* OOD explanation pill */}
              {isOOD(selectedFlow) && (
                <div className="p-3 bg-amber-950/30 border border-amber-500/40 rounded-lg text-amber-300 text-[11px] space-y-1">
                  <div className="font-bold flex items-center gap-1.5">
                    <AlertTriangle size={13} />
                    Anti-Hallucination OOD Guardrail
                  </div>
                  <p className="text-amber-200/80">
                    This flow's statistical fingerprint is distant from the synthetic training
                    distribution (real-world traffic domain gap). The raw model intent is shown —
                    the system refuses to make a high-confidence claim it can't support.
                  </p>
                </div>
              )}

              {/* IP-TFS obfuscation notice */}
              {selectedFlow.is_obfuscated && !isOOD(selectedFlow) && (
                <div className="p-3 bg-pink-950/30 border border-pink-500/40 rounded-lg text-pink-300 text-[11px] space-y-1">
                  <div className="font-bold flex items-center gap-1.5">
                    <AlertTriangle size={13} />
                    RFC 9347 IP-TFS Active
                  </div>
                  <p className="text-pink-200/80">
                    Packet size variance is ~0 and IAT is constant. Side-channel classification was
                    suppressed to avoid false positives.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
