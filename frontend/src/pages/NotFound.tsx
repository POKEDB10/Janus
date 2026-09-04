/**
 * pages/NotFound.tsx — 404 fallback page
 */
import { useNavigate } from "react-router-dom";
import { Shield, Home, Upload, ArrowRight } from "lucide-react";

export default function NotFound() {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-center space-y-8 animate-fadeIn">
      {/* Large 404 display */}
      <div className="space-y-3">
        <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-slate-900 border border-white/10 shadow-2xl mb-2">
          <Shield size={36} className="text-janus-blue" />
        </div>
        <p className="text-8xl font-black text-white font-mono tracking-tighter opacity-20 select-none">
          404
        </p>
        <h1 className="text-2xl font-bold text-white -mt-4">Page Not Found</h1>
        <p className="text-gray-400 text-sm max-w-md mx-auto leading-relaxed">
          The URL you entered doesn't exist in the Janus router. Maybe the capture ID
          expired or the link is incorrect.
        </p>
      </div>

      {/* Quick actions */}
      <div className="flex flex-wrap gap-3 justify-center">
        <button
          onClick={() => navigate("/")}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-janus-blue hover:bg-blue-500 text-white text-sm font-semibold shadow-lg shadow-blue-600/30 transition-all cursor-pointer"
        >
          <Home size={16} />
          Back to Dashboard
        </button>
        <button
          onClick={() => navigate("/upload")}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-white/10 hover:bg-white/15 text-white border border-white/20 text-sm font-semibold transition-all cursor-pointer"
        >
          <Upload size={16} />
          Analyze a PCAP
          <ArrowRight size={14} />
        </button>
      </div>

      {/* Subtle status badge */}
      <p className="text-xs text-gray-600 font-mono">
        Janus IPsec Analyzer · SIH 2026 · Cipher Ops
      </p>
    </div>
  );
}
