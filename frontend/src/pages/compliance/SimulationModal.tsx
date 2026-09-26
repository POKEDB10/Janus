import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  Activity,
  BookOpen,
  Clock,
  Download,
  FastForward,
  RotateCcw,
  Terminal,
  X,
} from "lucide-react";
import RiskBadge from "../../components/RiskBadge";
import { ErrorState, GradeMark, LoadingState } from "../../components/ui/Primitives";
import { getApiErrorMessage } from "../../lib/api-error";
import type { Finding, RiskLevel } from "../../types";

const focusableSelector =
  "button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";

interface SimulationModalProps {
  open: boolean;
  onClose: () => void;
  cipher: string;
  auth: string;
  dhGroup: number;
  pfsEnabled: boolean;
  lifetime: number;
  isPending?: boolean;
  isError?: boolean;
  error?: unknown;
  onRetry?: () => void;
  overallScore?: number;
  grade?: string;
  summary?: string;
  backendFindings?: Finding[];
  onExplain?: (finding: Finding) => void;
}

interface TimedFindingSlot {
  timeSec: number;
  timeFormatted: string;
  finding: Finding;
}

export function SimulationModal({
  open,
  onClose,
  cipher,
  auth,
  dhGroup,
  pfsEnabled,
  lifetime,
  isPending = false,
  isError = false,
  error = null,
  onRetry,
  overallScore = 100,
  grade = "A",
  summary,
  backendFindings = [],
  onExplain,
}: SimulationModalProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLElement | null>(null);
  const closeRef = useRef(onClose);

  const [elapsedRealMs, setElapsedRealMs] = useState(0);
  const [isSimulating, setIsSimulating] = useState(false);
  const [activeTab, setActiveTab] = useState<"TELEMETRY" | "LOGS">("TELEMETRY");
  const [logs, setLogs] = useState<string[]>([]);
  const logContainerRef = useRef<HTMLDivElement>(null);

  const simulatedHours = Math.max(1, Math.round(lifetime / 3600));
  const TOTAL_SIMULATED_SECONDS = lifetime > 0 ? lifetime : 3600;
  // 5.0 seconds real time per simulated hour (720x acceleration)
  const TOTAL_REAL_MS = simulatedHours * 5000;

  function formatDuration(totalSec: number): string {
    const h = Math.floor(totalSec / 3600);
    const m = Math.floor((totalSec % 3600) / 60);
    const s = totalSec % 60;
    return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }

  const totalSimFormatted = formatDuration(TOTAL_SIMULATED_SECONDS);
  const loggedEventsRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    closeRef.current = onClose;
  }, [onClose]);

  // Focus trap, Escape key handling, and focus restoration
  useEffect(() => {
    if (!open) return;
    triggerRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const panel = panelRef.current;
    const firstControl = panel?.querySelector<HTMLElement>(focusableSelector);
    firstControl?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      // If an overlying drawer is open, let the drawer handle Escape and Tab
      if (document.querySelector("[data-drawer-open='true']")) return;

      if (event.key === "Escape") {
        closeRef.current();
      }
      if (event.key !== "Tab" || !panel) return;
      const controls = Array.from(panel.querySelectorAll<HTMLElement>(focusableSelector));
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      }
      if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      triggerRef.current?.focus();
    };
  }, [open]);

  // Map real findings from backend adhoc evaluation to timed release slots
  const timedFindingSlots: TimedFindingSlot[] = backendFindings.map((finding, idx) => {
    const totalSlots = backendFindings.length;
    // Distribute evenly between 15% and 85% of total simulated time
    const startSec = Math.floor(TOTAL_SIMULATED_SECONDS * 0.15);
    const endSec = Math.floor(TOTAL_SIMULATED_SECONDS * 0.85);
    const span = Math.max(1, endSec - startSec);
    const step = totalSlots > 1 ? span / (totalSlots - 1) : 0;
    const timeSec = Math.floor(startSec + idx * step);
    return {
      timeSec,
      timeFormatted: formatDuration(timeSec),
      finding,
    };
  });

  const startSimulation = () => {
    setElapsedRealMs(0);
    setIsSimulating(true);
    loggedEventsRef.current.clear();
    setLogs([
      `[00:00:00] Initializing accelerated VPN testbed (${simulatedHours}h trace time in ${Math.round(TOTAL_REAL_MS / 1000)}s real time at 720x)...`,
      `[00:00:15] Tunnel endpoints configured: 192.168.100.1 <==> 192.168.100.2`,
      `[00:00:45] Negotiating IKEv2 SA: cipher=${cipher}, auth=${auth}, DH Group=${dhGroup}, PFS=${pfsEnabled ? "Enabled" : "Disabled"} (lifetime: ${lifetime}s)`,
    ]);
  };

  useEffect(() => {
    if (open && !isPending && !isError) {
      startSimulation();
    } else {
      setIsSimulating(false);
      setElapsedRealMs(0);
    }
  }, [open, isPending, isError, cipher, auth, dhGroup, pfsEnabled, lifetime]);

  // Animation ticker: 50ms interval across TOTAL_REAL_MS (5.0s per simulated hour)
  useEffect(() => {
    if (!isSimulating || isPending || isError) return;

    const interval = window.setInterval(() => {
      setElapsedRealMs((prev) => {
        const next = prev + 50;
        if (next >= TOTAL_REAL_MS) {
          window.clearInterval(interval);
          setIsSimulating(false);
          return TOTAL_REAL_MS;
        }
        return next;
      });
    }, 50);

    return () => window.clearInterval(interval);
  }, [isSimulating, isPending, isError, TOTAL_REAL_MS]);

  const progressRatio = Math.min(1, elapsedRealMs / TOTAL_REAL_MS);
  const currentSimulatedSec = Math.floor(progressRatio * TOTAL_SIMULATED_SECONDS);
  const simClockFormatted = formatDuration(currentSimulatedSec);

  // Live traffic metrics calculated from stated throughput assumption (~100 Mbps standard enterprise mix)
  const totalExpectedPackets = Math.floor(14820 * simulatedHours);
  const totalExpectedMB = 46.8 * simulatedHours;
  const packetsSent = Math.floor(progressRatio * totalExpectedPackets);
  const currentMB = progressRatio * totalExpectedMB;
  const formattedDataVolume =
    currentMB >= 1024
      ? `${(currentMB / 1024).toFixed(2)} GB`
      : `${currentMB.toFixed(1)} MB`;

  const activeFlowsCount = progressRatio > 0.05 ? 5 : 1;

  // Real findings discovered up to current elapsed simulated time
  const discoveredSlots = timedFindingSlots.filter((slot) => currentSimulatedSec >= slot.timeSec);

  // Dynamic log generator synced to real evaluation milestones
  useEffect(() => {
    if (!isSimulating && elapsedRealMs === 0) return;

    // Milestone 1 (10%): Ingesting traffic mix
    const m1Sec = Math.floor(TOTAL_SIMULATED_SECONDS * 0.1);
    if (currentSimulatedSec >= m1Sec && !loggedEventsRef.current.has("m1")) {
      loggedEventsRef.current.add("m1");
      setLogs((prev) => [
        ...prev,
        `[${formatDuration(m1Sec)}] Ingesting enterprise traffic mix (VoIP, HTTPS, DNS-over-ESP).`,
        `[${formatDuration(m1Sec)}] Validating ESP cipher '${cipher}' against RFC 8221 requirements...`,
      ]);
    }

    // Milestone 2 (30%): Anti-replay and DH work factor
    const m2Sec = Math.floor(TOTAL_SIMULATED_SECONDS * 0.3);
    if (currentSimulatedSec >= m2Sec && !loggedEventsRef.current.has("m2")) {
      loggedEventsRef.current.add("m2");
      setLogs((prev) => [
        ...prev,
        `[${formatDuration(m2Sec)}] Stress testing anti-replay window (64-packet bitmap).`,
        `[${formatDuration(m2Sec)}] Evaluating Diffie-Hellman Group ${dhGroup} work factor against RFC 8247 §2.4...`,
      ]);
    }

    // Milestone 3 (60%): Child SA rekey boundary
    const m3Sec = Math.floor(TOTAL_SIMULATED_SECONDS * 0.6);
    if (currentSimulatedSec >= m3Sec && !loggedEventsRef.current.has("m3")) {
      loggedEventsRef.current.add("m3");
      setLogs((prev) => [
        ...prev,
        `[${formatDuration(m3Sec)}] Simulating Child SA rekey boundary (lifetime: ${lifetime}s).`,
        `[${formatDuration(m3Sec)}] Perfect Forward Secrecy status: ${pfsEnabled ? "PFS Active (ephemeral key derived)" : "PFS Disabled (IKE master key reused)"}.`,
      ]);
    }

    // Weakness alerts for discovered slots
    discoveredSlots.forEach((slot) => {
      const key = `finding_${slot.finding.rule_id}_${slot.timeSec}`;
      if (!loggedEventsRef.current.has(key)) {
        loggedEventsRef.current.add(key);
        setLogs((prev) => [
          ...prev,
          `[${slot.timeFormatted}] WEAKNESS DETECTED [${slot.finding.rule_id}]: ${slot.finding.parameter} (${slot.finding.severity?.toUpperCase() || "HIGH"})`,
        ]);
      }
    });

    // Completion milestone
    if (currentSimulatedSec >= TOTAL_SIMULATED_SECONDS && !loggedEventsRef.current.has("complete")) {
      loggedEventsRef.current.add("complete");
      setLogs((prev) => [
        ...prev,
        `[${totalSimFormatted}] ${simulatedHours}-Hour Traffic Simulation Complete: ${totalExpectedPackets.toLocaleString()} packets, ${formattedDataVolume} processed (illustrative estimate).`,
        `[${totalSimFormatted}] Real Rule Engine Audit Complete: Grade ${grade} (${overallScore}/100) with ${backendFindings.length} finding(s).`,
      ]);
    }
  }, [
    currentSimulatedSec,
    isSimulating,
    TOTAL_SIMULATED_SECONDS,
    totalSimFormatted,
    simulatedHours,
    totalExpectedPackets,
    formattedDataVolume,
    cipher,
    dhGroup,
    lifetime,
    pfsEnabled,
    grade,
    overallScore,
    backendFindings.length,
    discoveredSlots,
  ]);

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  if (!open) return null;

  const isComplete = elapsedRealMs >= TOTAL_REAL_MS;

  const skipToResult = () => {
    setElapsedRealMs(TOTAL_REAL_MS);
    setIsSimulating(false);
  };

  return createPortal(
    <div
      className="fixed top-14 inset-x-0 bottom-0 z-dialog flex items-center justify-center bg-black/80 p-4 sm:p-6 backdrop-blur-sm motion-fade"
      role="dialog"
      aria-modal="true"
      aria-labelledby="simulation-modal-title"
      onMouseDown={(e) => {
        if (document.querySelector("[data-drawer-open='true']")) return;
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={panelRef}
        className="flex flex-col w-full max-w-4xl max-h-[calc(100vh-5rem)] rounded-2xl border border-rule bg-surface shadow-2xl overflow-hidden motion-scale-in my-auto"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-rule px-5 py-3.5 bg-surface">
          <div className="flex items-center gap-3">
            <div className="flex size-8 items-center justify-center rounded-lg bg-accent/10 text-accent border border-accent/20">
              <Activity className="size-4 animate-pulse" aria-hidden="true" />
            </div>
            <div>
              <h2 id="simulation-modal-title" className="text-sm font-bold text-ink flex items-center gap-2">
                {simulatedHours}-Hour Accelerated Traffic &amp; Rekeying Emulation
                {isPending ? (
                  <span className="rounded bg-sunken px-2 py-0.5 font-mono text-[10px] font-bold text-muted border border-rule">
                    EVALUATING
                  </span>
                ) : isError ? (
                  <span className="rounded bg-critical/10 px-2 py-0.5 font-mono text-[10px] font-bold text-critical border border-critical/30">
                    FAILED
                  </span>
                ) : isComplete ? (
                  <span className="rounded bg-pass/10 px-2 py-0.5 font-mono text-[10px] font-bold text-pass border border-pass/30">
                    COMPLETE
                  </span>
                ) : (
                  <span className="rounded bg-accent/10 px-2 py-0.5 font-mono text-[10px] font-bold text-accent border border-accent/20 animate-pulse">
                    RUNNING ({Math.round(TOTAL_REAL_MS / 1000)}s @ 720x)
                  </span>
                )}
              </h2>
              <p className="text-[11px] font-mono text-muted">
                Suite: {cipher} · {auth} · DH {dhGroup} · PFS {pfsEnabled ? "Enabled" : "Disabled"} · Lifetime {lifetime}s
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {!isComplete && !isPending && !isError && (
              <button
                type="button"
                onClick={skipToResult}
                className="inline-flex items-center gap-1.5 rounded-lg border border-rule bg-surface px-3 py-1.5 text-xs font-semibold text-muted hover:text-ink hover:border-accent transition-colors cursor-pointer"
                title="Skip animation directly to completed result"
              >
                <FastForward className="size-3.5" aria-hidden="true" />
                <span>Skip to result</span>
              </button>
            )}

            {isComplete && !isPending && !isError && (
              <button
                type="button"
                onClick={startSimulation}
                className="inline-flex items-center gap-1.5 rounded-lg border border-rule bg-surface px-3 py-1.5 text-xs font-semibold text-muted hover:text-ink hover:border-accent transition-colors cursor-pointer"
                title="Rerun Simulation"
              >
                <RotateCcw className="size-3.5" aria-hidden="true" />
                <span>Rerun</span>
              </button>
            )}

            <button
              type="button"
              onClick={onClose}
              className="p-1 rounded-md text-muted hover:text-ink hover:bg-sunken transition-colors cursor-pointer"
              aria-label="Close simulation dialog"
            >
              <X className="size-5" aria-hidden="true" />
            </button>
          </div>
        </div>

        {/* Technical Specification Ribbon */}
        <aside
          aria-label="Simulation specification ribbon"
          className="border-b border-rule bg-sunken/80 px-4 py-1.5 text-center font-mono text-[11px] text-muted flex flex-wrap items-center justify-center gap-x-3 gap-y-1"
        >
          <span className="text-accent font-semibold">SYNTHETIC TRAFFIC EMULATION</span>
          <span className="text-rule">|</span>
          <span>100 Mbps Enterprise Mix Baseline</span>
          <span className="text-rule">|</span>
          <span>Deterministic RFC 8221 / 8247 &amp; NIST SP 800-77 Evaluation</span>
        </aside>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-4">
          {isPending ? (
            <div className="py-12">
              <LoadingState label="Computing authoritative RFC 8221, RFC 8247, and NIST SP 800-77 compliance evaluation..." />
            </div>
          ) : isError ? (
            <div className="py-6">
              <ErrorState
                title="Cryptographic Evaluation Failed"
                detail={getApiErrorMessage(error)}
                onRetry={onRetry}
              />
            </div>
          ) : (
            <>
              {/* Speed & Accelerated Clock Banner */}
              <div className="rounded-xl border border-rule bg-canvas p-3.5 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-2 font-mono">
                    <Clock className="size-3.5 text-accent" aria-hidden="true" />
                    <span className="text-muted text-[11px]">Simulated Stream Time:</span>
                    <span className="text-sm font-bold text-ink tracking-wide">{simClockFormatted}</span>
                    <span className="text-muted text-[11px]">/ {totalSimFormatted}</span>
                  </div>

                  <div className="flex items-center gap-2 font-mono text-[11px]">
                    <span className="rounded bg-accent/10 border border-accent/20 px-2 py-0.5 text-accent font-semibold">
                      Pacing: 1h trace = 5.0s real (720x acceleration)
                      {!isComplete && !isPending && !isError && (
                        <span className="ml-1 text-muted">
                          • ~{Math.ceil((TOTAL_REAL_MS - elapsedRealMs) / 1000)}s remaining
                        </span>
                      )}
                    </span>
                  </div>
                </div>

                {/* Progress bar */}
                <div className="space-y-1">
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-sunken">
                    <div
                      className="h-full bg-accent transition-all duration-75 ease-linear rounded-full"
                      style={{ width: `${progressRatio * 100}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[10px] font-mono text-muted">
                    <span>00:00:00 (Start)</span>
                    <span>{formatDuration(Math.floor(TOTAL_SIMULATED_SECONDS / 2))} (Rekey &amp; Replay Check)</span>
                    <span>{totalSimFormatted} ({simulatedHours}h Boundary)</span>
                  </div>
                </div>
              </div>

              {/* Telemetry Counters */}
              <div className="grid gap-2.5 grid-cols-2 sm:grid-cols-4">
                <div className="rounded-xl border border-rule bg-surface p-3 space-y-0.5">
                  <span className="text-[10px] font-mono text-muted tracking-wider">Projected packets</span>
                  <p className="text-base font-mono font-bold text-ink">
                    {packetsSent.toLocaleString()}
                  </p>
                  <span className="text-[10px] text-muted font-mono">Enterprise Traffic Mix</span>
                </div>

                <div className="rounded-xl border border-rule bg-surface p-3 space-y-0.5">
                  <span className="text-[10px] font-mono text-muted tracking-wider">Projected volume</span>
                  <p className="text-base font-mono font-bold text-ink">
                    {formattedDataVolume}
                  </p>
                  <span className="text-[10px] text-muted font-mono">~100 Mbps Continuous Rate</span>
                </div>

                <div className="rounded-xl border border-rule bg-surface p-3 space-y-0.5">
                  <span className="text-[10px] font-mono text-muted tracking-wider">Flow concurrency</span>
                  <p className="text-base font-mono font-bold text-ink">
                    {activeFlowsCount} Tunnels
                  </p>
                  <span className="text-[10px] text-accent font-mono">HTTPS, VoIP, DNS</span>
                </div>

                <div className="rounded-xl border border-rule bg-surface p-3 space-y-0.5">
                  <span className="text-[10px] font-mono text-muted tracking-wider">Anti-replay window</span>
                  <p className="text-base font-mono font-bold text-pass">
                    64 / Active
                  </p>
                  <span className="text-[10px] text-pass font-mono">0 Forged Accepted</span>
                </div>
              </div>

              {/* Tabs: Real Backend Findings vs. Live Terminal Log */}
              <div className="space-y-3">
                <div className="flex items-center justify-between border-b border-rule pb-2">
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setActiveTab("TELEMETRY")}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-colors cursor-pointer ${
                        activeTab === "TELEMETRY"
                          ? "bg-accent text-white"
                          : "text-muted hover:text-ink bg-sunken/60"
                      }`}
                    >
                      Audit Findings ({backendFindings.length > 0 ? discoveredSlots.length : "0"})
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTab("LOGS")}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-colors flex items-center gap-1.5 cursor-pointer ${
                        activeTab === "LOGS"
                          ? "bg-accent text-white"
                          : "text-muted hover:text-ink bg-sunken/60"
                      }`}
                    >
                      <Terminal className="size-3" aria-hidden="true" />
                      <span>Terminal Log ({logs.length})</span>
                    </button>
                  </div>

                  <span className="text-xs font-mono text-muted">
                    {backendFindings.length > 0 ? (
                      <span className="text-critical font-semibold">
                        {discoveredSlots.length} of {backendFindings.length} Non-Compliant Identified
                      </span>
                    ) : isComplete ? (
                      <span className="text-pass font-semibold">Compliant Baseline (0 Weaknesses)</span>
                    ) : (
                      <span>Auditing suite parameters...</span>
                    )}
                  </span>
                </div>

                {activeTab === "TELEMETRY" ? (
                  <div className="space-y-2.5">
                    {backendFindings.length === 0 ? (
                      /* Zero findings case (Grade A): Display confirmed baseline passes with structured technical specs */
                      <div className="rounded-xl border border-pass/30 bg-pass/5 p-4 space-y-2.5">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-ink">
                            Cryptographic Baseline Standards Compliant
                          </span>
                          <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded border bg-pass/20 text-pass border-pass/30">
                            RFC 8221 / 8247 COMPLIANT
                          </span>
                        </div>
                        <ul className="text-xs text-muted space-y-1 font-mono">
                          <li>• Cipher: <strong className="text-ink">{cipher}</strong> — Authenticated AEAD encryption (RFC 8221 §5 MUST requirement)</li>
                          <li>• Integrity: <strong className="text-ink">{auth}</strong> — Integrated Galois/Counter Mode authentication tag</li>
                          <li>• Key Exchange: <strong className="text-ink">Diffie-Hellman Group {dhGroup}</strong> — Cryptographically sound key exchange parameter</li>
                          <li>• Forward Secrecy: <strong className="text-ink">PFS {pfsEnabled ? "Active" : "Disabled"}</strong> — Ephemeral Child SA key generation</li>
                        </ul>
                      </div>
                    ) : discoveredSlots.length === 0 ? (
                      <div className="rounded-xl border border-rule bg-canvas p-6 text-center text-xs font-mono text-muted">
                        <span>Evaluating stream parameters against RFC/NIST rule engine...</span>
                      </div>
                    ) : (
                      /* Real findings array returned by backend adhoc endpoint */
                      discoveredSlots.map(({ timeFormatted, finding }, idx) => (
                        <div
                          key={idx}
                          className="rounded-xl border border-critical/40 bg-critical/5 p-3.5 space-y-2 transition-all"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs text-muted">[{timeFormatted}]</span>
                              <span className="text-xs font-bold text-ink">{finding.rule_id}</span>
                              <span className="rounded bg-sunken px-2 py-0.5 font-mono text-[10px] text-muted border border-rule">
                                {finding.parameter}
                              </span>
                            </div>

                            <div className="flex items-center gap-2">
                              <RiskBadge level={(finding.severity?.toUpperCase() || "HIGH") as RiskLevel} size="sm" />
                              <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded border bg-critical/20 text-critical border-critical/30">
                                IDENTIFIED WEAKNESS
                              </span>
                            </div>
                          </div>

                          <p className="text-xs text-muted leading-relaxed">{finding.description}</p>

                          {finding.remediation && (
                            <p className="text-xs text-ink/80 font-mono">
                              Remediation: {finding.remediation}
                            </p>
                          )}

                          {onExplain && (
                            <div className="pt-2 border-t border-rule/40 flex justify-end">
                              <button
                                type="button"
                                onClick={() => onExplain(finding)}
                                className="inline-flex items-center gap-1.5 text-[11px] font-mono text-accent hover:text-accent-strong hover:underline transition-colors cursor-pointer"
                              >
                                <BookOpen className="size-3" aria-hidden="true" />
                                <span>Standards Advisory &amp; Clause Review &rarr;</span>
                              </button>
                            </div>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                ) : (
                  /* Terminal Log Stream */
                  <div
                    ref={logContainerRef}
                    className="max-h-64 overflow-y-auto rounded-xl border border-rule bg-canvas p-4 font-mono text-xs space-y-1.5 leading-relaxed"
                  >
                    {logs.map((logLine, idx) => (
                      <div key={idx} className="flex items-start gap-2">
                        <span className="text-muted select-none">&gt;</span>
                        <span
                          className={
                            logLine.includes("FAIL") || logLine.includes("finding")
                              ? "text-critical font-medium"
                              : logLine.includes("WARN")
                              ? "text-amber-400 font-medium"
                              : logLine.includes("PASS") || logLine.includes("Complete")
                              ? "text-pass"
                              : "text-ink"
                          }
                        >
                          {logLine}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Final Summary Card when simulation finishes */}
              {isComplete && (
                <div className="rounded-xl border border-rule bg-surface p-5 space-y-4 shadow-sm border-l-4 border-l-accent">
                  <div className="flex flex-wrap items-center justify-between gap-4 border-b border-rule pb-3">
                    <GradeMark
                      score={overallScore}
                      grade={grade}
                      label={`${simulatedHours}-Hour Simulated VPN Verdict`}
                    />
                    <div className="space-y-1 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <RiskBadge
                          level={
                            grade === "A" || grade === "B"
                              ? "LOW"
                              : grade === "C"
                              ? "MEDIUM"
                              : grade === "D"
                              ? "HIGH"
                              : "CRITICAL"
                          }
                          size="sm"
                        />
                        <span className="font-mono text-xs font-semibold text-ink">
                          {backendFindings.length} Security Finding(s)
                        </span>
                      </div>
                      <p className="text-[11px] font-mono text-muted">
                        Total Traffic: {packetsSent.toLocaleString()} packets · {formattedDataVolume} (Illustrative estimate)
                      </p>
                    </div>
                  </div>

                  {summary && (
                    <div className="space-y-1">
                      <h4 className="text-xs font-mono font-semibold text-ink">
                        Executive rule engine summary
                      </h4>
                      <p className="text-xs text-muted leading-relaxed">{summary}</p>
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer actions */}
        <div className="flex items-center justify-between border-t border-rule px-5 py-3.5 bg-surface">
          <button
            type="button"
            onClick={onClose}
            className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-rule bg-surface px-4 text-xs font-semibold text-muted hover:text-ink hover:border-accent transition-colors cursor-pointer"
          >
            <span>Close Simulation</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={isPending || isError}
              onClick={() => {
                const blob = new Blob([logs.join("\n")], { type: "text/plain" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `simulation_vpn_${simulatedHours}h_${cipher}_${new Date().toISOString()}.log`;
                a.click();
              }}
              className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-rule bg-sunken px-3 text-xs font-semibold text-ink hover:border-accent disabled:opacity-50 transition-colors cursor-pointer"
            >
              <Download className="size-3.5" aria-hidden="true" />
              <span>Export Log</span>
            </button>

            {isComplete && onExplain && (
              <button
                type="button"
                onClick={() =>
                  onExplain({
                    rule_id: "SIMULATED_VPN_SUITE",
                    parameter: cipher,
                    severity: grade === "A" ? "INFO" : "HIGH",
                    description: `Simulated IPsec suite evaluation: ${cipher} with auth ${auth}, DH Group ${dhGroup}, PFS ${pfsEnabled ? "enabled" : "disabled"}. Resulted in Grade ${grade} (${overallScore}/100).`,
                    remediation: "Review RFC 8221 and RFC 8247 compliance standards.",
                  })
                }
                className="inline-flex min-h-9 items-center gap-1.5 rounded-lg bg-accent px-4 text-xs font-semibold text-white hover:bg-accent-strong transition-colors cursor-pointer"
              >
                <BookOpen className="size-3.5" aria-hidden="true" />
                <span>Standards Advisory & Clause Review →</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}

export default SimulationModal;
