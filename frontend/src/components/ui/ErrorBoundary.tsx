import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertOctagon, Copy, Home, RefreshCw, Terminal } from "lucide-react";

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  copied: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
    copied: false,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null, copied: false };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("[Janus ErrorBoundary caught unhandled exception]:", error, errorInfo);
    this.setState({ errorInfo });
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null, copied: false });
    window.location.href = "/";
  };

  private handleReload = () => {
    window.location.reload();
  };

  private handleCopy = async () => {
    const details = [
      `Error: ${this.state.error?.name || "UnknownError"}: ${this.state.error?.message || "No message"}`,
      `Stack: ${this.state.error?.stack || "No stack trace available"}`,
      `Component Stack: ${this.state.errorInfo?.componentStack || "No component stack"}`,
      `URL: ${window.location.href}`,
      `User Agent: ${navigator.userAgent}`,
      `Timestamp: ${new Date().toISOString()}`,
    ].join("\n\n");

    try {
      await navigator.clipboard.writeText(details);
      this.setState({ copied: true });
      setTimeout(() => this.setState({ copied: false }), 2000);
    } catch {
      // Clipboard copy fallback
    }
  };

  public render() {
    if (this.state.hasError) {
      const errorMessage = this.state.error?.message || "An unexpected error disrupted the interface.";
      const errorStack = this.state.error?.stack || this.state.errorInfo?.componentStack;

      return (
        <div className="min-h-screen bg-[#0b0f19] text-[#f1f5f9] flex flex-col items-center justify-center p-4 sm:p-6 font-sans">
          <div className="w-full max-w-2xl rounded-2xl border border-red-500/30 bg-[#0f172a] p-6 sm:p-8 shadow-2xl space-y-6">
            <div className="flex items-start gap-4">
              <div className="rounded-xl bg-red-500/10 p-3 text-red-400 border border-red-500/20 shrink-0">
                <AlertOctagon size={28} />
              </div>
              <div className="space-y-1 min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px] font-bold uppercase tracking-wider text-red-400">
                    System Exception
                  </span>
                  <span className="text-muted text-xs">·</span>
                  <span className="font-mono text-xs text-muted">Janus UI Safeguard</span>
                </div>
                <h1 className="text-xl font-bold tracking-tight text-white">
                  {this.props.fallbackTitle || "Interface Rendering Interrupted"}
                </h1>
                <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
                  The client caught an unhandled runtime exception. Your data on the backend remains safe.
                </p>
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-[#020617] p-4 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400 border-b border-slate-800/80 pb-2">
                <div className="flex items-center gap-2">
                  <Terminal size={14} className="text-red-400" />
                  <span>Technical Diagnostics</span>
                </div>
                <button
                  type="button"
                  onClick={this.handleCopy}
                  className="inline-flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300 transition-colors cursor-pointer"
                >
                  <Copy size={12} />
                  <span>{this.state.copied ? "Copied to Clipboard!" : "Copy Report"}</span>
                </button>
              </div>
              <p className="font-mono text-xs text-red-300 font-semibold break-words">
                {errorMessage}
              </p>
              {errorStack && (
                <pre className="max-h-48 overflow-auto font-mono text-[11px] text-slate-500 leading-relaxed pt-1">
                  {errorStack}
                </pre>
              )}
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={this.handleReset}
                className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/60 px-4 py-2.5 text-xs font-semibold text-slate-200 hover:bg-slate-800 hover:text-white transition-all cursor-pointer"
              >
                <Home size={14} />
                <span>Return to Dashboard</span>
              </button>

              <button
                type="button"
                onClick={this.handleReload}
                className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-xs font-semibold text-white shadow-lg shadow-blue-600/30 hover:bg-blue-500 transition-all cursor-pointer"
              >
                <RefreshCw size={14} />
                <span>Reload Application</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
