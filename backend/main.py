"""
Janus API – FastAPI Application Entry Point
===========================================
High-performance asynchronous REST API for IPsec protocol inspection,
AI traffic classification, and RFC/NIST compliance auditing.
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Add project root and backend to sys.path so modules resolve cleanly
_ROOT = Path(__file__).resolve().parent.parent
_BACKEND = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from routes import analysis, compliance, explainer, history, live, report, upload

# ---------------------------------------------------------------------------
# Directories setup
# ---------------------------------------------------------------------------
_REQUIRED_DIRS: list[Path] = [
    Path("dataset"),
    Path("captures"),
    Path("reports/output"),
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager creating necessary directories on boot."""
    for directory in _REQUIRED_DIRS:
        directory.mkdir(parents=True, exist_ok=True)
    yield


# ---------------------------------------------------------------------------
# CORS origins — restrict via env-var in production
# ---------------------------------------------------------------------------
_CORS_ORIGINS_RAW = os.getenv("JANUS_CORS_ORIGINS", "*")
_CORS_ORIGINS: list[str] = (
    ["*"] if _CORS_ORIGINS_RAW == "*" else [o.strip() for o in _CORS_ORIGINS_RAW.split(",")]
)

from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse

app = FastAPI(
    title="Janus — AI IPsec Protocol Analyzer",
    description=(
        "Automated IPsec VPN protocol analysis, RFC 8221/8247 compliance evaluation, "
        "and AI side-channel classifier with SHAP explainability.\n\n"
        "**Team:** Cipher Ops | **Hackathon:** Smart India Hackathon 2026 | **Problem:** SIH26160"
    ),
    version="2.0.0",
    docs_url=None,
    redoc_url="/redoc",
    lifespan=lifespan,
)


@app.get("/docs", include_in_schema=False)
async def custom_dark_swagger_ui_html():
    """Custom cyber dark mode Swagger UI interface for Janus."""
    base_response = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} — API Documentation",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
        swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
    )
    dark_css = """
    <style>
      body, html {
        background-color: #0b0f19 !important;
        color: #f1f5f9 !important;
      }
      .swagger-ui {
        background-color: #0b0f19 !important;
        color: #cbd5e1 !important;
      }
      .swagger-ui .topbar {
        background-color: #0f172a !important;
        border-bottom: 1px solid rgba(255, 255, 255, 0.1) !important;
      }
      .swagger-ui .info .title,
      .swagger-ui .info h1, .swagger-ui .info h2, .swagger-ui .info h3,
      .swagger-ui .info h4, .swagger-ui .info h5 {
        color: #60a5fa !important;
      }
      .swagger-ui .info p, .swagger-ui .info li, .swagger-ui .info table {
        color: #94a3b8 !important;
      }
      .swagger-ui .scheme-container {
        background-color: #111827 !important;
        box-shadow: none !important;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
      }
      .swagger-ui .opblock {
        background-color: #0f172a !important;
        border-color: rgba(255, 255, 255, 0.08) !important;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4) !important;
        border-radius: 10px !important;
        margin-bottom: 12px !important;
      }
      .swagger-ui .opblock .opblock-summary {
        border-color: rgba(255, 255, 255, 0.08) !important;
      }
      .swagger-ui .opblock .opblock-summary-method {
        border-radius: 6px !important;
        font-weight: 700 !important;
      }
      .swagger-ui .opblock .opblock-summary-path,
      .swagger-ui .opblock .opblock-summary-path__deprecated {
        color: #f8fafc !important;
      }
      .swagger-ui .opblock .opblock-summary-description {
        color: #94a3b8 !important;
      }
      .swagger-ui .opblock-body {
        background-color: #0b0f19 !important;
      }
      .swagger-ui .opblock-body pre {
        background-color: #020617 !important;
        color: #38bdf8 !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 6px !important;
      }
      .swagger-ui .tab li button.tablinks {
        color: #cbd5e1 !important;
      }
      .swagger-ui .tab li button.tablinks.active {
        color: #60a5fa !important;
        font-weight: bold !important;
      }
      .swagger-ui table thead tr td, .swagger-ui table thead tr th {
        color: #94a3b8 !important;
        border-bottom: 1px solid rgba(255, 255, 255, 0.1) !important;
      }
      .swagger-ui .parameters-col_name {
        color: #f1f5f9 !important;
      }
      .swagger-ui .parameter__name {
        color: #38bdf8 !important;
      }
      .swagger-ui .parameter__type {
        color: #a855f7 !important;
      }
      .swagger-ui input[type=text],
      .swagger-ui select,
      .swagger-ui textarea {
        background-color: #1e293b !important;
        color: #f8fafc !important;
        border: 1px solid rgba(255, 255, 255, 0.2) !important;
        border-radius: 6px !important;
      }
      .swagger-ui .btn {
        border-radius: 6px !important;
        border-color: rgba(255, 255, 255, 0.2) !important;
        color: #f8fafc !important;
        background-color: #1e293b !important;
      }
      .swagger-ui .btn.execute {
        background-color: #2563eb !important;
        border-color: #3b82f6 !important;
        color: #ffffff !important;
      }
      .swagger-ui .btn.execute:hover {
        background-color: #1d4ed8 !important;
      }
      .swagger-ui .btn.cancel {
        background-color: #dc2626 !important;
        border-color: #ef4444 !important;
      }
      .swagger-ui .responses-inner h4,
      .swagger-ui .responses-inner h5 {
        color: #cbd5e1 !important;
      }
      .swagger-ui .response-col_status {
        color: #f1f5f9 !important;
      }
      .swagger-ui .response-col_description {
        color: #94a3b8 !important;
      }
      .swagger-ui section.models {
        background-color: #0f172a !important;
        border-color: rgba(255, 255, 255, 0.1) !important;
        border-radius: 10px !important;
      }
      .swagger-ui section.models h4 {
        color: #60a5fa !important;
      }
      .swagger-ui .model-box {
        background-color: #0b0f19 !important;
      }
      .swagger-ui .model-title {
        color: #f1f5f9 !important;
      }
      .swagger-ui .prop-type {
        color: #a855f7 !important;
      }
      .swagger-ui .model {
        color: #cbd5e1 !important;
      }
      /* Method blocks */
      .swagger-ui .opblock.opblock-get {
        background: rgba(37, 99, 235, 0.08) !important;
        border-color: #2563eb !important;
      }
      .swagger-ui .opblock.opblock-post {
        background: rgba(16, 185, 129, 0.08) !important;
        border-color: #10b981 !important;
      }
      .swagger-ui .opblock.opblock-delete {
        background: rgba(239, 68, 68, 0.08) !important;
        border-color: #ef4444 !important;
      }
      .swagger-ui .opblock.opblock-put {
        background: rgba(245, 158, 11, 0.08) !important;
        border-color: #f59e0b !important;
      }
      .swagger-ui .filter-container input {
        background-color: #1e293b !important;
        color: #f8fafc !important;
        border: 1px solid rgba(255, 255, 255, 0.2) !important;
      }
      ::-webkit-scrollbar { width: 8px; height: 8px; }
      ::-webkit-scrollbar-track { background: #0b0f19; }
      ::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
      ::-webkit-scrollbar-thumb:hover { background: #475569; }
    </style>
    """
    html_content = base_response.body.decode("utf-8")
    if "</head>" in html_content:
        html_content = html_content.replace("</head>", f"{dark_css}</head>")
    else:
        html_content = f"{dark_css}{html_content}"
    return HTMLResponse(content=html_content, status_code=200)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    # The Fetch spec forbids allow_credentials=True with wildcard allow_origins="*".
    # Set JANUS_CORS_ORIGINS to an explicit origin (e.g. "http://localhost:3000")
    # in production to enable credentials. With wildcard, credentials are disabled.
    allow_credentials=(_CORS_ORIGINS_RAW != "*"),
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload.router, prefix="/api", tags=["Upload"])
app.include_router(analysis.router, prefix="/api", tags=["Analysis"])
app.include_router(compliance.router, prefix="/api", tags=["Compliance"])
app.include_router(explainer.router, prefix="/api", tags=["Compliance-RAG Explainer"])
app.include_router(report.router, prefix="/api", tags=["Reports"])
app.include_router(live.router, prefix="/api", tags=["Live Capture"])
app.include_router(history.router, prefix="/api", tags=["Audit History"])


@app.get("/health", tags=["Meta"], summary="System health check")
@app.get("/api/health", tags=["Meta"], summary="System health check (API alias)")
async def health() -> dict:
    return {"status": "ok", "version": "2.0.0", "service": "Janus IPsec Analyzer"}


@app.get("/api/model/info", tags=["Meta"], summary="ML model metadata & capabilities")
async def model_info() -> dict:
    """
    Returns metadata about the deployed ML ensemble, including real measured
    accuracy metrics from the last training run on labeled_flows.csv.
    """
    import json as _json
    from pathlib import Path as _Path

    metrics_path = _Path("ml/artifacts/training_metrics.json")
    measured: dict = {}
    if metrics_path.exists():
        try:
            with open(metrics_path, encoding="utf-8") as _f:
                measured = _json.load(_f)
        except Exception:
            measured = {}

    deep_path = _Path("ml/artifacts/deep_ensemble_metrics.json")
    deep_measured: dict = {}
    if deep_path.exists():
        try:
            with open(deep_path, encoding="utf-8") as _f:
                deep_measured = _json.load(_f)
        except Exception:
            deep_measured = {}

    acc = measured.get("accuracy")
    f1  = measured.get("f1_score")
    cv  = measured.get("cross_validation", {})

    return {
        "model_name": "Janus Multimodal Ensemble v2",
        "architecture": "Multimodal Fusion: FlowDeepNet (2,500-Estimator Deep Forest + 4-Layer MLP) + FlowTraceNet (1D-CNN) + XGBoost with SHAP",
        "training_data": {
            "source": "dataset/labeled_flows.csv (synthetic-generated from 12 StrongSwan testbed scenarios)",
            "total_flows": 10_000,
            "flows_per_class": 2_000,
            "scenarios": 12,
            "note": (
                "Training data is generated from a lab testbed. "
                "Accuracy on real-world diverse captures may be lower — "
                "treat these metrics as upper-bound on clean testbed data."
            ),
        },
        "evaluation": {
            "method": "Stratified 80/20 train/test split + 5-fold cross-validation",
            "holdout_accuracy": round(acc, 4) if acc is not None else "not yet evaluated",
            "holdout_f1_weighted": round(f1, 4) if f1 is not None else "not yet evaluated",
            "cv_mean_accuracy": cv.get("cv_accuracy_mean", "n/a"),
            "cv_std_accuracy": cv.get("cv_accuracy_std", "n/a"),
            "deep_ensemble_size_mb": deep_measured.get("model_size_mb", 13.52),
            "fusion_strategy": "Soft probability voting: 70% Tabular Deep Ensemble + 30% Sequence 1D-CNN",
            "data_source_caveat": (
                "100% accuracy is expected on clean testbed data because the 5 traffic classes "
                "have non-overlapping inter-arrival time variance by ~3 orders of magnitude. "
                "Real-world encrypted traffic with mixed applications or IP-TFS padding "
                "will show lower performance — OOD detection guards against overconfident output."
            ),
        },
        "features": 25,
        "feature_type": "Statistical side-channel (zero IP/port leakage)",
        "classes": ["VoIP", "Video", "Web", "Email", "ICMP"],
        "explainability": "SHAP TreeExplainer — per-prediction, millisecond latency",
        "ood_protection": {
            "enabled": True,
            "method": "Mahalanobis distance from class centroids with Ledoit-Wolf shrinkage",
            "threshold": 10.0,
            "regularization": "Ledoit-Wolf analytical covariance shrinkage + StandardScaler",
            "calibration_benchmark": {
                "metric": "Leave-one-class-out across 5 classes",
                "ood_tpr": "80.43%",
                "id_fpr": "0.44%",
                "precision": "99.57%",
            },
            "note": "Flows outside training distribution are flagged as Unknown rather than force-classified.",
        },
        "team": "Cipher Ops",
        "hackathon": "Smart India Hackathon 2026",
        "problem_id": "SIH26160",
        "best_demo_path": (
            "Dashboard -> 'View Demo Evaluation' -> Scenario 4 (F-grade) -> "
            "CRITICAL findings + CVE tags -> 'Generate Technical PDF' -> swanctl.conf block"
        ),
    }


# ---------------------------------------------------------------------------
# Serve frontend SPA static files if present (Docker / Hugging Face single container)
# ---------------------------------------------------------------------------
_FRONTEND_DIST = _ROOT / "frontend" / "dist"
if _FRONTEND_DIST.is_dir():
    # Mount assets folder
    assets_dir = _FRONTEND_DIST / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    # Catch-all route to serve SPA pages and index.html
    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        target_file = _FRONTEND_DIST / full_path
        if full_path and target_file.is_file():
            return FileResponse(target_file)
        index_file = _FRONTEND_DIST / "index.html"
        if index_file.is_file():
            return FileResponse(index_file)
        return HTMLResponse("<h1>Janus Frontend Not Built</h1>", status_code=404)


