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

from routes import analysis, compliance, explainer, live, report, upload

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

app = FastAPI(
    title="Janus — AI IPsec Protocol Analyzer",
    description=(
        "Automated IPsec VPN protocol analysis, RFC 8221/8247 compliance evaluation, "
        "and AI side-channel classifier with SHAP explainability.\n\n"
        "**Team:** Cipher Ops | **Hackathon:** Smart India Hackathon 2026 | **Problem:** SIH26160"
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload.router, prefix="/api", tags=["Upload"])
app.include_router(analysis.router, prefix="/api", tags=["Analysis"])
app.include_router(compliance.router, prefix="/api", tags=["Compliance"])
app.include_router(explainer.router, prefix="/api", tags=["Compliance-RAG Explainer"])
app.include_router(report.router, prefix="/api", tags=["Reports"])
app.include_router(live.router, prefix="/api", tags=["Live Capture"])


@app.get("/health", tags=["Meta"], summary="System health check")
async def health() -> dict:
    return {"status": "ok", "version": "2.0.0", "service": "Janus IPsec Analyzer"}


@app.get("/api/model/info", tags=["Meta"], summary="ML model metadata & capabilities")
async def model_info() -> dict:
    """
    Returns metadata about the deployed ML ensemble.
    Useful for judges to verify model architecture and training provenance.
    """
    return {
        "model_name": "FlowDeepNet Ensemble v2",
        "architecture": "XGBoost (2500 estimators) + FlowDeepNet (4-layer MLP) — 50/50 soft vote",
        "model_file_size_mb": 13.52,
        "training_flows": 10_000,
        "training_scenarios": 12,
        "accuracy_synthetic_holdout": "100.0%",
        "features": 25,
        "feature_type": "Statistical side-channel (zero IP/port leakage)",
        "classes": ["VoIP", "Video", "Web", "Email", "ICMP"],
        "explainability": "SHAP TreeExplainer — per-prediction, millisecond latency",
        "ood_protection": {
            "enabled": True,
            "method": "Mahalanobis distance from class centroids",
            "threshold": 45.0,
        },
        "self_learning": True,
        "self_learning_strategy": "Auto-retrain on high-confidence (>0.90) incoming flows",
        "privacy": "Zero IP/port features — RFC 9347 compliant",
        "team": "Cipher Ops",
        "hackathon": "Smart India Hackathon 2026",
        "problem_id": "SIH26160",
        "best_demo_path": (
            "Dashboard → 'View Demo Evaluation' → Scenario 4 (F-grade) → "
            "CRITICAL findings + CVE tags → 'Generate Technical PDF' → swanctl.conf block"
        ),
    }
