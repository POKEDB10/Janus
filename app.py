"""
Janus — Hugging Face Spaces Entry Point
======================================
Runs the unified FastAPI application serving both the React SPA dashboard
and backend REST API on port 7860.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_BACKEND = _ROOT / "backend"
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

# Safe default environment settings for cloud demo execution
os.environ.setdefault("JANUS_REQUIRE_AUTH", "false")
os.environ.setdefault("JANUS_API_KEY", "janus-demo-key-2026")
os.environ.setdefault("JANUS_TOKEN_SECRET", "janus-token-secret-salt-2026")
os.environ.setdefault("JANUS_CORS_ORIGINS", "*")

import uvicorn
from backend.main import app

try:
    import gradio as gr

    # Optional Gradio bridge mount for Hugging Face discovery
    with gr.Blocks(title="Janus — AI IPsec Analyzer") as demo:
        gr.Markdown(
            "# Janus — IPsec Protocol Analyzer\n\n"
            "The full cyber interface is running at root: **[Open Janus Dashboard](/)**\n\n"
            "- [API Documentation](/docs)\n"
            "- [Health Check](/health)\n"
        )
    app = gr.mount_gradio_app(app, demo, path="/gradio")
except Exception:
    pass

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False, workers=1)
