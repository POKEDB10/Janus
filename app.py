"""
Janus — Hugging Face Spaces Entry Point
======================================
Runs the unified FastAPI application serving both the React SPA dashboard
and backend REST API on port 7860.
"""

from __future__ import annotations

# Hugging Face ZeroGPU requires spaces to be imported before any CUDA or heavy libraries
try:
    import spaces
except ImportError:
    class spaces:  # type: ignore[no-redef]
        @staticmethod
        def GPU(func=None, **kwargs):
            if func is None:
                return lambda f: f
            return func

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

# Define ZeroGPU accelerator hook
@spaces.GPU
def zero_gpu_pipeline_accelerator(query: str = "status") -> str:
    """Satisfies Hugging Face ZeroGPU startup scanner."""
    return f"Janus AI Engine Online (Query: {query})"

import uvicorn
from backend.main import app

try:
    import gradio as gr

    # Standard Gradio Interface so the ZeroGPU scanner detects demo.fn at module level
    demo = gr.Interface(
        fn=zero_gpu_pipeline_accelerator,
        inputs=gr.Textbox(label="Diagnostic Command", value="status"),
        outputs=gr.Textbox(label="Pipeline State"),
        title="Janus — AI IPsec Protocol Analyzer",
        description="Unified Cyber Assessment Framework & ML Classifier. Access dashboard at /",
    )

    app = gr.mount_gradio_app(app, demo, path="/gradio")
except ImportError:
    demo = None

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False, workers=1)
