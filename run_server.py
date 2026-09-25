"""
Janus Backend Server Runner
===========================
Configures verified environment variables and launches the FastAPI backend on port 9000
matching frontend/.env.local configuration with Windows asyncio hardening.
"""

import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

# Configure auth to match frontend/.env.local (VITE_API_KEY=janus-soc-internal-2026)
os.environ.setdefault("JANUS_REQUIRE_AUTH", "true")
os.environ.setdefault("JANUS_API_KEY", "janus-soc-internal-2026")
os.environ.setdefault("JANUS_TOKEN_SECRET", "janus-token-secret-salt-2026")

if __name__ == "__main__":
    # Harden against Windows proactor ConnectionResetError 10054 on SSE/client disconnect
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass

    import uvicorn

    port = int(os.getenv("PORT", "9000"))
    host = os.getenv("HOST", "127.0.0.1")
    print(f"Starting Janus Backend on http://{host}:{port} with auth enabled...")
    uvicorn.run("backend.main:app", host=host, port=port, log_level="info", loop="asyncio")
