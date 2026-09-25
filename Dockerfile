# =============================================================================
# Janus — Unified Production Container (Hugging Face Spaces & Cloud Deployment)
# Multi-stage build: Node.js frontend compiler + Debian Python ML runtime
# =============================================================================

# ── Stage 1: Compile Frontend SPA ────────────────────────────────────────────
FROM node:20-slim AS frontend-builder
WORKDIR /build/frontend

COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
# Build production assets with relative API base URL
ENV VITE_API_URL=""
ENV VITE_API_KEY=""
RUN npm run build

# ── Stage 2: Runtime Environment ─────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# System network dissection tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    tcpdump \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python ML dependencies with CPU-only PyTorch wheel
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir torch==2.3.1 --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r requirements.txt

# Copy backend code, models, and compliance rules
COPY pyproject.toml ./
COPY __init__.py ./
COPY backend/ ./backend/
COPY ml/ ./ml/
COPY compliance/ ./compliance/
COPY rag/ ./rag/
COPY parsing/ ./parsing/
COPY reports/ ./reports/
COPY dataset/ ./dataset/

# Copy compiled frontend from Stage 1 into backend static directory
COPY --from=frontend-builder /build/frontend/dist /app/frontend/dist

# Create runtime directories for captures, database, and generated PDF reports
RUN mkdir -p /app/captures /app/reports/output /app/dataset /app/data

# Non-root user required by Hugging Face Spaces (UID 1000)
RUN useradd -m -u 1000 user && \
    chown -R user:user /app
USER user

# Service port and runtime defaults
EXPOSE 7860
ENV PORT=7860
ENV HOST=0.0.0.0
ENV JANUS_REQUIRE_AUTH=true

# Health check to ensure service readiness before Cloudflare tunnel routing
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:${PORT:-7860}/health || exit 1

# Start FastAPI serving both backend API and compiled frontend (single worker to bound memory/CPU)
CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-7860} --workers 1"]
