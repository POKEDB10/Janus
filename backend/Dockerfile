# =============================================================================
# Janus Backend — Production Dockerfile
# Multi-stage build: deps layer cached separately from app layer
# =============================================================================

# ── Stage 1: Dependency builder ───────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# System tools needed to compile scipy/numpy native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    tshark \
    tcpdump \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --prefix=/install --no-cache-dir -r requirements.txt

# ── Stage 2: Runtime image ────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Runtime system libs only (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    tcpdump \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy project source — order matters for layer caching
COPY pyproject.toml ./
COPY __init__.py ./
COPY backend/ ./backend/
COPY ml/ ./ml/
COPY compliance/ ./compliance/
COPY rag/ ./rag/
COPY parsing/ ./parsing/
COPY reports/ ./reports/
COPY labeling/ ./labeling/
COPY dataset/ ./dataset/

# Create required runtime directories
RUN mkdir -p /captures /reports/output /dataset /app/ml/models

# Non-root user for security
RUN useradd -m -u 1000 janus && chown -R janus:janus /app /captures /reports /dataset
USER janus

# Expose API port
EXPOSE 8000

# Health check used by docker compose
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Startup command — runs from project root so module paths resolve
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
