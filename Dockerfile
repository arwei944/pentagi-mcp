# ============================================================
# PentAGI MCP Server v3.0 - Docker
# Multi-stage build for smaller final image

FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ============================================================
# Final stage - v3.0: single-process, no mcp_server.py needed
# ============================================================

FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends git curl nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application files
COPY app.py .
COPY requirements.txt .
COPY README.md .

# Environment
ENV PYTHONUNBUFFERED=1
ENV PANEL_PORT=7860
ENV PENTAGI_MODE=demo

# Expose port
EXPOSE 7860

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

# Start - single process, no subprocess
CMD ["python", "app.py"]