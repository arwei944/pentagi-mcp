# ==================== 构建阶段 ====================
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ==================== 运行阶段 ====================
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git curl nmap && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY app.py .
COPY mcp_server.py .
COPY README.md .

ENV PYTHONUNBUFFERED=1
ENV PANEL_PORT=7860
ENV MCP_SSE_PORT=8765
ENV PENTAGI_MODE=demo

EXPOSE 7860 8765

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 CMD curl -f http://localhost:7860/ || exit 1

CMD ["python", "app.py"]