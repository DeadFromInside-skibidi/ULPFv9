# ULPF — Universal Log Pre-processing Framework
# Multi-stage build: dependencies cached in a builder stage, lean non-root runtime.

FROM python:3.11-slim AS builder
WORKDIR /build
COPY requirements.txt .
# The desktop GUI (PySide6) and report tooling are not needed in the server image
RUN grep -viE '^(PySide6|matplotlib)' requirements.txt > requirements.server.txt \
 && pip install --no-cache-dir --prefix=/install -r requirements.server.txt


FROM python:3.11-slim
RUN groupadd -r ulpf && useradd -r -g ulpf -d /app -s /sbin/nologin ulpf
WORKDIR /app
COPY --from=builder /install /usr/local

COPY ulpf/ ulpf/
COPY config/ config/
COPY demo_data/ demo_data/
COPY benchmarks/ benchmarks/

# All mutable state (event store, evidence, spool, learned parsers, signing key)
# lives under ULPF_DATA_DIR, which is a volume
ENV ULPF_DATA_DIR=/app/output \
    ULPF_OFFLINE=1 \
    PYTHONUNBUFFERED=1
RUN mkdir -p /app/output && chown -R ulpf:ulpf /app
USER ulpf

# 8000: REST API + HTTP/OTLP ingest   5514: syslog UDP+TCP   6514: syslog TLS (when configured)
EXPOSE 8000 5514/udp 5514/tcp 6514/tcp

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=5).status == 200 else 1)"

VOLUME ["/app/output"]

# Default: the live pipeline (journal -> workers -> outputs) with the REST API.
# Set ULPF_API_KEY (admin) or mount an api.keys_file; ULPF_INGEST_KEY protects HTTP/OTLP ingest.
# One-shot CLI example: docker run --rm -v $PWD/logs:/logs ulpf python -m ulpf.main process --files "/logs/*.log"
CMD ["python", "-m", "ulpf.main", "run", "--config", "/app/config/pipeline.docker.yaml"]
