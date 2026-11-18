#!/bin/sh
# ULPF 10 - start the live SIEM (ingest + detections + SOAR + copilot + web console) on this machine.
#   scripts/start_siem.sh [pipeline.yaml]
set -eu
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
CFG="${1:-config/pipeline.live.yaml}"
echo "ULPF 10 - live SIEM"
echo "  config : $CFG"
echo "  console: http://127.0.0.1:8000/console/"
echo "  ingest : syslog UDP/TCP 5514, HTTP /api/v1/ingest/stream/<source>, OTLP /v1/logs"
if ! "$PY" -c "import ulpf.ulpf_core" 2>/dev/null; then
  echo "  [i] native core not found: checking release artifacts for high-speed engine..."
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o ulpf/ulpf_core.so https://github.com/DeadFromInside-skibidi/ULPFv9/releases/download/v10.0.0/ulpf_core.so 2>/dev/null || true
  fi
  if ! "$PY" -c "import ulpf.ulpf_core" 2>/dev/null; then
    echo "  [i] native core not built: running the Python engine; for full speed run scripts/build_native.sh"
  else
    echo "  [+] loaded high-speed native engine (ulpf_core.so)"
  fi
fi
( sleep 6; command -v xdg-open >/dev/null && xdg-open http://127.0.0.1:8000/console/ >/dev/null 2>&1 || true ) &
exec "$PY" -m ulpf.main run -c "$CFG"
