#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  ULPF LIVE SERVER TEST — TERMINAL 1: LISTENER
# ═══════════════════════════════════════════════════════════════════════════
#  This script starts the ULPF network listener which:
#    - Binds on port 5514 (UDP + TCP)
#    - Processes all incoming syslog messages in real-time
#    - Displays live EPS (Events Per Second), packet count, byte count
#    - Stores all parsed events in the DuckDB event store
#    - Runs anomaly detection on every batch
#    - Auto-saves output to tests/live_output/
#
#  ╔═══════════════════════════════════════════════════════════════════════╗
#  ║  RUN THIS IN TERMINAL 1 FIRST, then run terminal_2_sender.sh       ║
#  ║  in a SECOND terminal tab.                                          ║
#  ╚═══════════════════════════════════════════════════════════════════════╝
#
#  Usage:
#    chmod +x tests/scripts/terminal_1_listener.sh
#    ./tests/scripts/terminal_1_listener.sh
#
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

LIVE_OUTPUT="$PROJECT_ROOT/tests/live_output"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LIVE_OUTPUT/listener_${TIMESTAMP}.log"

mkdir -p "$LIVE_OUTPUT"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║              ULPF LIVE SERVER TEST — TERMINAL 1: LISTENER           ║"
echo "╠═══════════════════════════════════════════════════════════════════════╣"
echo "║  Port         : 5514 (UDP + TCP)                                    ║"
echo "║  Workers      : 4 (multi-process)                                   ║"
echo "║  Backend      : DuckDB (air-gap compatible)                         ║"
echo "║  Output log   : $LOG_FILE"
echo "║  Press Ctrl+C : Graceful shutdown + metrics dump                    ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo "[✓] Virtual environment activated"
else
    echo "[!] No venv found. Run: python3 -m venv venv && pip install -r requirements.txt"
    exit 1
fi

# Clean old database for fresh test run
if [ -f "output/ulpf.db" ]; then
    BACKUP="output/ulpf_backup_${TIMESTAMP}.db"
    cp "output/ulpf.db" "$BACKUP"
    echo "[✓] Backed up existing DB to $BACKUP"
    rm -f "output/ulpf.db" "output/ulpf.db-wal" "output/ulpf.db-shm"
    echo "[✓] Cleaned old database for fresh test"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Starting ULPF listener... (all output logged + displayed)"
echo "  Now open TERMINAL 2 and run: ./tests/scripts/terminal_2_sender.sh"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Start the listener — output goes to both terminal and log file
venv/bin/python -u -m ulpf.main listen --port 5514 --workers 4 --protocol both

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Listener stopped. Log saved to: $LOG_FILE"
echo "════════════════════════════════════════════════════════════════"
