#!/usr/bin/env sh
# Build the optional compiled core (native/ulpf_core) into ulpf/ulpf_core.abi3.so.
# Needs Rust (rustup). The batch engine (native lane) is used once built;
# ULPF_NATIVE_LANE=0 turns it off (docs/STATUS.md, Phase 4).
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PY=${PYTHON:-python3}
export PYO3_PYTHON=$(command -v "$PY")
cd "$ROOT/native/ulpf_core"
cargo build --release
cp target/release/libulpf_core.so "$ROOT/ulpf/ulpf_core.abi3.so"
"$PY" -c "from ulpf import ulpf_core; print('ulpf_core', ulpf_core.version(), 'built; batch engine:', hasattr(ulpf_core, 'Engine'))"
