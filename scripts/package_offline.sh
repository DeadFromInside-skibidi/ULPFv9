#!/bin/bash
# Build a self-contained offline install bundle for air-gapped hosts.
# Run on a connected machine with the SAME OS / CPU architecture / Python
# version as the target (wheels are platform-specific).
set -e
cd "$(dirname "$0")/.."

OUTPUT_DIR="ulpf-offline-pkg"
TAR_NAME="ulpf-plugin-offline.tar.gz"

echo "[1/4] Cleaning old builds..."
rm -rf "$OUTPUT_DIR" "$TAR_NAME" dist
mkdir -p "$OUTPUT_DIR/wheels"

echo "[2/4] Building the ULPF wheel..."
python3 -m pip install --quiet build
python3 -m build --wheel
cp dist/*.whl "$OUTPUT_DIR/wheels/"

echo "[3/4] Downloading runtime dependencies (server profile: core + API + TUI)..."
python3 -m pip download -d "$OUTPUT_DIR/wheels" \
    "duckdb>=1.0.0" "pyarrow>=14.0.0" "orjson>=3.9.0" "python-dateutil>=2.8.0" "psutil>=5.9.0" \
    "fastapi>=0.100.0" "uvicorn[standard]>=0.23.0" "python-multipart>=0.0.6" \
    "rich>=13.0.0" "textual>=0.40.0"
cp -r config/ "$OUTPUT_DIR/config/"
cp -r demo_data/ "$OUTPUT_DIR/demo_data/"

cat << 'EOF' > "$OUTPUT_DIR/install.sh"
#!/bin/bash
set -e
cd "$(dirname "$0")"
pip install --no-index --find-links=wheels/ wheels/ulpf-*.whl "ulpf[api,tui]"
echo "Installed. Try: ulpf process --files 'demo_data/*.log'"
EOF
chmod +x "$OUTPUT_DIR/install.sh"

echo "[4/4] Creating tarball..."
tar -czf "$TAR_NAME" "$OUTPUT_DIR/"
echo "Created $TAR_NAME — transfer it to the air-gapped host and run install.sh"
