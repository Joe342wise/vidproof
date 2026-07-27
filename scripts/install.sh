#!/usr/bin/env bash
# install.sh — install Python packages, Fabric binaries, and build the Go adapter
#
# Run from the project root:
#   ./scripts/install.sh
#
# Safe to re-run: all steps are idempotent.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FABRIC_SAMPLES_DIR="${FABRIC_SAMPLES_DIR:-$HOME/fabric-samples}"

log() { echo "==> [install] $*"; }

cd "$PROJECT_ROOT"

# ---------------------------------------------------------------------------
# Python packages
# ---------------------------------------------------------------------------
log "Installing Python packages..."
pip install --quiet streamlit opencv-python-headless
log "Python packages installed."

# ---------------------------------------------------------------------------
# Hyperledger Fabric binaries and samples
# ---------------------------------------------------------------------------
if [[ -d "$FABRIC_SAMPLES_DIR" && -f "$FABRIC_SAMPLES_DIR/bin/peer" ]]; then
    log "Fabric binaries already present at $FABRIC_SAMPLES_DIR — skipping download."
else
    log "Downloading Hyperledger Fabric binaries and samples (this may take a few minutes)..."
    FABRIC_INSTALL_TMP="$(mktemp -d)"
    cd "$FABRIC_INSTALL_TMP"
    curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
    chmod +x install-fabric.sh
    # Install into HOME so fabric-samples ends up at ~/fabric-samples
    cd "$HOME"
    "$FABRIC_INSTALL_TMP/install-fabric.sh" docker binary samples
    rm -rf "$FABRIC_INSTALL_TMP"
    cd "$PROJECT_ROOT"
    log "Fabric installed to $FABRIC_SAMPLES_DIR"
fi

# ---------------------------------------------------------------------------
# Build fabric-adapter Go binary
# ---------------------------------------------------------------------------
log "Building fabric-adapter binary..."
(cd "$PROJECT_ROOT/fabric-adapter" && go build -o "$PROJECT_ROOT/bin/fabric-adapter" .)
log "Binary written to bin/fabric-adapter"

log ""
log "Install complete. Next: run ./scripts/setup.sh to do the full first-time setup."
