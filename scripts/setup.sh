#!/usr/bin/env bash
# setup.sh — first-time full stack deployment for VidProof
#
# Run from the project root:
#   ./scripts/setup.sh
#
# What this does (in order):
#   1. Generate owner X25519 key pair (idempotent)
#   2. Bring up Fabric test network and deploy vidproof chaincode
#   3. Build and start all Docker Compose services
#
# After this completes:
#   Backend  → http://localhost:8010
#   Dashboard→ http://localhost:8501  (or via SSH tunnel)
#   TSA      → http://localhost:2560
#   Adapter  → http://localhost:8081

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FABRIC_SAMPLES_DIR="${FABRIC_SAMPLES_DIR:-$HOME/fabric-samples}"

log()  { echo ""; echo "===> $*"; echo ""; }
fail() { echo "ERROR: $*" >&2; exit 1; }

cd "$PROJECT_ROOT"

command -v docker >/dev/null || fail "Docker is not installed."
docker compose version >/dev/null 2>&1 || fail "Docker Compose V2 is not installed."

# ---------------------------------------------------------------------------
# Step 1: Generate owner keys
# ---------------------------------------------------------------------------
log "Step 1/3 — Generating owner key pair"
python3 "$SCRIPT_DIR/generate_owner_keys.py"

# ---------------------------------------------------------------------------
# Step 2: Bring up Fabric network + deploy chaincode
# ---------------------------------------------------------------------------
log "Step 2/3 — Starting Fabric test network and deploying chaincode"

if [[ ! -d "$FABRIC_SAMPLES_DIR" || ! -f "$FABRIC_SAMPLES_DIR/bin/peer" ]]; then
    log "Fabric binaries not found — downloading (this may take a few minutes)..."
    cd "$HOME"
    FABRIC_INSTALL_TMP="$(mktemp -d)"
    curl -sSLO --output-dir "$FABRIC_INSTALL_TMP" \
        https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
    chmod +x "$FABRIC_INSTALL_TMP/install-fabric.sh"
    "$FABRIC_INSTALL_TMP/install-fabric.sh" docker binary samples
    rm -rf "$FABRIC_INSTALL_TMP"
    cd "$PROJECT_ROOT"
fi

FABRIC_SAMPLES_DIR="$FABRIC_SAMPLES_DIR" "$SCRIPT_DIR/start_fabric_network.sh"

# ---------------------------------------------------------------------------
# Step 3: Build and start Docker Compose services
# ---------------------------------------------------------------------------
log "Step 3/3 — Building and starting Docker Compose services"
FABRIC_SAMPLES_DIR="$FABRIC_SAMPLES_DIR" docker compose up -d --build

echo ""
echo "=========================================================="
echo " VidProof deployment complete"
echo "=========================================================="
echo ""
echo "  Backend API : http://localhost:8010/docs"
echo "  Dashboard   : http://localhost:8501"
echo "  TSA server  : http://localhost:2560"
echo "  Fabric adpt : http://localhost:8081/health"
echo ""
echo " SSH tunnel (run locally to access dashboard):"
echo "   ssh -L 8501:127.0.0.1:8501 -L 8010:127.0.0.1:8010 personal_vps"
echo ""
echo " Logs:  docker compose logs -f"
echo " Owner pubkey: $(cat storage/keys/owner.x25519.pub.b64 2>/dev/null || echo '(not found)')"
echo ""
