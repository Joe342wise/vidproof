#!/usr/bin/env bash
# setup.sh — first-time full stack deployment for VidProof
#
# Run from the project root:
#   ./scripts/setup.sh
#
# What this does (in order):
#   1. Install Python packages + Fabric binaries + build Go adapter
#   2. Generate owner X25519 key pair (idempotent)
#   3. Bring up Fabric test network and deploy vidproof chaincode
#   4. Install and start all systemd services
#
# After this completes:
#   Backend  → http://localhost:8000
#   Dashboard→ http://localhost:8501  (or via SSH tunnel)
#   TSA      → http://localhost:2560
#   Adapter  → http://localhost:8081

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log()  { echo ""; echo "===> $*"; echo ""; }
fail() { echo "ERROR: $*" >&2; exit 1; }

cd "$PROJECT_ROOT"

# ---------------------------------------------------------------------------
# Step 1: Install dependencies
# ---------------------------------------------------------------------------
log "Step 1/4 — Installing dependencies"
"$SCRIPT_DIR/install.sh"

# ---------------------------------------------------------------------------
# Step 2: Generate owner keys
# ---------------------------------------------------------------------------
log "Step 2/4 — Generating owner key pair"
python3 "$SCRIPT_DIR/generate_owner_keys.py"

# ---------------------------------------------------------------------------
# Step 3: Bring up Fabric network + deploy chaincode
# ---------------------------------------------------------------------------
log "Step 3/4 — Starting Fabric test network and deploying chaincode"
"$SCRIPT_DIR/start_fabric_network.sh"

# ---------------------------------------------------------------------------
# Step 4: Install and start systemd services
# ---------------------------------------------------------------------------
log "Step 4/4 — Installing systemd services"
"$SCRIPT_DIR/install_services.sh"

echo ""
echo "Starting services..."
sudo systemctl start vidproof-tsa
sudo systemctl start vidproof-backend
sudo systemctl start vidproof-dashboard
sudo systemctl start vidproof-fabric-adapter

echo ""
echo "=========================================================="
echo " VidProof deployment complete"
echo "=========================================================="
echo ""
echo "  Backend API : http://localhost:8000/docs"
echo "  Dashboard   : http://localhost:8501"
echo "  TSA server  : http://localhost:2560"
echo "  Fabric adpt : http://localhost:8081/health"
echo ""
echo " SSH tunnel (run locally to access dashboard):"
echo "   ssh -L 8501:127.0.0.1:8501 -L 8000:127.0.0.1:8000 personal_vps"
echo ""
echo " Logs:  journalctl -u vidproof-backend -f"
echo " Owner pubkey: $(cat storage/keys/owner.x25519.pub.b64 2>/dev/null || echo '(not found)')"
echo ""
