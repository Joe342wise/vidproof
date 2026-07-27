#!/usr/bin/env bash
# install_services.sh — copy systemd units, reload daemon, enable all services.
#
# Run from the project root:
#   ./scripts/install_services.sh
#
# Requires sudo for writes to /etc/systemd/system/.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEMD_SRC="$SCRIPT_DIR/../infra/systemd"
SYSTEMD_DEST="/etc/systemd/system"

SERVICES=(
    vidproof-fabric
    vidproof-fabric-adapter
    vidproof-tsa
    vidproof-backend
    vidproof-dashboard
)

echo "Installing systemd service files (requires sudo)..."
for svc in "${SERVICES[@]}"; do
    sudo cp "$SYSTEMD_SRC/$svc.service" "$SYSTEMD_DEST/$svc.service"
    echo "  Copied $svc.service"
done

sudo systemctl daemon-reload

for svc in "${SERVICES[@]}"; do
    sudo systemctl enable "$svc"
    echo "  Enabled $svc"
done

echo ""
echo "Services installed and enabled. Start everything with:"
echo "  sudo systemctl start vidproof-fabric"
echo "  sudo systemctl start vidproof-fabric-adapter vidproof-tsa vidproof-backend vidproof-dashboard"
echo ""
echo "Check status:"
echo "  systemctl status 'vidproof-*'"
echo ""
echo "View logs:"
echo "  journalctl -u vidproof-backend -f"
