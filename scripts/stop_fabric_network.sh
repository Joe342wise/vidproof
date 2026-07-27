#!/usr/bin/env bash
# stop_fabric_network.sh — tear down the Fabric test network
#
# Called by vidproof-fabric.service ExecStop.

set -euo pipefail

FABRIC_SAMPLES_DIR="${FABRIC_SAMPLES_DIR:-$HOME/fabric-samples}"
NETWORK_DIR="$FABRIC_SAMPLES_DIR/test-network"

if [[ -d "$NETWORK_DIR" ]]; then
    export PATH="$FABRIC_SAMPLES_DIR/bin:$PATH"
    export FABRIC_CFG_PATH="$FABRIC_SAMPLES_DIR/config"
    (cd "$NETWORK_DIR" && ./network.sh down 2>/dev/null || true)
    echo "==> [fabric] Network stopped."
fi
