#!/usr/bin/env bash
# start_fabric_network.sh — bring up a fresh Fabric test network and deploy chaincode
#
# Called by vidproof-fabric.service on start. Safe to re-run:
# tears down any existing network first, then does a clean bring-up.
#
# Usage:
#   FABRIC_SAMPLES_DIR=~/fabric-samples ./scripts/start_fabric_network.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FABRIC_SAMPLES_DIR="${FABRIC_SAMPLES_DIR:-$HOME/fabric-samples}"
NETWORK_DIR="$FABRIC_SAMPLES_DIR/test-network"

log() { echo "==> [fabric] $*"; }

if [[ ! -d "$NETWORK_DIR" ]]; then
    echo "ERROR: Fabric test-network not found at $NETWORK_DIR" >&2
    echo "       Run ./scripts/install.sh first." >&2
    exit 1
fi

export PATH="$FABRIC_SAMPLES_DIR/bin:$PATH"
export FABRIC_CFG_PATH="$FABRIC_SAMPLES_DIR/config"

# Tear down any prior run cleanly
log "Tearing down any existing network..."
(cd "$NETWORK_DIR" && ./network.sh down 2>/dev/null || true)

# Bring up peers + orderer + channel
log "Bringing up test network with channel 'mychannel'..."
(cd "$NETWORK_DIR" && ./network.sh up createChannel -ca)

# Deploy chaincode
log "Deploying vidproof chaincode..."
FABRIC_SAMPLES_DIR="$FABRIC_SAMPLES_DIR" "$SCRIPT_DIR/deploy_chaincode.sh"

log "Fabric network ready."
