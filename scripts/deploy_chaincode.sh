#!/usr/bin/env bash
# deploy_chaincode.sh — full Fabric chaincode lifecycle for vidproof
# Usage: ./scripts/deploy_chaincode.sh [fabric-samples-dir]
#
# Assumes the test network is already up with a channel:
#   cd fabric-samples/test-network && ./network.sh up createChannel
#
# Example:
#   FABRIC_SAMPLES_DIR=~/fabric-samples ./scripts/deploy_chaincode.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

FABRIC_SAMPLES_DIR="${FABRIC_SAMPLES_DIR:-${1:-$(cd "$PROJECT_ROOT/../fabric-samples" 2>/dev/null && pwd || echo "")}}"
if [[ -z "$FABRIC_SAMPLES_DIR" || ! -d "$FABRIC_SAMPLES_DIR" ]]; then
  echo "ERROR: fabric-samples directory not found. Set FABRIC_SAMPLES_DIR or pass as argument." >&2
  exit 1
fi

NETWORK_DIR="$FABRIC_SAMPLES_DIR/test-network"
BIN_DIR="$FABRIC_SAMPLES_DIR/bin"
CONFIG_DIR="$FABRIC_SAMPLES_DIR/config"
CHAINCODE_DIR="$PROJECT_ROOT/chaincode/vidproof"

CC_NAME="vidproof"
CC_VERSION="${CC_VERSION:-1.0}"
CC_SEQUENCE="${CC_SEQUENCE:-1}"
CHANNEL="mychannel"
ORDERER_CA="$NETWORK_DIR/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

export PATH="$BIN_DIR:$PATH"
export FABRIC_CFG_PATH="$CONFIG_DIR"

log() { echo "==> $*"; }

# ---------------------------------------------------------------------------
# Vendor dependencies (required by Fabric Go builder)
# ---------------------------------------------------------------------------
log "Vendoring chaincode dependencies..."
(cd "$CHAINCODE_DIR" && go mod tidy && go mod vendor)

# ---------------------------------------------------------------------------
# Package
# ---------------------------------------------------------------------------
log "Packaging chaincode..."
peer lifecycle chaincode package \
  "$PROJECT_ROOT/${CC_NAME}.tar.gz" \
  --path "$CHAINCODE_DIR" \
  --lang golang \
  --label "${CC_NAME}_${CC_VERSION}"

# ---------------------------------------------------------------------------
# Install + Approve for Org1
# ---------------------------------------------------------------------------
log "Installing on Org1 peer..."
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
export CORE_PEER_ADDRESS="localhost:7051"

peer lifecycle chaincode install "$PROJECT_ROOT/${CC_NAME}.tar.gz"

CC_PACKAGE_ID=$(peer lifecycle chaincode queryinstalled \
  | grep "${CC_NAME}_${CC_VERSION}" | awk '{print $3}' | tr -d ',')
log "Package ID: $CC_PACKAGE_ID"

log "Approving for Org1..."
peer lifecycle chaincode approveformyorg \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --channelID "$CHANNEL" \
  --name "$CC_NAME" \
  --version "$CC_VERSION" \
  --package-id "$CC_PACKAGE_ID" \
  --sequence "$CC_SEQUENCE" \
  --tls \
  --cafile "$ORDERER_CA"

# ---------------------------------------------------------------------------
# Install + Approve for Org2
# ---------------------------------------------------------------------------
log "Installing on Org2 peer..."
export CORE_PEER_LOCALMSPID="Org2MSP"
export CORE_PEER_TLS_ROOTCERT_FILE="$NETWORK_DIR/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="$NETWORK_DIR/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp"
export CORE_PEER_ADDRESS="localhost:9051"

peer lifecycle chaincode install "$PROJECT_ROOT/${CC_NAME}.tar.gz"

log "Approving for Org2..."
peer lifecycle chaincode approveformyorg \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --channelID "$CHANNEL" \
  --name "$CC_NAME" \
  --version "$CC_VERSION" \
  --package-id "$CC_PACKAGE_ID" \
  --sequence "$CC_SEQUENCE" \
  --tls \
  --cafile "$ORDERER_CA"

# ---------------------------------------------------------------------------
# Check readiness
# ---------------------------------------------------------------------------
log "Checking commit readiness (both orgs must show true)..."
peer lifecycle chaincode checkcommitreadiness \
  --channelID "$CHANNEL" \
  --name "$CC_NAME" \
  --version "$CC_VERSION" \
  --sequence "$CC_SEQUENCE" \
  --tls \
  --cafile "$ORDERER_CA" \
  --output json

# ---------------------------------------------------------------------------
# Commit
# ---------------------------------------------------------------------------
log "Committing chaincode..."
peer lifecycle chaincode commit \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --channelID "$CHANNEL" \
  --name "$CC_NAME" \
  --version "$CC_VERSION" \
  --sequence "$CC_SEQUENCE" \
  --tls \
  --cafile "$ORDERER_CA" \
  --peerAddresses localhost:7051 \
  --tlsRootCertFiles "$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" \
  --peerAddresses localhost:9051 \
  --tlsRootCertFiles "$NETWORK_DIR/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
log "Verifying committed..."
peer lifecycle chaincode querycommitted \
  --channelID "$CHANNEL" \
  --name "$CC_NAME" \
  --cafile "$ORDERER_CA"

log "Done. Chaincode '$CC_NAME' v${CC_VERSION} (sequence ${CC_SEQUENCE}) deployed to channel '$CHANNEL'."
log "To upgrade: set CC_VERSION and CC_SEQUENCE to the next values and re-run."
