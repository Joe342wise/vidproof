#!/usr/bin/env bash
# start_tsa.sh — set up a self-signed RFC 3161 TSA and start the HTTP server
#
# Run from the project root:
#   ./scripts/start_tsa.sh [port]
#
# The first run generates infra/tsa/{ca.key,ca.crt,tsa.key,tsa.crt,tsa.cnf}.
# Subsequent runs skip generation and go straight to starting the server.
# Certificates are self-signed and valid for 10 years (prototype only).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TSA_DIR="$PROJECT_ROOT/infra/tsa"
PORT="${1:-2560}"

mkdir -p "$TSA_DIR"
cd "$PROJECT_ROOT"

log() { echo "==> [TSA] $*"; }

# ---------------------------------------------------------------------------
# Step 1: Generate CA key and self-signed certificate (once)
# ---------------------------------------------------------------------------
if [[ ! -f "$TSA_DIR/ca.key" ]]; then
    log "Generating TSA CA key..."
    openssl genrsa -out "$TSA_DIR/ca.key" 2048 2>/dev/null
fi

if [[ ! -f "$TSA_DIR/ca.crt" ]]; then
    log "Generating TSA CA certificate..."
    openssl req -new -x509 \
        -key "$TSA_DIR/ca.key" \
        -out "$TSA_DIR/ca.crt" \
        -days 3650 \
        -subj "/CN=VidProof TSA CA/O=VidProof/C=GB" \
        2>/dev/null
fi

# ---------------------------------------------------------------------------
# Step 2: Generate TSA signing key and certificate (once)
# ---------------------------------------------------------------------------
if [[ ! -f "$TSA_DIR/tsa.key" ]]; then
    log "Generating TSA signing key..."
    openssl genrsa -out "$TSA_DIR/tsa.key" 2048 2>/dev/null
fi

if [[ ! -f "$TSA_DIR/tsa.crt" ]]; then
    log "Generating TSA signing certificate..."

    # CSR
    openssl req -new \
        -key "$TSA_DIR/tsa.key" \
        -out "$TSA_DIR/tsa.csr" \
        -subj "/CN=VidProof TSA/O=VidProof/C=GB" \
        2>/dev/null

    # Extension file: extendedKeyUsage = timeStamping is mandatory for RFC 3161
    cat > "$TSA_DIR/tsa_ext.cnf" <<'EXTEOF'
[ tsa_ext ]
extendedKeyUsage = critical, timeStamping
basicConstraints = CA:false
EXTEOF

    # Sign with CA
    openssl x509 -req \
        -in "$TSA_DIR/tsa.csr" \
        -CA "$TSA_DIR/ca.crt" \
        -CAkey "$TSA_DIR/ca.key" \
        -CAcreateserial \
        -out "$TSA_DIR/tsa.crt" \
        -days 3650 \
        -extfile "$TSA_DIR/tsa_ext.cnf" \
        -extensions tsa_ext \
        2>/dev/null

    rm -f "$TSA_DIR/tsa.csr" "$TSA_DIR/tsa_ext.cnf"
    log "TSA certificate generated."
fi

# ---------------------------------------------------------------------------
# Step 3: Write TSA config (always regenerate so paths stay absolute)
# ---------------------------------------------------------------------------
cat > "$TSA_DIR/tsa.cnf" <<EOF
[ tsa ]
default_tsa = tsa_config1

[ tsa_config1 ]
dir                    = $TSA_DIR
serial                 = \$dir/tsaserial
crypto_device          = builtin
signer_cert            = \$dir/tsa.crt
certs                  = \$dir/ca.crt
signer_key             = \$dir/tsa.key
signer_digest          = sha256
default_policy         = 1.3.6.1.4.1.99999.2.1
digests                = sha256
accuracy               = secs:1
clock_precision_digits = 0
ordering               = yes
tsa_name               = yes
ess_cert_id_chain      = no
EOF

# Initialize serial counter if missing
if [[ ! -f "$TSA_DIR/tsaserial" ]]; then
    printf '%02d' 1 > "$TSA_DIR/tsaserial"
fi

# ---------------------------------------------------------------------------
# Step 4: Start the HTTP TSA server
# ---------------------------------------------------------------------------
log "Starting RFC 3161 TSA server on port $PORT..."
log "  CA cert:  $TSA_DIR/ca.crt"
log "  TSA cert: $TSA_DIR/tsa.crt"
log "  Config:   $TSA_DIR/tsa.cnf"
log "Press Ctrl-C to stop."

exec python3 "$PROJECT_ROOT/infra/tsa/tsa_server.py" \
    "$PORT" \
    "$TSA_DIR/tsa.cnf" \
    "$TSA_DIR/tsa.crt" \
    "$TSA_DIR/tsa.key" \
    "$TSA_DIR/ca.crt"
