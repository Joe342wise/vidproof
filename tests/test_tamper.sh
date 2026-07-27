#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CAMERA_ID="cam-tamper-test"
EVIDENCE_ID="ev-tamper-test"
STORAGE_DIR="storage"
SAMPLE_VIDEO="/tmp/vidproof_tamper_sample.mp4"
CAMERA_JSON="$STORAGE_DIR/metadata/cameras/$CAMERA_ID.json"
PRIVKEY="$STORAGE_DIR/keys/$CAMERA_ID.private.pem"
OWNER_PUB="$STORAGE_DIR/keys/owner.x25519.pub"
OWNER_PRIV="$STORAGE_DIR/keys/owner.x25519.priv.pem"
EVIDENCE_JSON="$STORAGE_DIR/metadata/evidence/$EVIDENCE_ID.json"
ENC_FILE="$STORAGE_DIR/evidence/$EVIDENCE_ID.enc"

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "[PASS] $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "[FAIL] $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

assert_field() {
  local json="$1" field="$2" expected="$3" label="$4"
  local actual
  actual=$(python3 -c "import json,sys; d=json.loads('''$json'''); print(str(d.get('result',{}).get('$field','')).lower())")
  if [ "$actual" = "$expected" ]; then
    pass "$label: $field=$expected"
  else
    fail "$label: expected $field=$expected, got $field=$actual"
  fi
}

echo "=== VidProof Tamper Tests ==="

# Cleanup stale test data from previous runs
chmod -f 644 "$EVIDENCE_JSON" "$ENC_FILE" 2>/dev/null || true
rm -f "$EVIDENCE_JSON" "$ENC_FILE" "$CAMERA_JSON" "$PRIVKEY"

# Setup: sample video
dd if=/dev/urandom of="$SAMPLE_VIDEO" bs=1024 count=64 2>/dev/null

# Setup: owner X25519 keypair
if [ ! -f "$OWNER_PUB" ]; then
  python3 -c "
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import base64, pathlib
pathlib.Path('storage/keys').mkdir(parents=True, exist_ok=True)
k = X25519PrivateKey.generate()
pathlib.Path('$OWNER_PRIV').write_bytes(k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
pathlib.Path('$OWNER_PUB').write_text(base64.b64encode(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())
"
fi

# Enroll camera
python forensics/enroll.py \
  --camera-id "$CAMERA_ID" --serial "TAMPER-SN" \
  --operator-id "tamper-tester" \
  --owner-pubkey-file "$OWNER_PUB" \
  --keys-dir "$STORAGE_DIR/keys" > /dev/null

# Capture evidence
python forensics/capture.py \
  --video-file "$SAMPLE_VIDEO" \
  --camera-json "$CAMERA_JSON" \
  --private-key "$PRIVKEY" \
  --evidence-id "$EVIDENCE_ID" \
  --storage-dir "$STORAGE_DIR" > /dev/null

echo ""
echo "--- Tamper Test 1: Bit-flip encrypted file ---"
# Flip one byte in the .enc file (byte offset 0, XOR with 0xFF)
cp "$ENC_FILE" "/tmp/enc_backup.enc"
python3 -c "
import pathlib
p = pathlib.Path('$ENC_FILE')
# Make writable, corrupt, restore permissions
import os
os.chmod(p, 0o644)
data = bytearray(p.read_bytes())
data[0] ^= 0xFF
p.write_bytes(bytes(data))
os.chmod(p, 0o444)
"
TAMPER1_OUT=$(python forensics/verify.py \
  --evidence-id "$EVIDENCE_ID" \
  --camera-json "$CAMERA_JSON" \
  --storage-dir "$STORAGE_DIR")
assert_field "$TAMPER1_OUT" "encryptedFileHashValid" "false" "Bit-flip .enc"
assert_field "$TAMPER1_OUT" "primaryDecision" "fail" "Bit-flip .enc"
# Restore the .enc file for subsequent tests
chmod 644 "$ENC_FILE"
cp "/tmp/enc_backup.enc" "$ENC_FILE"
chmod 444 "$ENC_FILE"

echo ""
echo "--- Tamper Test 2: Corrupt device signature ---"
# Copy evidence.json, flip one char in deviceSignature, verify with --evidence-json override
TAMPER_EVIDENCE="/tmp/tamper_evidence_sig.json"
# evidence.json is 0444; make a writable copy with corrupted signature
python3 -c "
import json, pathlib
ev = json.loads(pathlib.Path('$EVIDENCE_JSON').read_text())
sig = ev['deviceSignature']
# Flip one base64 character
chars = list(sig)
chars[4] = 'A' if chars[4] != 'A' else 'B'
ev['deviceSignature'] = ''.join(chars)
pathlib.Path('/tmp/tamper_evidence_sig.json').write_text(json.dumps(ev, indent=2))
"
TAMPER2_OUT=$(python forensics/verify.py \
  --evidence-id "$EVIDENCE_ID" \
  --camera-json "$CAMERA_JSON" \
  --storage-dir "$STORAGE_DIR" \
  --evidence-json "$TAMPER_EVIDENCE")
assert_field "$TAMPER2_OUT" "deviceSignatureValid" "false" "Corrupt signature"
assert_field "$TAMPER2_OUT" "primaryDecision" "fail" "Corrupt signature"

echo ""
echo "--- Tamper Test 3: Corrupt authTag ---"
TAMPER_EVIDENCE_TAG="/tmp/tamper_evidence_tag.json"
python3 -c "
import json, pathlib
ev = json.loads(pathlib.Path('$EVIDENCE_JSON').read_text())
tag = ev['authTag']
chars = list(tag)
chars[2] = 'A' if chars[2] != 'A' else 'B'
ev['authTag'] = ''.join(chars)
pathlib.Path('/tmp/tamper_evidence_tag.json').write_text(json.dumps(ev, indent=2))
"
TAMPER3_OUT=$(python forensics/verify.py \
  --evidence-id "$EVIDENCE_ID" \
  --camera-json "$CAMERA_JSON" \
  --owner-privkey "$OWNER_PRIV" \
  --storage-dir "$STORAGE_DIR" \
  --evidence-json "$TAMPER_EVIDENCE_TAG")
assert_field "$TAMPER3_OUT" "decryptionValid" "false" "Corrupt authTag"

echo ""
echo "--- Tamper Test 4: Corrupt nonce ---"
TAMPER_EVIDENCE_NONCE="/tmp/tamper_evidence_nonce.json"
python3 -c "
import json, pathlib
ev = json.loads(pathlib.Path('$EVIDENCE_JSON').read_text())
nonce = ev['nonce']
chars = list(nonce)
chars[2] = 'A' if chars[2] != 'A' else 'B'
ev['nonce'] = ''.join(chars)
pathlib.Path('/tmp/tamper_evidence_nonce.json').write_text(json.dumps(ev, indent=2))
"
TAMPER4_OUT=$(python forensics/verify.py \
  --evidence-id "$EVIDENCE_ID" \
  --camera-json "$CAMERA_JSON" \
  --owner-privkey "$OWNER_PRIV" \
  --storage-dir "$STORAGE_DIR" \
  --evidence-json "$TAMPER_EVIDENCE_NONCE")
assert_field "$TAMPER4_OUT" "decryptionValid" "false" "Corrupt nonce"

# Cleanup
rm -f "$SAMPLE_VIDEO" "/tmp/enc_backup.enc" \
  "/tmp/tamper_evidence_sig.json" \
  "/tmp/tamper_evidence_tag.json" \
  "/tmp/tamper_evidence_nonce.json"

echo ""
echo "=== TAMPER TEST RESULTS: $PASS_COUNT passed, $FAIL_COUNT failed ==="
[ "$FAIL_COUNT" -eq 0 ] || exit 1
