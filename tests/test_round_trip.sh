#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CAMERA_ID="cam-rt-test"
EVIDENCE_ID="ev-rt-test"
STORAGE_DIR="storage"
SAMPLE_VIDEO="/tmp/vidproof_test_sample.mp4"
CAMERA_JSON="$STORAGE_DIR/metadata/cameras/$CAMERA_ID.json"
PRIVKEY="$STORAGE_DIR/keys/$CAMERA_ID.private.pem"
OWNER_PUB="$STORAGE_DIR/keys/owner.x25519.pub"
OWNER_PRIV="$STORAGE_DIR/keys/owner.x25519.priv.pem"
EVIDENCE_JSON="$STORAGE_DIR/metadata/evidence/$EVIDENCE_ID.json"

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }

echo "=== VidProof Round-Trip Test ==="

# Setup: create a sample video (random bytes stand in for a real .mp4)
dd if=/dev/urandom of="$SAMPLE_VIDEO" bs=1024 count=64 2>/dev/null
echo "Created sample video: $SAMPLE_VIDEO"

# Setup: generate owner X25519 keypair if not present
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
  echo "Generated owner X25519 keypair"
fi

# Step 1: Enroll camera
echo ""
echo "--- Step 1: Enroll camera ---"
ENROLL_OUT=$(python forensics/enroll.py \
  --camera-id "$CAMERA_ID" \
  --serial "TEST-SN-001" \
  --operator-id "test-operator" \
  --owner-pubkey-file "$OWNER_PUB" \
  --keys-dir "$STORAGE_DIR/keys")

echo "$ENROLL_OUT"
python3 -c "import sys, json; d=json.loads('$ENROLL_OUT'); sys.exit(0 if d.get('ok') else 1)" \
  || fail "Enrollment returned ok=false"
[ -f "$CAMERA_JSON" ] || fail "camera.json not created"
[ -f "$PRIVKEY" ]     || fail "Private key not created"
pass "Camera enrolled"

# Step 2: Capture evidence
echo ""
echo "--- Step 2: Capture evidence ---"
CAPTURE_OUT=$(python forensics/capture.py \
  --video-file "$SAMPLE_VIDEO" \
  --camera-json "$CAMERA_JSON" \
  --private-key "$PRIVKEY" \
  --evidence-id "$EVIDENCE_ID" \
  --storage-dir "$STORAGE_DIR")

echo "$CAPTURE_OUT"
python3 -c "import sys, json; d=json.loads('$CAPTURE_OUT'); sys.exit(0 if d.get('ok') else 1)" \
  || fail "Capture returned ok=false"
[ -f "$EVIDENCE_JSON" ]                                 || fail "evidence.json not created"
[ -f "$STORAGE_DIR/evidence/$EVIDENCE_ID.enc" ]         || fail ".enc file not created"
pass "Evidence captured"

# Step 3: Record md5sum of evidence.json before verify
EVIDENCE_MD5_BEFORE=$(md5sum "$EVIDENCE_JSON" | awk '{print $1}')

# Step 4: Verify (signature + hash only, no decryption)
echo ""
echo "--- Step 3: Verify (no decryption) ---"
VERIFY_OUT=$(python forensics/verify.py \
  --evidence-id "$EVIDENCE_ID" \
  --camera-json "$CAMERA_JSON" \
  --verifier-id "test-operator" \
  --storage-dir "$STORAGE_DIR")

echo "$VERIFY_OUT"
python3 -c "
import sys, json
d = json.loads('$VERIFY_OUT')
r = d.get('result', {})
assert d.get('ok'), 'ok=false'
assert r.get('encryptedFileHashValid'), 'encryptedFileHashValid=false'
assert r.get('deviceSignatureValid'), 'deviceSignatureValid=false'
assert r.get('primaryDecision') == 'PASS', f'primaryDecision={r.get(\"primaryDecision\")}'
" || fail "Verification (no decryption) failed checks"
pass "Verified without decryption: PASS"

# Step 5: Verify evidence.json was not mutated
EVIDENCE_MD5_AFTER=$(md5sum "$EVIDENCE_JSON" | awk '{print $1}')
[ "$EVIDENCE_MD5_BEFORE" = "$EVIDENCE_MD5_AFTER" ] \
  || fail "evidence.json was mutated during verification"
pass "evidence.json is unchanged after verification"

# Step 6: Verify with decryption
echo ""
echo "--- Step 4: Verify (with decryption) ---"
VERIFY_DEC_OUT=$(python forensics/verify.py \
  --evidence-id "$EVIDENCE_ID" \
  --camera-json "$CAMERA_JSON" \
  --owner-privkey "$OWNER_PRIV" \
  --verifier-id "test-operator" \
  --storage-dir "$STORAGE_DIR")

echo "$VERIFY_DEC_OUT"
python3 -c "
import sys, json
d = json.loads('$VERIFY_DEC_OUT')
r = d.get('result', {})
assert d.get('ok'), 'ok=false'
assert r.get('decryptionAttempted'), 'decryptionAttempted=false'
assert r.get('decryptionValid'), 'decryptionValid=false'
assert r.get('plaintextHashMatchesEvidence'), 'plaintextHashMatchesEvidence=false'
assert r.get('primaryDecision') == 'PASS', f'primaryDecision={r.get(\"primaryDecision\")}'
" || fail "Verification (with decryption) failed checks"
pass "Verified with decryption: PASS, plaintext hash matches"

# Cleanup
rm -f "$SAMPLE_VIDEO"

echo ""
echo "=== ALL ROUND-TRIP TESTS PASSED ==="
