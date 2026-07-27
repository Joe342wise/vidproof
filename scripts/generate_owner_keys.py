#!/usr/bin/env python3
"""Generate X25519 owner key pair (run once, from project root).

Writes:
  storage/keys/owner.x25519.priv.pem   — private key (0600)
  storage/keys/owner.x25519.pub.b64    — base64 public key, for use with
                                         forensics/enroll.py --owner-pubkey-file

Safe to re-run: exits without overwriting if keys already exist.
"""
import base64
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

sys.path.insert(0, str(Path(__file__).parent.parent))

KEYS_DIR = Path("storage/keys")
PRIV_PATH = KEYS_DIR / "owner.x25519.priv.pem"
PUB_PATH = KEYS_DIR / "owner.x25519.pub.b64"


def main() -> int:
    if PRIV_PATH.exists() and PUB_PATH.exists():
        print(f"Owner keys already exist — not overwriting.")
        print(f"  Private key : {PRIV_PATH}")
        print(f"  Public key  : {PUB_PATH.read_text().strip()}")
        return 0

    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    priv = X25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    PRIV_PATH.write_bytes(pem)
    os.chmod(PRIV_PATH, 0o600)
    PUB_PATH.write_text(pub_b64 + "\n")

    print(f"Owner key pair generated.")
    print(f"  Private key : {PRIV_PATH}")
    print(f"  Public key  : {pub_b64}")
    print()
    print(f"Use with enroll:")
    print(f"  python forensics/enroll.py \\")
    print(f"    --camera-id cam-001 --serial SN001 --operator-id <you> \\")
    print(f"    --owner-pubkey-file {PUB_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
