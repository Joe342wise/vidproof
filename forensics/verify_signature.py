#!/usr/bin/env python3
import base64
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def fail(code: str, message: str, exit_code: int = 1) -> int:
    print(json.dumps({"ok": False, "error": {"code": code, "message": message}}))
    return exit_code


def main() -> int:
    if len(sys.argv) != 4:
        return fail("USAGE", "Usage: verify_signature.py <public-key-base64> <hash-hex> <signature-base64>", 2)

    try:
        public_key_bytes = base64.b64decode(sys.argv[1], validate=True)
        message = bytes.fromhex(sys.argv[2])
        signature = base64.b64decode(sys.argv[3], validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, message)
    except InvalidSignature:
        print(json.dumps({"ok": True, "result": {"valid": False}}))
        return 0
    except ValueError as exc:
        return fail("INVALID_INPUT", str(exc))

    print(json.dumps({"ok": True, "result": {"valid": True}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
