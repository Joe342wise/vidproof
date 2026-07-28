#!/usr/bin/env python3
"""CLI: verify an RFC 3161 timestamp token against a known SHA-256 digest.

Usage:
    python forensics/tsa_verify.py \
        --tsr-file storage/tsa/ev-001.tsr \
        --hash-hex <sha256-hex> \
        --ca-cert infra/tsa/ca.crt \
        --tsa-cert infra/tsa/tsa.crt

Output (stdout):
    {"ok": true,  "result": {"valid": true,  "detail": "Verification: OK"}}
    {"ok": true,  "result": {"valid": false, "detail": "..."}}
    {"ok": false, "error": {"code": "...", "message": "..."}}
"""
import argparse
import json
import logging
import subprocess
from pathlib import Path

_log = logging.getLogger(__name__)


def verify_tsa_token(
    tsr_path: Path,
    hash_hex: str,
    ca_cert_path: Path,
    tsa_cert_path: Path,
) -> dict:
    """Verify an RFC 3161 timestamp token against a known SHA-256 digest.

    Returns {"valid": bool, "detail": str}.  Never raises.
    """
    if not tsr_path.exists():
        return {"valid": False, "detail": f"Token file not found: {tsr_path}"}
    for p, label in [(ca_cert_path, "ca_cert"), (tsa_cert_path, "tsa_cert")]:
        if not p.exists():
            return {"valid": False, "detail": f"Certificate not found ({label}): {p}"}

    try:
        proc = subprocess.run(
            [
                "openssl", "ts", "-verify",
                "-in", str(tsr_path),
                "-digest", hash_hex,
                "-sha256",
                "-CAfile", str(ca_cert_path),
                "-untrusted", str(tsa_cert_path),
            ],
            capture_output=True,
        )
        valid = proc.returncode == 0
        detail = (proc.stdout.decode(errors="replace") or
                  proc.stderr.decode(errors="replace")).strip()
        return {"valid": valid, "detail": detail}
    except Exception as exc:
        _log.warning("tsa_verify: unexpected error: %s", exc)
        return {"valid": False, "detail": str(exc)}


def fail(code: str, message: str) -> None:
    print(json.dumps({"ok": False, "error": {"code": code, "message": message}}))
    raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an RFC 3161 timestamp token")
    parser.add_argument("--tsr-file", required=True, help="Path to .tsr token file")
    parser.add_argument("--hash-hex", required=True, help="SHA-256 hex digest that was stamped")
    parser.add_argument("--ca-cert", required=True, help="TSA CA certificate (PEM)")
    parser.add_argument("--tsa-cert", required=True, help="TSA signing certificate (PEM)")
    args = parser.parse_args()

    tsr_path = Path(args.tsr_file)
    if not tsr_path.exists():
        fail("TSR_NOT_FOUND", f"Token file not found: {tsr_path}")

    for cert, label in [(args.ca_cert, "ca-cert"), (args.tsa_cert, "tsa-cert")]:
        if not Path(cert).exists():
            fail("CERT_NOT_FOUND", f"Certificate not found for --{label}: {cert}")

    try:
        bytes.fromhex(args.hash_hex)
    except ValueError:
        fail("INVALID_HASH", f"Not a valid hex string: {args.hash_hex!r}")

    result = subprocess.run(
        [
            "openssl", "ts", "-verify",
            "-in", str(tsr_path),
            "-digest", args.hash_hex,
            "-sha256",
            "-CAfile", args.ca_cert,
            "-untrusted", args.tsa_cert,
        ],
        capture_output=True,
    )

    valid = result.returncode == 0
    # openssl ts -verify writes "Verification: OK" to stdout on success,
    # and diagnostics to stderr on failure.
    detail = (result.stdout.decode(errors="replace") or
              result.stderr.decode(errors="replace")).strip()

    print(json.dumps({
        "ok": True,
        "result": {
            "valid": valid,
            "detail": detail,
        },
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
