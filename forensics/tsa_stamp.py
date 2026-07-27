#!/usr/bin/env python3
"""CLI: request an RFC 3161 timestamp for a SHA-256 hex digest.

Usage:
    python forensics/tsa_stamp.py \
        --hash-hex <sha256-hex> \
        --tsa-url http://localhost:2560 \
        --out-file storage/tsa/ev-001.tsr

Output (stdout):
    {"ok": true,  "result": {"tsrPath": "...", "tsaTokenHash": "..."}}
    {"ok": false, "error": {"code": "...", "message": "..."}}
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import requests


def fail(code: str, message: str) -> None:
    print(json.dumps({"ok": False, "error": {"code": code, "message": message}}))
    raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Request an RFC 3161 timestamp token")
    parser.add_argument("--hash-hex", required=True, help="SHA-256 hex digest to timestamp")
    parser.add_argument("--tsa-url", required=True, help="RFC 3161 TSA HTTP endpoint")
    parser.add_argument("--out-file", required=True, help="Destination path for .tsr token")
    args = parser.parse_args()

    out_path = Path(args.out_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Validate hex
    try:
        bytes.fromhex(args.hash_hex)
    except ValueError:
        fail("INVALID_HASH", f"Not a valid hex string: {args.hash_hex!r}")

    fd, tsq_path = tempfile.mkstemp(suffix=".tsq")
    os.close(fd)
    tsq_path = Path(tsq_path)

    try:
        # Build timestamp query
        result = subprocess.run(
            [
                "openssl", "ts", "-query",
                "-sha256",
                "-digest", args.hash_hex,
                "-cert",
                "-out", str(tsq_path),
            ],
            capture_output=True,
        )
        if result.returncode != 0:
            fail("TSQ_FAILED", result.stderr.decode(errors="replace").strip())

        # POST to TSA
        try:
            resp = requests.post(
                args.tsa_url,
                data=tsq_path.read_bytes(),
                headers={"Content-Type": "application/timestamp-query"},
                timeout=15,
            )
        except requests.exceptions.ConnectionError as exc:
            fail("TSA_UNREACHABLE", f"Cannot connect to TSA at {args.tsa_url}: {exc}")

        if resp.status_code != 200:
            fail("TSA_HTTP_ERROR", f"TSA returned HTTP {resp.status_code}: {resp.text[:200]}")

        tsr_bytes = resp.content
        if not tsr_bytes:
            fail("TSA_EMPTY_RESPONSE", "TSA returned an empty response body")

        out_path.write_bytes(tsr_bytes)
        tsa_token_hash = hashlib.sha256(tsr_bytes).hexdigest()

    finally:
        tsq_path.unlink(missing_ok=True)

    print(json.dumps({
        "ok": True,
        "result": {
            "tsrPath": str(out_path),
            "tsaTokenHash": tsa_token_hash,
        },
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
