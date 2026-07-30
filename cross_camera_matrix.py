#!/usr/bin/env python3
"""Cross-camera signature attribution matrix — VidProof Objective 2.

Verifies every enrolled camera's public key against every evidence record's
device signature. Correct behaviour: a signature verifies ONLY against the key
of the camera that actually produced it. Anything else is a false positive.

Run from the repo root:

    python cross_camera_matrix.py
    python cross_camera_matrix.py --storage-dir storage

Exit code 0 if the matrix is perfect, 1 if any cell is wrong.
"""
import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def check(pubkey_b64: str, hash_hex: str, sig_b64: str) -> bool:
    """Return True if sig_b64 is a valid Ed25519 signature over hash_hex."""
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64, validate=True))
        key.verify(base64.b64decode(sig_b64, validate=True), bytes.fromhex(hash_hex))
        return True
    except (InvalidSignature, ValueError):
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--storage-dir", type=Path, default=Path("storage"))
    args = ap.parse_args()

    cameras_dir = args.storage_dir / "metadata" / "cameras"
    evidence_dir = args.storage_dir / "metadata" / "evidence"

    if not cameras_dir.is_dir():
        print(f"ERROR: {cameras_dir} not found — are you in the repo root?", file=sys.stderr)
        return 2

    cameras = {}
    for p in sorted(cameras_dir.glob("*.json")):
        rec = json.loads(p.read_text())
        cameras[rec["cameraId"]] = rec["publicKeyEd25519"]

    evidence = []
    for p in sorted(evidence_dir.glob("*.json")):
        rec = json.loads(p.read_text())
        if rec.get("deviceSignature") and rec.get("plaintextHash"):
            evidence.append(rec)

    if not cameras:
        print("ERROR: no enrolled cameras found.", file=sys.stderr)
        return 2
    if not evidence:
        print("ERROR: no evidence records found.", file=sys.stderr)
        return 2

    cam_ids = list(cameras)
    width = max(len("evidence (source)"), max(len(e["evidenceId"]) + 10 for e in evidence))

    print(f"\nEnrolled cameras : {', '.join(cam_ids)}")
    print(f"Evidence records : {len(evidence)}\n")
    header = "evidence (source)".ljust(width) + "".join(f"  vs {c:<10}" for c in cam_ids)
    print(header)
    print("-" * len(header))

    errors = 0
    true_pos = true_neg = 0

    for ev in evidence:
        label = f"{ev['evidenceId']} ({ev['cameraId']})".ljust(width)
        cells = []
        for cid in cam_ids:
            got = check(cameras[cid], ev["plaintextHash"], ev["deviceSignature"])
            want = cid == ev["cameraId"]
            ok = got == want
            if not ok:
                errors += 1
                mark = "  !! FALSE POS" if got else "  !! FALSE NEG"
            else:
                mark = "  valid " if got else "  reject"
                if got:
                    true_pos += 1
                else:
                    true_neg += 1
            cells.append(f"{mark:<14}")
        print(label + "".join(cells))

    total = len(evidence) * len(cam_ids)
    print("-" * len(header))
    print(f"\nCells checked         : {total}")
    print(f"Correct attributions  : {true_pos}")
    print(f"Correct rejections    : {true_neg}")
    print(f"False positives/neg   : {errors}")

    if errors:
        print("\nRESULT: FAIL — attribution is not sound.")
        return 1

    print("\nRESULT: PASS — every signature verifies only against its own camera's key.")
    print("Pass condition met: correct attribution in both directions, zero false positives.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())