#!/usr/bin/env python3
import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def fail(code: str, message: str, exit_code: int = 1) -> int:
    print(json.dumps({"ok": False, "error": {"code": code, "message": message}}))
    return exit_code


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    private_key = Ed25519PrivateKey.generate()
    private_raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_raw, public_raw


def write_private_key(path: Path, private_raw: bytes) -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(private_raw)
    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)
    os.chmod(path, 0o600)


def build_camera_record(
    camera_id: str,
    device_serial: str,
    operator_id: str,
    public_key_raw: bytes,
    owner_pubkey_b64: str,
) -> dict:
    return {
        "cameraId": camera_id,
        "deviceSerial": device_serial,
        "publicKeyEd25519": base64.b64encode(public_key_raw).decode(),
        "prnuReferenceHash": "",
        "ownerPublicKey": owner_pubkey_b64,
        "authorizationPolicy": "default",
        "enrollmentTimestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "operatorId": operator_id,
    }


def write_camera_json(record: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{record['cameraId']}.json"
    path.write_text(json.dumps(record, indent=2))
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Enroll a camera and generate its Ed25519 key pair.")
    parser.add_argument("--camera-id", required=True, help="Unique camera identifier (e.g. cam-001)")
    parser.add_argument("--serial", required=True, help="Device serial number")
    parser.add_argument("--operator-id", required=True, help="Operator or investigator ID")
    parser.add_argument("--owner-pubkey-file", required=True, help="Path to owner X25519 public key (base64 one-liner)")
    parser.add_argument("--out-dir", default="storage/metadata/cameras", help="Directory for camera.json output")
    parser.add_argument("--keys-dir", default="storage/keys", help="Directory for private key output")
    args = parser.parse_args()

    owner_pubkey_path = Path(args.owner_pubkey_file)
    try:
        owner_pubkey_b64 = owner_pubkey_path.read_text().strip()
    except OSError as exc:
        return fail("READ_FAILED", f"Cannot read owner public key: {exc}")

    if not owner_pubkey_b64:
        return fail("INVALID_INPUT", "Owner public key file is empty")

    try:
        base64.b64decode(owner_pubkey_b64, validate=True)
    except Exception:
        return fail("INVALID_INPUT", "Owner public key is not valid base64")

    try:
        private_raw, public_raw = generate_ed25519_keypair()
    except Exception as exc:
        return fail("KEYGEN_FAILED", f"Key generation failed: {exc}")

    privkey_path = Path(args.keys_dir) / f"{args.camera_id}.private.pem"
    try:
        write_private_key(privkey_path, private_raw)
    except OSError as exc:
        return fail("WRITE_FAILED", f"Cannot write private key: {exc}")

    record = build_camera_record(
        camera_id=args.camera_id,
        device_serial=args.serial,
        operator_id=args.operator_id,
        public_key_raw=public_raw,
        owner_pubkey_b64=owner_pubkey_b64,
    )

    try:
        camera_json_path = write_camera_json(record, Path(args.out_dir))
    except OSError as exc:
        return fail("WRITE_FAILED", f"Cannot write camera.json: {exc}")

    print(json.dumps({
        "ok": True,
        "result": {
            "cameraId": record["cameraId"],
            "cameraJsonPath": str(camera_json_path),
            "privateKeyPath": str(privkey_path),
        },
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
