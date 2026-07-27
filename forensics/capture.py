#!/usr/bin/env python3
import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from forensics.crypto_core import (
    encrypt_aes_gcm,
    sha256_bytes,
    sha256_file,
    sign_plaintext_hash,
    wrap_aes_key,
)


def fail(code: str, message: str, exit_code: int = 1) -> int:
    print(json.dumps({"ok": False, "error": {"code": code, "message": message}}))
    return exit_code


def run_capture(
    video_path: Path,
    camera_json_path: Path,
    privkey_path: Path,
    evidence_id: str,
    storage_dir: Path,
) -> dict:
    try:
        plaintext = video_path.read_bytes()
    except OSError as exc:
        raise OSError(f"Cannot read video file: {exc}") from exc

    try:
        camera = json.loads(camera_json_path.read_text())
    except OSError as exc:
        raise OSError(f"Cannot read camera.json: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"camera.json is not valid JSON: {exc}") from exc

    plaintext_hash = sha256_bytes(plaintext)

    try:
        device_signature = sign_plaintext_hash(plaintext_hash, privkey_path)
    except Exception as exc:
        raise RuntimeError(f"Signing failed: {exc}") from exc

    try:
        aes_key, ciphertext, nonce_b64, auth_tag_b64 = encrypt_aes_gcm(plaintext)
    except Exception as exc:
        raise RuntimeError(f"Encryption failed: {exc}") from exc

    try:
        wrapped_key = wrap_aes_key(aes_key, camera["ownerPublicKey"])
    except Exception as exc:
        raise RuntimeError(f"Key wrapping failed: {exc}") from exc
    finally:
        # Zero out the raw AES key bytes immediately after wrapping
        aes_key = b"\x00" * len(aes_key)

    enc_dir = storage_dir / "evidence"
    enc_dir.mkdir(parents=True, exist_ok=True)
    enc_path = enc_dir / f"{evidence_id}.enc"

    try:
        enc_path.write_bytes(ciphertext)
    except OSError as exc:
        raise OSError(f"Cannot write encrypted evidence: {exc}") from exc

    try:
        encrypted_file_hash = sha256_file(enc_path)
    except OSError as exc:
        raise OSError(f"Cannot hash encrypted evidence: {exc}") from exc

    object_uri = str(enc_path)
    capture_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    record = {
        "evidenceId": evidence_id,
        "cameraId": camera["cameraId"],
        "objectUri": object_uri,
        "encryptedFileHash": encrypted_file_hash,
        "plaintextHash": plaintext_hash,
        "encryptionAlgo": "AES-256-GCM",
        "nonce": nonce_b64,
        "authTag": auth_tag_b64,
        "wrappedKey": wrapped_key,
        "captureTimestamp": capture_timestamp,
        "deviceSignature": device_signature,
        "prnuCaptureScore": 0.0,
        "tsaTokenRef": "",
        "fabricTxId": "",
    }

    evidence_dir = storage_dir / "metadata" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / f"{evidence_id}.json"

    try:
        evidence_path.write_text(json.dumps(record, indent=2))
        os.chmod(evidence_path, 0o444)
    except OSError as exc:
        raise OSError(f"Cannot write evidence.json: {exc}") from exc

    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture and encrypt a video file as evidence.")
    parser.add_argument("--video-file", required=True, help="Path to the plaintext video file")
    parser.add_argument("--camera-json", required=True, help="Path to camera.json")
    parser.add_argument("--private-key", required=True, help="Path to camera Ed25519 private key PEM")
    parser.add_argument("--evidence-id", default=None, help="Evidence ID (auto-generated if omitted)")
    parser.add_argument("--storage-dir", default="storage", help="Storage root directory")
    args = parser.parse_args()

    evidence_id = args.evidence_id or ("ev-" + secrets.token_hex(8))

    try:
        record = run_capture(
            video_path=Path(args.video_file),
            camera_json_path=Path(args.camera_json),
            privkey_path=Path(args.private_key),
            evidence_id=evidence_id,
            storage_dir=Path(args.storage_dir),
        )
    except (OSError, ValueError, RuntimeError) as exc:
        return fail("CAPTURE_FAILED", str(exc))

    print(json.dumps({
        "ok": True,
        "result": {
            "evidenceId": record["evidenceId"],
            "plaintextHash": record["plaintextHash"],
            "encryptedFileHash": record["encryptedFileHash"],
            "objectUri": record["objectUri"],
        },
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
