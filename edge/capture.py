#!/usr/bin/env python3
"""Edge capture entry point — file-mode or Raspberry Pi camera.

The cryptographic pipeline is identical to forensics/capture.py.
Only the video source changes between modes.

This module imports exclusively from vidproof_crypto so it can run on a
Raspberry Pi with only the crypto package installed — the full forensics
stack (numpy, scipy, OpenCV) is not required.

Install the crypto package once:
    pip install -e /path/to/vidproof   # on Pi or dev machine

Usage:
    # File mode (development / testing)
    python edge/capture.py \\
        --video-file sample.mp4 \\
        --camera-json /etc/vidproof/camera.json \\
        --private-key /etc/vidproof/keys/camera.private.pem \\
        --evidence-id ev-001 \\
        [--storage-dir storage]

    # Pi mode (Raspberry Pi with picamera2)
    python edge/capture.py \\
        --pi-mode \\
        --duration 10 \\
        --camera-json /etc/vidproof/camera.json \\
        --private-key /etc/vidproof/keys/camera.private.pem \\
        [--storage-dir /var/vidproof/storage]

Output (stdout):
    {"ok": true,  "result": {...evidence record...}}
    {"ok": false, "error": {"code": "...", "message": "..."}}
"""
import argparse
import json
import os
import secrets
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

try:
    from vidproof_crypto import (
        encrypt_aes_gcm,
        sha256_bytes,
        sha256_file,
        sign_plaintext_hash,
        wrap_aes_key,
    )
except ImportError:
    # Fallback: add project root to path when not installed as a package.
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from vidproof_crypto import (
        encrypt_aes_gcm,
        sha256_bytes,
        sha256_file,
        sign_plaintext_hash,
        wrap_aes_key,
    )


# ---------------------------------------------------------------------------
# Video source functions — both return raw bytes, nothing else.
# ---------------------------------------------------------------------------

def get_video_segment_file_mode(path: Path) -> bytes:
    """Read a video file from disk and return its bytes unchanged."""
    return path.read_bytes()


def get_video_segment_pi_mode(duration: int = 10) -> bytes:
    """Capture a video segment from the Raspberry Pi camera module.

    Requires picamera2 (pre-installed on Raspberry Pi OS).
    Captures H.264-encoded footage for `duration` seconds.

    Raises RuntimeError if picamera2 is not available.
    """
    try:
        from picamera2 import Picamera2  # type: ignore[import]
        from picamera2.encoders import H264Encoder  # type: ignore[import]
        from picamera2.outputs import FileOutput  # type: ignore[import]
    except ImportError as exc:
        raise RuntimeError(
            "picamera2 is not available — this mode requires a Raspberry Pi running Pi OS"
        ) from exc

    import time

    cam = Picamera2()
    cam.configure(cam.create_video_configuration(main={"size": (1280, 720)}))
    encoder = H264Encoder(bitrate=4_000_000)

    fd, tmp = tempfile.mkstemp(suffix=".h264")
    os.close(fd)
    tmp_path = Path(tmp)
    try:
        cam.start_recording(encoder, output=FileOutput(str(tmp_path)))
        time.sleep(duration)
        cam.stop_recording()
        cam.close()
        return tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Capture pipeline — identical logic to forensics/capture.py:run_capture()
# but takes plaintext bytes directly so it works in both file and Pi modes
# without depending on the forensics package.
# ---------------------------------------------------------------------------

def _run_capture_pipeline(
    plaintext: bytes,
    camera_json_path: Path,
    privkey_path: Path,
    evidence_id: str,
    storage_dir: Path,
) -> dict:
    """Run the full capture pipeline on in-memory plaintext bytes.

    Mirrors forensics/capture.py:run_capture() exactly — same steps, same
    output schema, same evidence.json format. Any change here must be
    mirrored there and vice versa.
    """
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
        aes_key = b"\x00" * len(aes_key)

    enc_dir = storage_dir / "evidence"
    enc_dir.mkdir(parents=True, exist_ok=True)
    enc_path = enc_dir / f"{evidence_id}.enc"

    try:
        enc_path.write_bytes(ciphertext)
    except OSError as exc:
        raise OSError(f"Cannot write encrypted evidence: {exc}") from exc

    encrypted_file_hash = sha256_file(enc_path)
    capture_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    record = {
        "evidenceId": evidence_id,
        "cameraId": camera["cameraId"],
        "objectUri": str(enc_path),
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


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def fail(code: str, message: str) -> None:
    print(json.dumps({"ok": False, "error": {"code": code, "message": message}}))
    raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="VidProof edge capture — file mode or Raspberry Pi camera"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--video-file", type=Path, help="Path to video file (file mode)")
    source.add_argument("--pi-mode", action="store_true", help="Capture from Pi camera (Pi mode)")

    parser.add_argument("--duration", type=int, default=10,
                        help="Capture duration in seconds (Pi mode only, default: 10)")
    parser.add_argument("--camera-json", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--evidence-id", default=None,
                        help="Evidence ID (auto-generated if omitted)")
    parser.add_argument("--storage-dir", type=Path, default=Path("storage"))
    args = parser.parse_args()

    evidence_id = args.evidence_id or ("ev-" + secrets.token_hex(8))

    # --- Acquire video bytes ---
    try:
        if args.pi_mode:
            try:
                plaintext = get_video_segment_pi_mode(duration=args.duration)
            except RuntimeError as exc:
                fail("PI_UNAVAILABLE", str(exc))
        else:
            if not args.video_file.exists():
                fail("VIDEO_NOT_FOUND", f"Video file not found: {args.video_file}")
            plaintext = get_video_segment_file_mode(args.video_file)

        try:
            record = _run_capture_pipeline(
                plaintext=plaintext,
                camera_json_path=args.camera_json,
                privkey_path=args.private_key,
                evidence_id=evidence_id,
                storage_dir=args.storage_dir,
            )
        except (OSError, ValueError, RuntimeError) as exc:
            fail("CAPTURE_FAILED", str(exc))
        finally:
            del plaintext  # drop plaintext reference as soon as pipeline finishes
    except SystemExit:
        raise
    except Exception as exc:
        fail("UNEXPECTED_ERROR", str(exc))

    print(json.dumps({"ok": True, "result": record}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
