#!/usr/bin/env python3
"""Edge capture entry point — file-mode or Raspberry Pi camera.

The cryptographic pipeline is identical to forensics/capture.py.
Only the video source changes between modes.

Usage:
    # File mode (development / testing)
    python edge/capture.py \
        --video-file sample.mp4 \
        --camera-json storage/metadata/cameras/cam-001.json \
        --private-key storage/keys/cam-001.private.pem \
        --evidence-id ev-001 \
        [--storage-dir storage]

    # Pi mode (Raspberry Pi with picamera2)
    python edge/capture.py \
        --pi-mode \
        --duration 10 \
        --camera-json /etc/vidproof/camera.json \
        --private-key /etc/vidproof/keys/camera.private.pem \
        [--evidence-id ev-$(date +%s)] \
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
from pathlib import Path

# Run from project root so forensics package is importable.
sys.path.insert(0, str(Path(__file__).parent.parent))

from forensics.capture import run_capture


# ---------------------------------------------------------------------------
# Video source functions — both return raw bytes, nothing else.
# ---------------------------------------------------------------------------

def get_video_segment_file_mode(path: Path) -> bytes:
    """Read a video file from disk and return its bytes unchanged."""
    return path.read_bytes()


def get_video_segment_pi_mode(duration: int = 10) -> bytes:
    """Capture a video segment from the Raspberry Pi camera module.

    Requires picamera2 (available only on Raspberry Pi OS).
    Captures H.264-encoded footage for `duration` seconds.

    Raises RuntimeError if picamera2 is not installed.
    """
    try:
        from picamera2 import Picamera2  # type: ignore[import]
        from picamera2.encoders import H264Encoder  # type: ignore[import]
        from picamera2.outputs import FileOutput  # type: ignore[import]
    except ImportError as exc:
        raise RuntimeError(
            "picamera2 is not installed — run 'pip install picamera2' on a Raspberry Pi"
        ) from exc

    import time

    cam = Picamera2()
    cam.configure(cam.create_video_configuration(main={"size": (1280, 720)}))
    encoder = H264Encoder()

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
    parser.add_argument("--evidence-id",
                        default=None,
                        help="Evidence ID (auto-generated if omitted)")
    parser.add_argument("--storage-dir", type=Path, default=Path("storage"))
    args = parser.parse_args()

    evidence_id = args.evidence_id or ("ev-" + secrets.token_hex(8))

    # --- Acquire video bytes ---
    video_bytes: bytes
    tmp_video: Path | None = None

    try:
        if args.pi_mode:
            try:
                video_bytes = get_video_segment_pi_mode(duration=args.duration)
            except RuntimeError as exc:
                fail("PI_UNAVAILABLE", str(exc))
        else:
            if not args.video_file.exists():
                fail("VIDEO_NOT_FOUND", f"Video file not found: {args.video_file}")
            video_bytes = get_video_segment_file_mode(args.video_file)

        # Write to a temp file so run_capture (which takes a Path) can read it.
        # This keeps the crypto pipeline identical between modes.
        fd, tmp = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        tmp_video = Path(tmp)
        tmp_video.write_bytes(video_bytes)
        del video_bytes  # drop plaintext reference once written

        try:
            record = run_capture(
                video_path=tmp_video,
                camera_json_path=args.camera_json,
                privkey_path=args.private_key,
                evidence_id=evidence_id,
                storage_dir=args.storage_dir,
            )
        except (OSError, ValueError, RuntimeError) as exc:
            fail("CAPTURE_FAILED", str(exc))

    finally:
        if tmp_video is not None:
            try:
                tmp_video.unlink()
            except OSError:
                pass

    print(json.dumps({"ok": True, "result": record}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
