import json
from pathlib import Path

from backend.app.config import settings
from backend.app.services import fabric_client
from forensics.enroll import (
    build_camera_record,
    generate_ed25519_keypair,
    write_camera_json,
    write_private_key,
)


def enroll_camera(
    camera_id: str,
    device_serial: str,
    operator_id: str,
    owner_public_key_b64: str,
) -> dict:
    """Generate an Ed25519 key pair and write camera.json + private key.

    Returns the camera record dict on success.
    Raises ValueError for invalid inputs, OSError for file I/O failures.
    """
    import base64
    try:
        base64.b64decode(owner_public_key_b64, validate=True)
    except Exception as exc:
        raise ValueError(f"ownerPublicKey is not valid base64: {exc}") from exc

    private_raw, public_raw = generate_ed25519_keypair()

    privkey_path = settings.keys_dir / f"{camera_id}.private.pem"
    settings.keys_dir.mkdir(parents=True, exist_ok=True)
    write_private_key(privkey_path, private_raw)

    record = build_camera_record(
        camera_id=camera_id,
        device_serial=device_serial,
        operator_id=operator_id,
        public_key_raw=public_raw,
        owner_pubkey_b64=owner_public_key_b64,
    )

    camera_json_path = write_camera_json(record, settings.cameras_dir)
    record["_privateKeyPath"] = str(privkey_path)
    record["_cameraJsonPath"] = str(camera_json_path)

    fabric_client.register_camera(camera_id, record)
    return record


def list_cameras() -> list[dict]:
    """Return all camera records from local metadata storage."""
    cameras = []
    if not settings.cameras_dir.exists():
        return cameras
    for path in sorted(settings.cameras_dir.glob("*.json")):
        try:
            cameras.append(json.loads(path.read_text()))
        except (json.JSONDecodeError, OSError):
            continue
    return cameras


def get_camera(camera_id: str) -> dict | None:
    """Return a single camera record or None if not found."""
    path = settings.cameras_dir / f"{camera_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
