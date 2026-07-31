import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key

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
    device_public_key_b64: str | None = None,
) -> dict:
    """Enroll a camera and write camera.json.

    If device_public_key_b64 is provided the device already has its own Ed25519
    keypair; the server stores only the public key and writes no private key.
    If omitted the server generates a keypair and stores the private key locally.

    Returns the camera record dict on success.
    Raises ValueError for invalid inputs, OSError for file I/O failures.
    """
    try:
        owner_bytes = base64.b64decode(owner_public_key_b64, validate=True)
    except Exception as exc:
        raise ValueError(f"ownerPublicKey is not valid base64: {exc}") from exc
    if len(owner_bytes) != 32:
        raise ValueError(f"ownerPublicKey must be a 32-byte X25519 key (got {len(owner_bytes)} bytes)")

    privkey_path: Path | None = None

    if device_public_key_b64 is not None:
        try:
            device_pub_bytes = base64.b64decode(device_public_key_b64, validate=True)
        except Exception as exc:
            raise ValueError(f"devicePublicKeyEd25519 is not valid base64: {exc}") from exc
        if len(device_pub_bytes) != 32:
            raise ValueError(
                f"devicePublicKeyEd25519 must be a 32-byte Ed25519 key (got {len(device_pub_bytes)} bytes)"
            )
        public_raw = device_pub_bytes
    else:
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
    record["_privateKeyPath"] = str(privkey_path) if privkey_path else None
    record["_cameraJsonPath"] = str(camera_json_path)

    fabric_client.register_camera(camera_id, record)
    return record


def get_owner_public_key() -> str | None:
    """Return the server's owner X25519 public key as base64, or None if not set up."""
    priv_path = settings.keys_dir / "owner.x25519.priv.pem"
    if not priv_path.exists():
        return None
    try:
        priv = load_pem_private_key(priv_path.read_bytes(), password=None)
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(pub_bytes).decode()
    except Exception:
        return None


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


def delete_camera(camera_id: str) -> None:
    """Delete a camera record and its local private key. Raises ValueError if not found."""
    path = settings.cameras_dir / f"{camera_id}.json"
    if not path.exists():
        raise ValueError(f"Camera '{camera_id}' not found")
    path.unlink()
    privkey = settings.keys_dir / f"{camera_id}.private.pem"
    if privkey.exists():
        privkey.unlink()


def get_camera(camera_id: str) -> dict | None:
    """Return a single camera record or None if not found."""
    path = settings.cameras_dir / f"{camera_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
