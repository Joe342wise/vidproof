import hashlib
import json
import os
import uuid
from pathlib import Path

from forensics.tsa_stamp import stamp_evidence_hash

from backend.app.config import settings
from backend.app.services import fabric_client
from forensics.capture import run_capture


def _patch_fabric_tx(evidence_path: Path, tx_id: str) -> None:
    """Write fabricTxId into a read-only evidence file, then re-lock it."""
    try:
        os.chmod(evidence_path, 0o644)
        data = json.loads(evidence_path.read_text())
        data["fabricTxId"] = tx_id
        evidence_path.write_text(json.dumps(data, indent=2))
    finally:
        os.chmod(evidence_path, 0o444)


async def save_upload(file_obj, dest_dir: Path) -> Path:
    """Stream an UploadFile to a temporary path in dest_dir."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = dest_dir / f"tmp-{uuid.uuid4().hex}"
    with tmp_path.open("wb") as fh:
        while True:
            chunk = await file_obj.read(1024 * 1024)
            if not chunk:
                break
            fh.write(chunk)
    return tmp_path


def capture_evidence(
    video_path: Path,
    camera_id: str,
    evidence_id: str | None = None,
) -> dict:
    """Run the capture pipeline against a video file already on disk.

    Returns the evidence record dict.
    Raises ValueError if camera.json is missing, OSError / RuntimeError on
    pipeline failure.
    """
    import secrets
    camera_json_path = settings.cameras_dir / f"{camera_id}.json"
    if not camera_json_path.exists():
        raise ValueError(f"Camera '{camera_id}' is not enrolled")

    privkey_path = settings.keys_dir / f"{camera_id}.private.pem"
    if not privkey_path.exists():
        raise ValueError(f"Private key for camera '{camera_id}' not found in keys directory")

    eid = evidence_id or ("ev-" + secrets.token_hex(8))

    record = run_capture(
        video_path=video_path,
        camera_json_path=camera_json_path,
        privkey_path=privkey_path,
        evidence_id=eid,
        storage_dir=settings.storage_dir,
        tsa_url=settings.tsa_url,
    )

    tx_id = fabric_client.register_evidence(eid, record)
    if tx_id:
        record["fabricTxId"] = tx_id
        _patch_fabric_tx(settings.evidence_meta_dir / f"{eid}.json", tx_id)

    return record


def list_evidence() -> list[dict]:
    """Return all evidence records from local metadata storage."""
    items = []
    if not settings.evidence_meta_dir.exists():
        return items
    for path in sorted(settings.evidence_meta_dir.glob("*.json")):
        try:
            items.append(json.loads(path.read_text()))
        except (json.JSONDecodeError, OSError):
            continue
    return items


def get_evidence(evidence_id: str) -> dict | None:
    """Return a single evidence record or None if not found."""
    path = settings.evidence_meta_dir / f"{evidence_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


_REQUIRED_EVIDENCE_FIELDS = {
    "evidenceId", "cameraId", "encryptedFileHash", "plaintextHash",
    "encryptionAlgo", "nonce", "authTag", "wrappedKey",
    "captureTimestamp", "deviceSignature",
}


def ingest_device_evidence(evidence_json_str: str, enc_bytes: bytes) -> dict:
    """Accept pre-signed, pre-encrypted evidence produced by an edge device.

    Validates the evidence record, verifies the .enc file hash matches the
    declared encryptedFileHash, writes both files to storage, and returns
    the stored evidence record. Raises ValueError on validation failures.
    """
    try:
        evidence = json.loads(evidence_json_str)
    except json.JSONDecodeError as exc:
        raise ValueError(f"evidence_json is not valid JSON: {exc}")

    missing = _REQUIRED_EVIDENCE_FIELDS - evidence.keys()
    if missing:
        raise ValueError(f"evidence_json missing required fields: {sorted(missing)}")

    eid = evidence["evidenceId"]
    camera_id = evidence["cameraId"]

    if not eid or not camera_id:
        raise ValueError("evidenceId and cameraId must not be empty")

    camera_path = settings.cameras_dir / f"{camera_id}.json"
    if not camera_path.exists():
        raise ValueError(f"Camera '{camera_id}' is not enrolled on this backend")

    enc_path = settings.evidence_dir / f"{eid}.enc"
    evidence_path = settings.evidence_meta_dir / f"{eid}.json"

    if enc_path.exists() or evidence_path.exists():
        raise ValueError(f"Evidence '{eid}' already exists — ingest is write-once")

    actual_hash = hashlib.sha256(enc_bytes).hexdigest()
    if actual_hash != evidence["encryptedFileHash"]:
        raise ValueError(
            f"encryptedFileHash mismatch: declared={evidence['encryptedFileHash']!r} "
            f"actual={actual_hash!r}"
        )

    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    settings.evidence_meta_dir.mkdir(parents=True, exist_ok=True)

    enc_path.write_bytes(enc_bytes)

    evidence.setdefault("objectUri", str(enc_path))
    evidence.setdefault("prnuCaptureScore", 0.0)

    tsa_result = stamp_evidence_hash(
        evidence["encryptedFileHash"],
        settings.tsa_url,
        settings.tsa_dir / f"{eid}.tsr",
    )
    if tsa_result:
        evidence["tsaTokenRef"] = tsa_result["tsrPath"]
        evidence["tsaTokenHash"] = tsa_result["tsaTokenHash"]
    else:
        evidence.setdefault("tsaTokenRef", "")
        evidence.setdefault("tsaTokenHash", "")

    tx_id = fabric_client.register_evidence(eid, evidence)
    evidence["fabricTxId"] = tx_id or ""

    evidence_path.write_text(json.dumps(evidence, indent=2))
    os.chmod(evidence_path, 0o444)

    return evidence
