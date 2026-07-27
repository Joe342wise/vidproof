import json
import uuid
from pathlib import Path

from backend.app.config import settings
from forensics.capture import run_capture


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

    return run_capture(
        video_path=video_path,
        camera_json_path=camera_json_path,
        privkey_path=privkey_path,
        evidence_id=eid,
        storage_dir=settings.storage_dir,
    )


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
