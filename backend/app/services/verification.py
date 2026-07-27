import json
from pathlib import Path

from backend.app.config import settings
from forensics.verify import run_verify


def verify_evidence(
    evidence_id: str,
    verifier_id: str = "system",
    include_decryption: bool = False,
) -> dict:
    """Run the verification pipeline for a given evidence item.

    Returns the verification result dict.
    Raises ValueError if required files are missing, OSError on I/O failure.
    """
    evidence_path = settings.evidence_meta_dir / f"{evidence_id}.json"
    if not evidence_path.exists():
        raise ValueError(f"Evidence '{evidence_id}' not found")

    try:
        evidence = json.loads(evidence_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"Cannot read evidence record: {exc}") from exc

    camera_json_path = settings.cameras_dir / f"{evidence['cameraId']}.json"
    if not camera_json_path.exists():
        raise ValueError(f"Camera '{evidence['cameraId']}' not found — cannot verify signature")

    owner_privkey_path: Path | None = None
    if include_decryption:
        candidate = settings.keys_dir / "owner.x25519.priv.pem"
        if not candidate.exists():
            raise ValueError(
                "include_decryption=true but owner.x25519.priv.pem not found in keys directory"
            )
        owner_privkey_path = candidate

    return run_verify(
        evidence_id=evidence_id,
        camera_json_path=camera_json_path,
        storage_dir=settings.storage_dir,
        owner_privkey_path=owner_privkey_path,
        verifier_id=verifier_id,
    )


def list_verification_results(evidence_id: str) -> list[dict]:
    """Return all verification results for a given evidence item."""
    results = []
    if not settings.results_dir.exists():
        return results
    for path in sorted(settings.results_dir.glob("ver-*.json")):
        try:
            record = json.loads(path.read_text())
            if record.get("evidenceId") == evidence_id:
                results.append(record)
        except (json.JSONDecodeError, OSError):
            continue
    return results
