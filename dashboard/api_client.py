import os

import requests

BACKEND_URL = os.environ.get("VIDPROOF_BACKEND_URL", "http://localhost:8000")
_session = requests.Session()


def _url(path: str) -> str:
    return f"{BACKEND_URL}{path}"


def health() -> dict:
    return _session.get(_url("/health"), timeout=5).json()


# ---------------------------------------------------------------------------
# Cameras
# ---------------------------------------------------------------------------

def get_owner_public_key() -> str | None:
    """Return the server's owner X25519 public key as base64, or None if not configured."""
    try:
        resp = _session.get(_url("/camera/owner-public-key"), timeout=5)
        data = resp.json()
        return data.get("ownerPublicKey") if data.get("ok") else None
    except Exception:
        return None


def enroll_camera(
    camera_id: str,
    device_serial: str,
    operator_id: str,
    owner_public_key: str,
    device_public_key: str | None = None,
) -> dict:
    payload: dict = {
        "cameraId": camera_id,
        "deviceSerial": device_serial,
        "operatorId": operator_id,
        "ownerPublicKey": owner_public_key,
    }
    if device_public_key:
        payload["devicePublicKeyEd25519"] = device_public_key
    return _session.post(_url("/camera/enroll"), json=payload, timeout=10).json()


def list_cameras() -> list[dict]:
    resp = _session.get(_url("/camera/"), timeout=10)
    resp.raise_for_status()
    return resp.json()


def get_camera(camera_id: str) -> dict:
    resp = _session.get(_url(f"/camera/{camera_id}"), timeout=10)
    resp.raise_for_status()
    return resp.json()


def delete_camera(camera_id: str) -> None:
    resp = _session.delete(_url(f"/camera/{camera_id}"), timeout=10)
    resp.raise_for_status()


def upload_prnu_reference(camera_id: str, video_bytes: bytes, filename: str) -> dict:
    resp = _session.post(
        _url(f"/camera/{camera_id}/prnu-reference"),
        files={"video_file": (filename, video_bytes, "application/octet-stream")},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

def capture_evidence(camera_id: str, video_bytes: bytes, filename: str, evidence_id: str | None = None) -> dict:
    data = {"camera_id": camera_id}
    if evidence_id:
        data["evidence_id"] = evidence_id
    resp = _session.post(
        _url("/evidence/capture"),
        data=data,
        files={"video_file": (filename, video_bytes, "application/octet-stream")},
        timeout=60,
    )
    return resp.json()


def list_evidence() -> list[dict]:
    resp = _session.get(_url("/evidence/"), timeout=10)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_evidence(
    evidence_id: str,
    verifier_id: str = "system",
    include_decryption: bool = False,
    override_public_key: str | None = None,
) -> dict:
    payload: dict = {"verifierId": verifier_id, "includeDecryption": include_decryption}
    if override_public_key:
        payload["overridePublicKeyEd25519"] = override_public_key
    resp = _session.post(_url(f"/evidence/{evidence_id}/verify"), json=payload, timeout=30)
    return resp.json()


def list_verification_results(evidence_id: str) -> list[dict]:
    resp = _session.get(_url(f"/evidence/{evidence_id}/verification-results"), timeout=10)
    resp.raise_for_status()
    return resp.json()


def get_fabric_history(evidence_id: str) -> dict:
    resp = _session.get(_url(f"/evidence/{evidence_id}/fabric-history"), timeout=10)
    resp.raise_for_status()
    return resp.json()


def run_attack_demo(evidence_id: str, attack_type: str) -> dict:
    resp = _session.post(_url(f"/evidence/{evidence_id}/attack-demo"), json={
        "attackType": attack_type,
    }, timeout=30)
    resp.raise_for_status()
    return resp.json()


def verify_package(zip_bytes: bytes, filename: str = "package.zip") -> dict:
    resp = _session.post(
        _url("/evidence/verify-package"),
        files={"package_file": (filename, zip_bytes, "application/zip")},
        timeout=60,
    )
    if not resp.ok:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        raise Exception(f"Backend {resp.status_code}: {detail}")
    return resp.json()


def export_evidence(evidence_id: str, include_decryption: bool = False) -> bytes:
    resp = _session.post(
        _url(f"/evidence/{evidence_id}/export"),
        json={"includeDecryption": include_decryption},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.content


def export_evidence_bulk(evidence_ids: list[str], include_decryption: bool = False) -> bytes:
    resp = _session.post(
        _url("/evidence/export/bulk"),
        json={"evidenceIds": evidence_ids, "includeDecryption": include_decryption},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.content
