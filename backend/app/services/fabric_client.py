"""
Thin HTTP client for the Fabric adapter (vidproof/fabric-adapter running on port 8081).
Called by enrollment and capture services after local operations succeed.
Returns the Fabric tx ID string on success, or None when Fabric is unavailable.
"""

import json
import logging
from typing import Any

import requests

from backend.app.config import settings

_log = logging.getLogger(__name__)

_TIMEOUT = 15  # seconds
_session = requests.Session()


def _url(path: str) -> str:
    return f"{settings.fabric_adapter_url}{path}"


def _post(path: str, payload: dict) -> dict | None:
    """POST payload to the adapter; returns the parsed JSON or None on failure."""
    try:
        resp = _session.post(_url(path), json=payload, timeout=_TIMEOUT)
        data = resp.json()
        if not data.get("ok"):
            code = data.get("error", {}).get("code", "UNKNOWN")
            if code == "FABRIC_UNAVAILABLE":
                _log.info("fabric adapter: Fabric not connected — skipping ledger write")
                return None
            _log.warning("fabric adapter: %s returned error: %s", path, data)
            return None
        return data
    except requests.exceptions.ConnectionError:
        _log.info("fabric adapter: not reachable — skipping ledger write")
        return None
    except Exception as exc:
        _log.warning("fabric adapter: unexpected error posting to %s: %s", path, exc)
        return None


def register_camera(camera_id: str, camera_record: dict) -> str | None:
    """Submit RegisterCamera to Fabric. Returns fabric tx ID or None."""
    result = _post("/camera/register", {
        "cameraId": camera_id,
        "cameraJson": json.dumps(camera_record),
    })
    return result.get("txId") if result else None


def register_evidence(evidence_id: str, evidence_record: dict) -> str | None:
    """Submit RegisterEvidence to Fabric. Returns fabric tx ID or None.

    The evidence record posted to Fabric must exclude nonce, authTag, wrappedKey
    (decryption material must never leave the local system).
    """
    safe_record = {k: v for k, v in evidence_record.items()
                   if k not in ("nonce", "authTag", "wrappedKey")}
    result = _post("/evidence/register", {
        "evidenceId": evidence_id,
        "evidenceJson": json.dumps(safe_record),
    })
    return result.get("txId") if result else None


def log_verification(verification_id: str, verification_record: dict) -> str | None:
    """Submit LogVerification to Fabric. Returns fabric tx ID or None."""
    result = _post("/verification/log", {
        "verificationId": verification_id,
        "verificationJson": json.dumps(verification_record),
    })
    return result.get("txId") if result else None


def log_access(evidence_id: str, actor_id: str, timestamp: str, notes: str = "") -> str | None:
    """Submit LogAccess custody event to Fabric. Returns fabric tx ID or None."""
    payload = {
        "eventType": "access",
        "evidenceId": evidence_id,
        "actorId": actor_id,
        "timestamp": timestamp,
        "notes": notes,
    }
    result = _post("/custody/log", {"custodyJson": json.dumps(payload)})
    return result.get("txId") if result else None


def log_export(evidence_id: str, actor_id: str, timestamp: str, notes: str = "") -> str | None:
    """Submit LogExport custody event to Fabric. Returns fabric tx ID or None."""
    payload = {
        "eventType": "export",
        "evidenceId": evidence_id,
        "actorId": actor_id,
        "timestamp": timestamp,
        "notes": notes,
    }
    result = _post("/custody/log", {"custodyJson": json.dumps(payload)})
    return result.get("txId") if result else None


def get_evidence_history(evidence_id: str) -> list[dict] | None:
    """Fetch evidence history from Fabric. Returns list or None if unavailable."""
    try:
        resp = _session.get(_url(f"/evidence/{evidence_id}/history"), timeout=_TIMEOUT)
        data = resp.json()
        if not data.get("ok"):
            code = data.get("error", {}).get("code", "UNKNOWN")
            if code == "FABRIC_UNAVAILABLE":
                return None
            _log.warning("fabric adapter: history error: %s", data)
            return None
        return data.get("history", [])
    except requests.exceptions.ConnectionError:
        return None
    except Exception as exc:
        _log.warning("fabric adapter: get_evidence_history: %s", exc)
        return None
