import copy
import json
import tempfile
from pathlib import Path

from backend.app.config import settings
from backend.app.services import fabric_client
from forensics.verify import run_verify

_ATTACK_DESCRIPTIONS = {
    "bit_flip": (
        "A single byte in the middle of the encrypted video file is flipped. "
        "This simulates an attacker physically modifying stored footage."
    ),
    "forge_signature": (
        "The last characters of the Ed25519 device signature are corrupted. "
        "This simulates an attacker attempting to forge a cryptographic signature."
    ),
    "metadata_injection": (
        "The plaintextHash field in evidence metadata is replaced with a fake value. "
        "This simulates an attacker altering what the evidence claims the video contained — "
        "but the original device signature still covers the real hash, so verification rejects the injected value."
    ),
}


def run_attack_demo(evidence_id: str, attack_type: str) -> dict:
    """Run a tamper demonstration on a temp copy of the evidence. Does not write results."""
    if attack_type not in _ATTACK_DESCRIPTIONS:
        raise ValueError(f"Unknown attack type '{attack_type}'. Valid: {list(_ATTACK_DESCRIPTIONS)}")

    evidence_path = settings.evidence_meta_dir / f"{evidence_id}.json"
    if not evidence_path.exists():
        raise ValueError(f"Evidence '{evidence_id}' not found")

    evidence = json.loads(evidence_path.read_text())
    camera_id = evidence["cameraId"]
    camera_json_path = settings.cameras_dir / f"{camera_id}.json"
    if not camera_json_path.exists():
        raise ValueError(f"Camera '{camera_id}' not found")

    enc_src = settings.evidence_dir / f"{evidence_id}.enc"

    with tempfile.TemporaryDirectory() as tmp_root:
        tmp = Path(tmp_root)

        if attack_type == "bit_flip":
            enc_bytes = bytearray(enc_src.read_bytes())
            mid = max(1, len(enc_bytes) // 2)
            enc_bytes[mid] ^= 0xFF
            tampered_enc = tmp / f"{evidence_id}.enc"
            tampered_enc.write_bytes(bytes(enc_bytes))
            result = run_verify(
                evidence_id=evidence_id,
                camera_json_path=camera_json_path,
                storage_dir=settings.storage_dir,
                enc_path_override=tampered_enc,
                dry_run=True,
            )

        elif attack_type == "forge_signature":
            tampered_ev = copy.deepcopy(evidence)
            sig = list(tampered_ev["deviceSignature"])
            sig[-1] = "A" if sig[-1] != "A" else "B"
            sig[-2] = "Z" if sig[-2] != "Z" else "Y"
            tampered_ev["deviceSignature"] = "".join(sig)
            ev_path = tmp / "evidence.json"
            ev_path.write_text(json.dumps(tampered_ev))
            result = run_verify(
                evidence_id=evidence_id,
                camera_json_path=camera_json_path,
                storage_dir=settings.storage_dir,
                evidence_json_override=ev_path,
                dry_run=True,
            )

        else:  # metadata_injection
            tampered_ev = copy.deepcopy(evidence)
            tampered_ev["plaintextHash"] = "0" * 64
            ev_path = tmp / "evidence.json"
            ev_path.write_text(json.dumps(tampered_ev))
            result = run_verify(
                evidence_id=evidence_id,
                camera_json_path=camera_json_path,
                storage_dir=settings.storage_dir,
                evidence_json_override=ev_path,
                dry_run=True,
            )

    result["_attackType"] = attack_type
    result["_attackDescription"] = _ATTACK_DESCRIPTIONS[attack_type]
    return result


def verify_evidence(
    evidence_id: str,
    verifier_id: str = "system",
    include_decryption: bool = False,
    override_public_key_b64: str | None = None,
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

    tsa_ca = settings.tsa_ca_cert if settings.tsa_ca_cert.exists() else None
    tsa_crt = settings.tsa_cert if settings.tsa_cert.exists() else None

    if override_public_key_b64 is not None:
        import base64
        try:
            key_bytes = base64.b64decode(override_public_key_b64, validate=True)
        except Exception as exc:
            raise ValueError(f"overridePublicKeyEd25519 is not valid base64: {exc}") from exc
        if len(key_bytes) != 32:
            raise ValueError(
                f"overridePublicKeyEd25519 must be a 32-byte Ed25519 key (got {len(key_bytes)} bytes)"
            )

    result = run_verify(
        evidence_id=evidence_id,
        camera_json_path=camera_json_path,
        storage_dir=settings.storage_dir,
        owner_privkey_path=owner_privkey_path,
        verifier_id=verifier_id,
        tsa_ca_cert=tsa_ca,
        tsa_cert=tsa_crt,
        override_public_key_b64=override_public_key_b64,
    )

    fabric_client.log_verification(result["verificationId"], result)
    return result


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
