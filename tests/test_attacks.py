#!/usr/bin/env python3
"""Automated attack matrix — VidProof Milestone 12.

Runs 6 attacks against isolated evidence sets. Each result is written to
tests/results/<attack_name>.json for inclusion in the project report.

Usage:
    python tests/test_attacks.py [--storage-dir storage]

Exit codes: 0 = all attacks detected, 1 = one or more attacks not detected.
"""
import argparse
import base64
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from forensics.capture import run_capture
from forensics.crypto_core import sha256_bytes, sign_plaintext_hash
from forensics.enroll import (
    build_camera_record,
    generate_ed25519_keypair,
    write_camera_json,
    write_private_key,
)
from forensics.verify import run_verify

RESULTS_DIR = Path(__file__).parent / "results"
_FAKE_VIDEO = b"\x00\x01\x02\x03" * 1024 + b"VIDPROOF_TEST_PAYLOAD"


# ---------------------------------------------------------------------------
# Test fixture helpers
# ---------------------------------------------------------------------------

def _gen_owner_keypair(keys_dir: Path) -> tuple[str, Path]:
    """Generate X25519 owner key pair; return (pubkey_b64, privkey_path)."""
    priv = X25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    priv_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    priv_path = keys_dir / "owner.x25519.priv.pem"
    priv_path.write_bytes(priv_pem)
    return pub_b64, priv_path


def _setup(tmp: Path, camera_id: str = "cam-atk") -> dict:
    """Enroll a camera and capture evidence into tmp; return context dict."""
    keys_dir = tmp / "keys"
    keys_dir.mkdir(parents=True)

    owner_pub_b64, owner_priv_path = _gen_owner_keypair(keys_dir)

    private_raw, public_raw = generate_ed25519_keypair()
    privkey_path = keys_dir / f"{camera_id}.private.pem"
    write_private_key(privkey_path, private_raw)

    cam_record = build_camera_record(
        camera_id=camera_id,
        device_serial="ATK-SN",
        operator_id="attacker-tester",
        public_key_raw=public_raw,
        owner_pubkey_b64=owner_pub_b64,
    )
    cams_dir = tmp / "metadata" / "cameras"
    camera_json_path = write_camera_json(cam_record, cams_dir)

    video_path = tmp / "video.bin"
    video_path.write_bytes(_FAKE_VIDEO)

    evidence = run_capture(
        video_path=video_path,
        camera_json_path=camera_json_path,
        privkey_path=privkey_path,
        evidence_id="ev-atk",
        storage_dir=tmp,
    )

    enc_path = tmp / "evidence" / "ev-atk.enc"
    evidence_json_path = tmp / "metadata" / "evidence" / "ev-atk.json"

    return {
        "camera_id": camera_id,
        "camera_json_path": camera_json_path,
        "privkey_path": privkey_path,
        "owner_priv_path": owner_priv_path,
        "evidence_id": "ev-atk",
        "storage_dir": tmp,
        "enc_path": enc_path,
        "evidence_json_path": evidence_json_path,
        "evidence": evidence,
    }


def _verify(ctx: dict, *, with_decrypt: bool = False, evidence_json_override: Path | None = None) -> dict:
    return run_verify(
        evidence_id=ctx["evidence_id"],
        camera_json_path=ctx["camera_json_path"],
        storage_dir=ctx["storage_dir"],
        owner_privkey_path=ctx["owner_priv_path"] if with_decrypt else None,
        verifier_id="attack-test",
        evidence_json_override=evidence_json_override,
    )


def _tamper_evidence(ctx: dict, field: str, mutate) -> Path:
    """Return path to a temp file with one field of evidence.json mutated."""
    ev = json.loads(ctx["evidence_json_path"].read_text())
    ev[field] = mutate(ev[field])
    tmp_ev = ctx["storage_dir"] / f"tampered-{field}.json"
    tmp_ev.write_text(json.dumps(ev))
    return tmp_ev


# ---------------------------------------------------------------------------
# Attack 1: Bit-flip encrypted file
# ---------------------------------------------------------------------------

def attack_enc_file_tamper() -> dict:
    """Flip one byte in the .enc file; expect encryptedFileHashValid = false."""
    with tempfile.TemporaryDirectory() as td:
        ctx = _setup(Path(td))
        enc = ctx["enc_path"]

        # Make writable, flip first byte, lock again
        os.chmod(enc, 0o644)
        data = bytearray(enc.read_bytes())
        data[0] ^= 0xFF
        enc.write_bytes(bytes(data))
        os.chmod(enc, 0o444)

        result = _verify(ctx)

    detected = not result["encryptedFileHashValid"] and result["primaryDecision"] == "FAIL"
    return {
        "description": "Bit-flip encrypted file → hash mismatch",
        "expectedFailure": "encryptedFileHashValid: false",
        "encryptedFileHashValid": result["encryptedFileHashValid"],
        "primaryDecision": result["primaryDecision"],
        "detectedFailure": detected,
    }


# ---------------------------------------------------------------------------
# Attack 2: Corrupt device signature in evidence
# ---------------------------------------------------------------------------

def attack_signature_tamper() -> dict:
    """Replace one char in deviceSignature; expect deviceSignatureValid = false."""
    with tempfile.TemporaryDirectory() as td:
        ctx = _setup(Path(td))

        def corrupt_sig(sig: str) -> str:
            chars = list(sig)
            chars[4] = "A" if chars[4] != "A" else "B"
            return "".join(chars)

        tampered = _tamper_evidence(ctx, "deviceSignature", corrupt_sig)
        result = _verify(ctx, evidence_json_override=tampered)

    detected = not result["deviceSignatureValid"] and result["primaryDecision"] == "FAIL"
    return {
        "description": "Corrupt deviceSignature → signature verification failure",
        "expectedFailure": "deviceSignatureValid: false",
        "deviceSignatureValid": result["deviceSignatureValid"],
        "primaryDecision": result["primaryDecision"],
        "detectedFailure": detected,
    }


# ---------------------------------------------------------------------------
# Attack 3: Corrupt AES-GCM auth tag
# ---------------------------------------------------------------------------

def attack_auth_tag_tamper() -> dict:
    """Replace one char in authTag; expect decryptionValid = false."""
    with tempfile.TemporaryDirectory() as td:
        ctx = _setup(Path(td))

        def corrupt_tag(tag: str) -> str:
            chars = list(tag)
            chars[2] = "Z" if chars[2] != "Z" else "Y"
            return "".join(chars)

        tampered = _tamper_evidence(ctx, "authTag", corrupt_tag)
        result = _verify(ctx, with_decrypt=True, evidence_json_override=tampered)

    detected = result.get("decryptionAttempted") and not result["decryptionValid"]
    return {
        "description": "Corrupt authTag → AES-GCM authentication failure",
        "expectedFailure": "decryptionValid: false",
        "decryptionAttempted": result.get("decryptionAttempted"),
        "decryptionValid": result["decryptionValid"],
        "detectedFailure": detected,
    }


# ---------------------------------------------------------------------------
# Attack 4: Corrupt AES-GCM nonce
# ---------------------------------------------------------------------------

def attack_nonce_tamper() -> dict:
    """Replace one char in nonce; expect decryptionValid = false."""
    with tempfile.TemporaryDirectory() as td:
        ctx = _setup(Path(td))

        def corrupt_nonce(nonce: str) -> str:
            chars = list(nonce)
            chars[0] = "X" if chars[0] != "X" else "W"
            return "".join(chars)

        tampered = _tamper_evidence(ctx, "nonce", corrupt_nonce)
        result = _verify(ctx, with_decrypt=True, evidence_json_override=tampered)

    detected = result.get("decryptionAttempted") and not result["decryptionValid"]
    return {
        "description": "Corrupt nonce → AES-GCM authentication failure",
        "expectedFailure": "decryptionValid: false",
        "decryptionAttempted": result.get("decryptionAttempted"),
        "decryptionValid": result["decryptionValid"],
        "detectedFailure": detected,
    }


# ---------------------------------------------------------------------------
# Attack 5: Foreign key — sign with wrong camera's private key
# ---------------------------------------------------------------------------

def attack_foreign_key() -> dict:
    """Sign plaintextHash with a different camera's key; expect deviceSignatureValid = false."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ctx = _setup(tmp, camera_id="cam-real")

        # Generate a foreign key pair (simulates an attacker's camera)
        foreign_priv_raw, _ = generate_ed25519_keypair()
        foreign_privkey_path = tmp / "keys" / "foreign.private.pem"
        write_private_key(foreign_privkey_path, foreign_priv_raw)

        # Re-sign the plaintextHash with the foreign key
        pt_hash = ctx["evidence"]["plaintextHash"]
        foreign_sig = sign_plaintext_hash(pt_hash, foreign_privkey_path)

        # Replace deviceSignature in evidence with the foreign signature
        tampered = _tamper_evidence(ctx, "deviceSignature", lambda _: foreign_sig)
        result = _verify(ctx, evidence_json_override=tampered)

    detected = not result["deviceSignatureValid"] and result["primaryDecision"] == "FAIL"
    return {
        "description": "Evidence signed with foreign key → source authentication failure",
        "expectedFailure": "deviceSignatureValid: false",
        "deviceSignatureValid": result["deviceSignatureValid"],
        "primaryDecision": result["primaryDecision"],
        "detectedFailure": detected,
    }


# ---------------------------------------------------------------------------
# Attack 6: Delete encrypted evidence file
# ---------------------------------------------------------------------------

def attack_missing_enc() -> dict:
    """Delete .enc file; expect hash check to fail and primaryDecision = FAIL."""
    with tempfile.TemporaryDirectory() as td:
        ctx = _setup(Path(td))
        os.chmod(ctx["enc_path"], 0o644)
        ctx["enc_path"].unlink()

        detected = False
        detail = ""
        try:
            result = _verify(ctx)
            detected = not result["encryptedFileHashValid"] and result["primaryDecision"] == "FAIL"
            detail = f"encryptedFileHashValid={result['encryptedFileHashValid']}, decision={result['primaryDecision']}"
        except (FileNotFoundError, OSError) as exc:
            # verify raises if file is gone — this IS the expected detection
            detected = True
            detail = f"Exception (expected): {exc}"

    return {
        "description": "Delete encrypted evidence file → retrieval / hash failure",
        "expectedFailure": "FileNotFoundError or encryptedFileHashValid: false",
        "detail": detail,
        "detectedFailure": detected,
    }


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ATTACKS = [
    ("enc_file_tamper",   attack_enc_file_tamper),
    ("signature_tamper",  attack_signature_tamper),
    ("auth_tag_tamper",   attack_auth_tag_tamper),
    ("nonce_tamper",      attack_nonce_tamper),
    ("foreign_key",       attack_foreign_key),
    ("missing_enc",       attack_missing_enc),
]


def main() -> int:
    parser = argparse.ArgumentParser(description="VidProof attack test matrix")
    parser.add_argument("--attack", default=None,
                        help="Run one specific attack by name (default: run all)")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(exist_ok=True)

    attacks_to_run = [(n, f) for n, f in ATTACKS if args.attack is None or n == args.attack]
    if not attacks_to_run:
        print(f"Unknown attack: {args.attack!r}. Available: {[n for n, _ in ATTACKS]}")
        return 2

    print(f"{'Attack':<25}  {'Description':<52}  Result")
    print("-" * 95)

    all_passed = True
    for name, fn in attacks_to_run:
        try:
            result = fn()
        except Exception as exc:
            result = {
                "description": name,
                "error": str(exc),
                "detectedFailure": False,
            }

        result["attack"] = name
        (RESULTS_DIR / f"{name}.json").write_text(json.dumps(result, indent=2))

        passed = result.get("detectedFailure", False)
        all_passed = all_passed and passed
        status = "DETECTED" if passed else "MISSED  "
        desc = result.get("description", name)[:50]
        print(f"  {name:<23}  {desc:<52}  {status}")

    print("-" * 95)
    detected_count = sum(1 for n, f in attacks_to_run
                         if json.loads((RESULTS_DIR / f"{n}.json").read_text()).get("detectedFailure"))
    print(f"\n{detected_count}/{len(attacks_to_run)} attacks detected correctly.")
    print(f"Results written to {RESULTS_DIR}/")

    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
