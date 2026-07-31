#!/usr/bin/env python3
import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

sys.path.insert(0, str(Path(__file__).parent.parent))
from forensics.crypto_core import (
    decrypt_aes_gcm,
    sha256_bytes,
    sha256_file,
    unwrap_aes_key,
    verify_ed25519_signature,
)


def fail(code: str, message: str, exit_code: int = 1) -> int:
    print(json.dumps({"ok": False, "error": {"code": code, "message": message}}))
    return exit_code


def run_verify(
    evidence_id: str,
    camera_json_path: Path,
    storage_dir: Path,
    owner_privkey_path: Path | None = None,
    verifier_id: str = "system",
    evidence_json_override: Path | None = None,
    enc_path_override: Path | None = None,
    tsa_ca_cert: Path | None = None,
    tsa_cert: Path | None = None,
    dry_run: bool = False,
    override_public_key_b64: str | None = None,
) -> dict:
    # Resolve evidence.json path — override is for tamper testing only
    if evidence_json_override is not None:
        evidence_path = evidence_json_override
    else:
        evidence_path = storage_dir / "metadata" / "evidence" / f"{evidence_id}.json"

    try:
        evidence = json.loads(evidence_path.read_text())
    except OSError as exc:
        raise OSError(f"Cannot read evidence.json: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"evidence.json is not valid JSON: {exc}") from exc

    try:
        camera = json.loads(camera_json_path.read_text())
    except OSError as exc:
        raise OSError(f"Cannot read camera.json: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"camera.json is not valid JSON: {exc}") from exc

    enc_path = enc_path_override if enc_path_override is not None else storage_dir / "evidence" / f"{evidence_id}.enc"

    # Step 1: verify encrypted file integrity
    encrypted_file_hash_valid = False
    try:
        recomputed = sha256_file(enc_path)
        encrypted_file_hash_valid = recomputed == evidence["encryptedFileHash"]
    except OSError:
        encrypted_file_hash_valid = False

    # Step 2: verify device signature
    # The override key lets an independent verifier supply the key directly
    # (e.g. from a QR code scan) rather than trusting the enrolled record.
    public_key_source = "enrolled"
    if override_public_key_b64 is not None:
        sig_public_key = override_public_key_b64
        public_key_source = "override"
    else:
        sig_public_key = camera.get("publicKeyEd25519", "")

    device_signature_valid = False
    try:
        device_signature_valid = verify_ed25519_signature(
            hash_hex=evidence["plaintextHash"],
            signature_b64=evidence["deviceSignature"],
            public_key_b64=sig_public_key,
        )
    except (ValueError, KeyError):
        device_signature_valid = False

    # Step 3: optional decryption
    decryption_attempted = False
    decryption_valid = False
    decrypted_plaintext_hash: str | None = None
    plaintext_hash_matches_evidence = False
    notes_parts = []

    if owner_privkey_path is not None:
        decryption_attempted = True
        try:
            aes_key = unwrap_aes_key(evidence["wrappedKey"], owner_privkey_path)
            plaintext = decrypt_aes_gcm(
                enc_path=enc_path,
                nonce_b64=evidence["nonce"],
                auth_tag_b64=evidence["authTag"],
                aes_key=aes_key,
            )
            decryption_valid = True
            decrypted_plaintext_hash = sha256_bytes(plaintext)
            plaintext_hash_matches_evidence = (
                decrypted_plaintext_hash == evidence["plaintextHash"]
            )
            if not plaintext_hash_matches_evidence:
                notes_parts.append("Decrypted plaintext hash does not match evidence record.")
        except InvalidUnwrap:
            decryption_valid = False
            notes_parts.append("AES key unwrap failed — wrappedKey may be tampered.")
        except InvalidTag:
            decryption_valid = False
            notes_parts.append("AES-GCM authentication failed — nonce, authTag, or ciphertext may be tampered.")
        except OSError as exc:
            decryption_valid = False
            notes_parts.append(f"Decryption I/O error: {exc}")

    # Step 4: RFC 3161 timestamp verification (optional — skipped if no token or no certs)
    tsa_checked = False
    tsa_valid: bool | None = None
    tsa_detail: str | None = None

    tsr_ref = evidence.get("tsaTokenRef", "")
    if tsr_ref and tsa_ca_cert and tsa_cert:
        from forensics.tsa_verify import verify_tsa_token
        tsa_result = verify_tsa_token(Path(tsr_ref), evidence["encryptedFileHash"], tsa_ca_cert, tsa_cert)
        tsa_checked = True
        tsa_valid = tsa_result["valid"]
        tsa_detail = tsa_result["detail"]
        if not tsa_valid:
            notes_parts.append(f"RFC 3161 timestamp verification failed: {tsa_detail}")

    # Overall decision.
    #
    # Mandatory gates are always evaluated. Conditional gates bind only when the
    # corresponding check actually ran — a check that was skipped is reported as
    # unchecked, never as a failure. This stops records ingested before a
    # capability existed (e.g. no TSA running) from becoming retroactive
    # failures, while ensuring a check that ran and failed can never be
    # reported as an overall pass.
    # Primary decision: hash + signature only (per system design in CLAUDE.md).
    # Decryption and TSA are secondary checks — their failures are recorded in
    # failedChecks for transparency but do not change primaryDecision.
    primary_failed: list[str] = []
    if not encrypted_file_hash_valid:
        primary_failed.append("encryptedFileHash")
    if not device_signature_valid:
        primary_failed.append("deviceSignature")

    secondary_failed: list[str] = []
    if decryption_attempted:
        if not decryption_valid:
            secondary_failed.append("decryption")
        elif not plaintext_hash_matches_evidence:
            secondary_failed.append("plaintextHashMatch")
    if tsa_checked and not tsa_valid:
        secondary_failed.append("tsaToken")

    failed_checks = primary_failed + secondary_failed
    primary_decision = "FAIL" if primary_failed else "PASS"

    if not encrypted_file_hash_valid:
        notes_parts.append("Encrypted file hash mismatch — ciphertext may be tampered.")
    if not device_signature_valid:
        notes_parts.append("Device signature verification failed — signature or plaintext hash may be tampered.")

    verification_id = "ver-" + secrets.token_hex(8)
    verified_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    result = {
        "verificationId": verification_id,
        "evidenceId": evidence_id,
        "verifiedAt": verified_at,
        "verifierId": verifier_id,
        "publicKeySource": public_key_source,
        "encryptedFileHashValid": encrypted_file_hash_valid,
        "deviceSignatureValid": device_signature_valid,
        "decryptionAttempted": decryption_attempted,
        "decryptionValid": decryption_valid,
        "decryptedPlaintextHash": decrypted_plaintext_hash,
        "plaintextHashMatchesEvidence": plaintext_hash_matches_evidence,
        "prnuChecked": False,
        "prnuScore": None,
        "tsaChecked": tsa_checked,
        "tsaValid": tsa_valid,
        "tsaDetail": tsa_detail,
        "primaryDecision": primary_decision,
        "failedChecks": failed_checks,
        "notes": " ".join(notes_parts) if notes_parts else "All primary checks passed.",
    }

    if not dry_run:
        results_dir = storage_dir / "metadata" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        result_path = results_dir / f"{verification_id}.json"
        result_path.write_text(json.dumps(result, indent=2))
        os.chmod(result_path, 0o444)

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify evidence integrity and authenticity.")
    parser.add_argument("--evidence-id", required=True, help="Evidence ID to verify")
    parser.add_argument("--camera-json", required=True, help="Path to camera.json")
    parser.add_argument("--owner-privkey", default=None, help="Path to owner X25519 private key PEM (enables decryption)")
    parser.add_argument("--verifier-id", default="system", help="Identifier of the verifier")
    parser.add_argument("--storage-dir", default="storage", help="Storage root directory")
    parser.add_argument("--evidence-json", default=None, help="Override evidence.json path (for tamper testing)")
    args = parser.parse_args()

    try:
        result = run_verify(
            evidence_id=args.evidence_id,
            camera_json_path=Path(args.camera_json),
            storage_dir=Path(args.storage_dir),
            owner_privkey_path=Path(args.owner_privkey) if args.owner_privkey else None,
            verifier_id=args.verifier_id,
            evidence_json_override=Path(args.evidence_json) if args.evidence_json else None,
        )
    except (OSError, ValueError) as exc:
        return fail("VERIFY_FAILED", str(exc))

    print(json.dumps({"ok": True, "result": result}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
