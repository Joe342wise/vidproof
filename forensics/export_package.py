#!/usr/bin/env python3
"""CLI: build a self-contained forensic export package (zip archive).

Contents:
    evidence/<id>.enc              — encrypted video file
    metadata/evidence.json         — immutable evidence record
    metadata/camera.json           — camera record
    metadata/verification-results/ — all verification runs
    tsa/token.tsr                  — timestamp token (if present)
    fabric-history.json            — Fabric custody history (if available)
    MANIFEST.json                  — SHA-256 hashes of all included files
    VERIFY_INSTRUCTIONS.md         — step-by-step verification guide

Usage:
    python forensics/export_package.py \
        --evidence-id ev-001 \
        --out-dir exports/ \
        [--storage-dir storage] \
        [--tsa-url http://localhost:2560] \
        [--fabric-adapter-url http://localhost:8081]

Output (stdout):
    {"ok": true,  "result": {"packagePath": "...", "manifestHash": "..."}}
    {"ok": false, "error": {"code": "...", "message": "..."}}
"""
import argparse
import datetime as _dt
import hashlib
import json
import sys
import zipfile
from pathlib import Path

import requests


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _try_get_fabric_history(adapter_url: str, evidence_id: str) -> list | None:
    """Return Fabric history list or None if adapter not available."""
    try:
        resp = requests.get(
            f"{adapter_url}/evidence/{evidence_id}/history",
            timeout=10,
        )
        data = resp.json()
        if data.get("ok"):
            return data.get("history", [])
    except Exception:
        pass
    return None


def _detect_video_ext(data: bytes) -> str:
    if len(data) >= 12 and data[4:8] in (b"ftyp", b"mdat", b"moov", b"free"):
        return ".mp4"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"AVI ":
        return ".avi"
    if len(data) >= 4 and data[:3] in (b"\x00\x00\x01", b"\x1a\x45\xdf\xa3"):
        return ".mkv"
    return ".mp4"


def build_package(
    evidence_id: str,
    out_dir: Path,
    storage_dir: Path = Path("storage"),
    fabric_adapter_url: str = "http://localhost:8081",
    owner_privkey_path: Path | None = None,
) -> dict:
    """Build a forensic zip package.

    Returns a result dict on success. Raises ValueError on failure.
    """
    eid = evidence_id
    storage = storage_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    enc_path = storage / "evidence" / f"{eid}.enc"
    evidence_path = storage / "metadata" / "evidence" / f"{eid}.json"

    if not enc_path.exists():
        raise ValueError(f"ENC_NOT_FOUND: Encrypted evidence file not found: {enc_path}")
    if not evidence_path.exists():
        raise ValueError(f"EVIDENCE_NOT_FOUND: Evidence record not found: {evidence_path}")

    try:
        evidence = json.loads(evidence_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"EVIDENCE_READ_ERROR: {exc}")

    camera_id = evidence.get("cameraId", "")
    camera_path = storage / "metadata" / "cameras" / f"{camera_id}.json"
    if not camera_path.exists():
        raise ValueError(f"CAMERA_NOT_FOUND: Camera record not found: {camera_path}")

    results_dir = storage / "metadata" / "results"
    ver_records: list[tuple[str, bytes]] = []
    if results_dir.exists():
        for vpath in sorted(results_dir.glob("ver-*.json")):
            try:
                rec = json.loads(vpath.read_text())
                if rec.get("evidenceId") == eid:
                    ver_records.append((vpath.name, vpath.read_bytes()))
            except (json.JSONDecodeError, OSError):
                continue

    tsr_path = storage / "tsa" / f"{eid}.tsr"
    tsr_bytes: bytes | None = tsr_path.read_bytes() if tsr_path.exists() else None

    fabric_history = _try_get_fabric_history(fabric_adapter_url, eid)

    zip_path = out_dir / f"{eid}.zip"
    manifest: dict[str, str] = {}

    enc_bytes = enc_path.read_bytes()
    evidence_bytes = evidence_path.read_bytes()
    camera_bytes = camera_path.read_bytes()

    plaintext_bytes: bytes | None = None
    plaintext_ext = ".mp4"
    if owner_privkey_path is not None:
        try:
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from forensics.crypto_core import decrypt_aes_gcm, unwrap_aes_key
            aes_key = unwrap_aes_key(evidence["wrappedKey"], owner_privkey_path)
            plaintext_bytes = decrypt_aes_gcm(
                enc_path,
                evidence["nonce"],
                evidence["authTag"],
                aes_key,
            )
            plaintext_ext = _detect_video_ext(plaintext_bytes)
        except Exception:
            plaintext_bytes = None

    verify_instructions = _build_verify_instructions(
        eid=eid,
        evidence=evidence,
        has_tsr=tsr_bytes is not None,
    )

    now = _dt.datetime.now(_dt.timezone.utc)
    _ts = (now.year, now.month, now.day, now.hour, now.minute, now.second)

    def _zip_entry(arcname: str, mode: int = 0o444) -> zipfile.ZipInfo:
        info = zipfile.ZipInfo(arcname, date_time=_ts)
        info.compress_type = zipfile.ZIP_DEFLATED
        # Upper 16 bits: Unix permissions (Linux/macOS)
        # Lower 16 bits: MS-DOS attributes — 0x01 = read-only (Windows)
        info.external_attr = (mode << 16) | 0x01
        return info

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        def add(arcname: str, data: bytes, mode: int = 0o444) -> None:
            zf.writestr(_zip_entry(arcname, mode), data)
            manifest[arcname] = sha256_bytes(data)

        add(f"evidence/{eid}.enc", enc_bytes)
        if plaintext_bytes is not None:
            add(f"video/{eid}{plaintext_ext}", plaintext_bytes)
        add("metadata/evidence.json", evidence_bytes)
        add("metadata/camera.json", camera_bytes)

        for fname, fbytes in ver_records:
            add(f"metadata/verification-results/{fname}", fbytes)

        if tsr_bytes is not None:
            add("tsa/token.tsr", tsr_bytes)

        if fabric_history is not None:
            history_bytes = json.dumps(fabric_history, indent=2).encode()
            add("fabric-history.json", history_bytes)

        add("VERIFY_INSTRUCTIONS.md", verify_instructions.encode())

        manifest_payload = {
            "evidenceId": eid,
            "exportedAt": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "fabricHistoryIncluded": fabric_history is not None,
            "tsaTokenIncluded": tsr_bytes is not None,
            "files": manifest,
        }
        manifest_bytes = json.dumps(manifest_payload, indent=2).encode()
        zf.writestr(_zip_entry("MANIFEST.json"), manifest_bytes)

    manifest_hash = sha256_bytes(zip_path.read_bytes())

    return {
        "packagePath": str(zip_path),
        "manifestHash": manifest_hash,
        "filesIncluded": len(manifest) + 1,
        "tsaTokenIncluded": tsr_bytes is not None,
        "fabricHistoryIncluded": fabric_history is not None,
        "verificationResultsIncluded": len(ver_records),
        "videoIncluded": plaintext_bytes is not None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a forensic export package")
    parser.add_argument("--evidence-id", required=True)
    parser.add_argument("--out-dir", required=True, help="Output directory for the zip archive")
    parser.add_argument("--storage-dir", default="storage")
    parser.add_argument("--tsa-url", default=None, help="TSA URL (currently unused; token read from storage)")
    parser.add_argument("--fabric-adapter-url", default="http://localhost:8081")
    args = parser.parse_args()

    try:
        result = build_package(
            evidence_id=args.evidence_id,
            out_dir=Path(args.out_dir),
            storage_dir=Path(args.storage_dir),
            fabric_adapter_url=args.fabric_adapter_url,
        )
    except ValueError as exc:
        msg = str(exc)
        code, _, message = msg.partition(": ")
        print(json.dumps({"ok": False, "error": {"code": code, "message": message or msg}}))
        return 1

    print(json.dumps({"ok": True, "result": result}))
    return 0


def _build_verify_instructions(eid: str, evidence: dict, has_tsr: bool) -> str:
    enc_hash = evidence.get("encryptedFileHash", "<encryptedFileHash>")
    sig = evidence.get("deviceSignature", "<deviceSignature>")
    cam_pub = evidence.get("publicKeyEd25519", "<publicKeyEd25519 from camera.json>")
    pt_hash = evidence.get("plaintextHash", "<plaintextHash>")

    tsr_section = ""
    if has_tsr:
        tsr_section = f"""
## 3. Verify RFC 3161 Timestamp Token

```bash
# Verify the timestamp token against the encrypted file hash
openssl ts -verify \\
    -in tsa/token.tsr \\
    -digest {enc_hash} \\
    -sha256 \\
    -CAfile <tsa-ca.crt> \\
    -untrusted <tsa.crt>
# Expected output: Verification: OK
```
"""

    return f"""# VidProof — Forensic Package Verification Instructions

Evidence ID: `{eid}`

This package was produced by VidProof and can be verified independently
using standard tools (OpenSSL, Python 3).

> **How authentication works in this package.**
> VidProof signs the plaintext block hash *before* encryption. The encrypted
> video block (`evidence/{eid}.enc`) is ciphertext only — the device signature
> is stored separately in `metadata/evidence.json` and anchored in Hyperledger
> Fabric. The signature is therefore verifiable without decrypting the video,
> and decryption is independent of signature verification. Steps 1 and 2 below
> can be performed in either order.

---

## 1. Verify Encrypted File Integrity

```bash
sha256sum evidence/{eid}.enc
# Must match: {enc_hash}
```

Or with Python:
```python
import hashlib, pathlib
h = hashlib.sha256(pathlib.Path("evidence/{eid}.enc").read_bytes()).hexdigest()
assert h == "{enc_hash}", f"Hash mismatch: {{h}}"
print("File integrity: OK")
```

---

## 2. Verify Device Signature

The device signature proves the plaintext hash was attested by the enrolled
camera's Ed25519 private key at capture time.

```python
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

pubkey_b64  = "{cam_pub}"
sig_b64     = "{sig}"
hash_hex    = "{pt_hash}"

pub  = Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64))
sig  = base64.b64decode(sig_b64)
data = bytes.fromhex(hash_hex)
pub.verify(sig, data)   # raises InvalidSignature on failure
print("Device signature: OK")
```
{tsr_section}
---

## Files in this package

| Path | Contents |
|---|---|
| `evidence/{eid}.enc` | AES-256-GCM encrypted video (ciphertext only) |
| `metadata/evidence.json` | Immutable evidence record — hashes, signature, timestamps |
| `metadata/camera.json` | Enrolled camera record — Ed25519 public key |
| `metadata/verification-results/` | All verification runs for this evidence item |
| `tsa/token.tsr` | RFC 3161 timestamp token (if included) |
| `fabric-history.json` | Hyperledger Fabric custody history (if included) |
| `MANIFEST.json` | SHA-256 hashes of every file in this package |

---

*Generated by VidProof forensic export.*
"""


if __name__ == "__main__":
    raise SystemExit(main())
