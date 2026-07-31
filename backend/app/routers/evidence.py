import hashlib
import json
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import Response as RawResponse

from backend.app.config import settings
from backend.app.models import (
    AttackDemoRequest,
    AttackDemoResponse,
    BulkExportRequest,
    CaptureResponse,
    EvidenceRecord,
    ExportRequest,
    IngestResponse,
    VerificationResult,
    VerifyEvidenceRequest,
    VerifyEvidenceResponse,
)
from backend.app.services import capture as capture_svc
from backend.app.services import fabric_client
from backend.app.services import verification as verification_svc

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.post("/capture", response_model=CaptureResponse, status_code=201)
async def capture_evidence(
    camera_id: str = Form(...),
    evidence_id: str = Form(None),
    video_file: UploadFile = File(...),
):
    tmp_dir = settings.evidence_dir / "uploads"
    tmp_path: Path | None = None
    try:
        tmp_path = await capture_svc.save_upload(video_file, tmp_dir)
        record = capture_svc.capture_evidence(
            video_path=tmp_path,
            camera_id=camera_id,
            evidence_id=evidence_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"File I/O error: {exc}")
    finally:
        if tmp_path and tmp_path.exists():
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return CaptureResponse(
        ok=True,
        evidenceId=record["evidenceId"],
        plaintextHash=record["plaintextHash"],
        encryptedFileHash=record["encryptedFileHash"],
        objectUri=record["objectUri"],
    )


@router.post("/ingest", response_model=IngestResponse, status_code=201)
async def ingest_evidence(
    evidence_json: str = Form(...),
    enc_file: UploadFile = File(...),
):
    """Accept pre-signed, pre-encrypted evidence from an edge device (e.g. Raspberry Pi).

    The edge device runs the full crypto pipeline locally — this endpoint only
    validates, stores, and registers to Fabric. It never sees plaintext video.
    """
    enc_bytes = await enc_file.read()
    try:
        record = capture_svc.ingest_device_evidence(evidence_json, enc_bytes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Storage error: {exc}")

    return IngestResponse(
        ok=True,
        evidenceId=record["evidenceId"],
        encryptedFileHash=record["encryptedFileHash"],
        fabricTxId=record.get("fabricTxId") or None,
    )


@router.post("/export/bulk")
def export_evidence_bulk(body: BulkExportRequest):
    """Bundle multiple evidence blocks into one zip archive.

    Each block is packaged individually under blocks/<evidenceId>/ inside the
    master zip.  Fabric export events are logged for every included block.
    """
    from forensics.export_package import build_package

    if not body.evidenceIds:
        raise HTTPException(status_code=400, detail="evidenceIds must not be empty")

    owner_privkey_path = None
    if body.includeDecryption:
        candidate = settings.keys_dir / "owner.x25519.priv.pem"
        if not candidate.exists():
            raise HTTPException(status_code=400, detail="Owner private key not found on server — cannot decrypt")
        owner_privkey_path = candidate

    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    master_manifest: dict = {"exportedAt": now_ts, "blocks": {}}

    with tempfile.TemporaryDirectory() as tmp_root:
        tmp = Path(tmp_root)
        master_zip_path = tmp / "bulk-export.zip"

        with zipfile.ZipFile(master_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as mzf:
            for eid in body.evidenceIds:
                block_dir = tmp / eid
                block_dir.mkdir(exist_ok=True)
                try:
                    result = build_package(
                        evidence_id=eid,
                        out_dir=block_dir,
                        storage_dir=settings.storage_dir,
                        fabric_adapter_url=settings.fabric_adapter_url,
                        owner_privkey_path=owner_privkey_path,
                    )
                except ValueError as exc:
                    raise HTTPException(status_code=404, detail=str(exc))

                with zipfile.ZipFile(Path(result["packagePath"]), "r") as bzf:
                    for name in bzf.namelist():
                        mzf.writestr(f"blocks/{eid}/{name}", bzf.read(name))

                master_manifest["blocks"][eid] = {
                    "filesIncluded": result["filesIncluded"],
                    "tsaTokenIncluded": result["tsaTokenIncluded"],
                    "fabricHistoryIncluded": result["fabricHistoryIncluded"],
                    "verificationResultsIncluded": result["verificationResultsIncluded"],
                    "videoIncluded": result.get("videoIncluded", False),
                }

                fabric_client.log_export(
                    evidence_id=eid,
                    actor_id="operator",
                    timestamp=now_ts,
                    notes=f"bulk export ({len(body.evidenceIds)} blocks)",
                )

            mzf.writestr("MANIFEST.json", json.dumps(master_manifest, indent=2))
            mzf.writestr(
                "VERIFY_INSTRUCTIONS.md",
                (
                    f"# VidProof Bulk Export — {len(body.evidenceIds)} block(s)\n\n"
                    "Each evidence block is in its own directory under `blocks/`.\n"
                    "See `blocks/<evidenceId>/VERIFY_INSTRUCTIONS.md` for per-block "
                    "verification steps using only OpenSSL and Python 3.\n"
                ),
            )

        zip_bytes = master_zip_path.read_bytes()

    filename = f"vidproof-export-{now_ts[:10]}.zip"
    return RawResponse(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/", response_model=list[EvidenceRecord])
def list_evidence():
    return capture_svc.list_evidence()


@router.post("/verify-package")
async def verify_package(package_file: UploadFile = File(...)):
    """Verify an exported zip package and report any tampering.

    Accepts both single-block and bulk export packages.  For each block the
    response includes:
      - manifestIntegrity: per-file hash comparison against the package MANIFEST
      - verification: the standard hash + signature result run against the
        uploaded files (not the server copy), using the camera key from the
        package's own camera.json
    """
    from forensics.verify import run_verify

    zip_bytes = await package_file.read()

    with tempfile.TemporaryDirectory() as tmp_root:
        tmp = Path(tmp_root)
        zip_path = tmp / "upload.zip"
        zip_path.write_bytes(zip_bytes)

        try:
            zf = zipfile.ZipFile(zip_path, "r")
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Uploaded file is not a valid zip archive")

        names = set(zf.namelist())

        try:
            master_manifest = json.loads(zf.read("MANIFEST.json"))
        except KeyError:
            raise HTTPException(status_code=400, detail="Package is missing MANIFEST.json")
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="MANIFEST.json is not valid JSON")

        is_bulk = "blocks" in master_manifest
        block_ids: list[str] = (
            list(master_manifest["blocks"].keys()) if is_bulk
            else [master_manifest.get("evidenceId", "")]
        )

        blocks_out = []

        for eid in block_ids:
            pfx = f"blocks/{eid}/" if is_bulk else ""

            # --- manifest integrity ---
            try:
                block_manifest = json.loads(zf.read(f"{pfx}MANIFEST.json"))
            except (KeyError, json.JSONDecodeError):
                blocks_out.append({"evidenceId": eid, "_error": "Block MANIFEST.json missing or invalid"})
                continue

            file_results: dict[str, str] = {}
            tampered: list[str] = []
            for rel_path, expected_hash in block_manifest.get("files", {}).items():
                full_name = f"{pfx}{rel_path}"
                if full_name not in names:
                    file_results[rel_path] = "MISSING"
                    tampered.append(rel_path)
                else:
                    actual = hashlib.sha256(zf.read(full_name)).hexdigest()
                    if actual == expected_hash:
                        file_results[rel_path] = "OK"
                    else:
                        file_results[rel_path] = "TAMPERED"
                        tampered.append(rel_path)

            # --- extract files for verification ---
            block_tmp = tmp / eid
            block_tmp.mkdir(exist_ok=True)

            enc_name      = f"{pfx}evidence/{eid}.enc"
            evidence_name = f"{pfx}metadata/evidence.json"
            camera_name   = f"{pfx}metadata/camera.json"

            missing = [n for n in (enc_name, evidence_name, camera_name) if n not in names]
            if missing:
                blocks_out.append({
                    "evidenceId": eid,
                    "manifestIntegrity": {"ok": not tampered, "fileResults": file_results, "tamperedFiles": tampered},
                    "_error": f"Required file(s) missing from package: {missing}",
                })
                continue

            enc_path      = block_tmp / f"{eid}.enc"
            evidence_path = block_tmp / "evidence.json"
            camera_path   = block_tmp / "camera.json"

            enc_path.write_bytes(zf.read(enc_name))
            evidence_path.write_bytes(zf.read(evidence_name))
            camera_path.write_bytes(zf.read(camera_name))

            try:
                verify_result = run_verify(
                    evidence_id=eid,
                    camera_json_path=camera_path,
                    storage_dir=block_tmp,
                    enc_path_override=enc_path,
                    evidence_json_override=evidence_path,
                    verifier_id="package-verify",
                    dry_run=True,
                )
            except Exception as exc:
                verify_result = {"_error": str(exc)}

            blocks_out.append({
                "evidenceId": eid,
                "manifestIntegrity": {
                    "ok": len(tampered) == 0,
                    "fileResults": file_results,
                    "tamperedFiles": tampered,
                },
                "verification": verify_result,
            })

        zf.close()

    return {
        "ok": True,
        "packageType": "bulk" if is_bulk else "single",
        "blockCount": len(block_ids),
        "blocks": blocks_out,
    }


@router.post("/{evidence_id}/verify", response_model=VerifyEvidenceResponse)
def verify_evidence(evidence_id: str, req: VerifyEvidenceRequest):
    try:
        result = verification_svc.verify_evidence(
            evidence_id=evidence_id,
            verifier_id=req.verifierId,
            include_decryption=req.includeDecryption,
            override_public_key_b64=req.overridePublicKeyEd25519,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"File I/O error: {exc}")

    return VerifyEvidenceResponse(ok=True, result=VerificationResult(**result))


@router.post("/{evidence_id}/attack-demo", response_model=AttackDemoResponse)
def attack_demo(evidence_id: str, req: AttackDemoRequest):
    try:
        result = verification_svc.run_attack_demo(
            evidence_id=evidence_id,
            attack_type=req.attackType,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"File I/O error: {exc}")

    return AttackDemoResponse(
        ok=True,
        attackType=result["_attackType"],
        attackDescription=result["_attackDescription"],
        result=VerificationResult(**{k: v for k, v in result.items() if not k.startswith("_")}),
    )


@router.get("/{evidence_id}/verification-results", response_model=list[VerificationResult])
def list_verification_results(evidence_id: str):
    return verification_svc.list_verification_results(evidence_id)


@router.get("/{evidence_id}/fabric-history")
def get_fabric_history(evidence_id: str):
    history = fabric_client.get_evidence_history(evidence_id)
    return {"ok": True, "history": history or [], "available": history is not None}


@router.post("/{evidence_id}/export")
def export_evidence_package(evidence_id: str, body: ExportRequest = ExportRequest()):
    from forensics.export_package import build_package

    owner_privkey_path = None
    if body.includeDecryption:
        candidate = settings.keys_dir / "owner.x25519.priv.pem"
        if not candidate.exists():
            raise HTTPException(status_code=400, detail="Owner private key not found on server — cannot decrypt")
        owner_privkey_path = candidate

    with tempfile.TemporaryDirectory() as tmp:
        try:
            result = build_package(
                evidence_id=evidence_id,
                out_dir=Path(tmp),
                storage_dir=settings.storage_dir,
                fabric_adapter_url=settings.fabric_adapter_url,
                owner_privkey_path=owner_privkey_path,
            )
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        zip_bytes = Path(result["packagePath"]).read_bytes()

    fabric_client.log_export(
        evidence_id=evidence_id,
        actor_id="operator",
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        notes="forensic export package generated",
    )

    return RawResponse(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{evidence_id}.zip"'},
    )
