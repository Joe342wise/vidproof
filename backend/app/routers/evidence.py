import os
import tempfile
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import Response as RawResponse

from backend.app.config import settings
from backend.app.models import (
    CaptureResponse,
    EvidenceRecord,
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

    fabric_tx = fabric_client.register_evidence(record["evidenceId"], record)

    return IngestResponse(
        ok=True,
        evidenceId=record["evidenceId"],
        encryptedFileHash=record["encryptedFileHash"],
        fabricTxId=fabric_tx,
    )


@router.get("/", response_model=list[EvidenceRecord])
def list_evidence():
    return capture_svc.list_evidence()


@router.post("/{evidence_id}/verify", response_model=VerifyEvidenceResponse)
def verify_evidence(evidence_id: str, req: VerifyEvidenceRequest):
    try:
        result = verification_svc.verify_evidence(
            evidence_id=evidence_id,
            verifier_id=req.verifierId,
            include_decryption=req.includeDecryption,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"File I/O error: {exc}")

    return VerifyEvidenceResponse(ok=True, result=VerificationResult(**result))


@router.get("/{evidence_id}/verification-results", response_model=list[VerificationResult])
def list_verification_results(evidence_id: str):
    return verification_svc.list_verification_results(evidence_id)


@router.get("/{evidence_id}/fabric-history")
def get_fabric_history(evidence_id: str):
    history = fabric_client.get_evidence_history(evidence_id)
    return {"ok": True, "history": history or [], "available": history is not None}


@router.post("/{evidence_id}/export")
def export_evidence_package(evidence_id: str):
    from forensics.export_package import build_package

    with tempfile.TemporaryDirectory() as tmp:
        try:
            result = build_package(
                evidence_id=evidence_id,
                out_dir=Path(tmp),
                storage_dir=settings.storage_dir,
                fabric_adapter_url=settings.fabric_adapter_url,
            )
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        zip_bytes = Path(result["packagePath"]).read_bytes()

    return RawResponse(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{evidence_id}.zip"'},
    )
