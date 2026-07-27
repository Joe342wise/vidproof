import os
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from backend.app.config import settings
from backend.app.models import (
    CaptureResponse,
    EvidenceRecord,
    VerificationResult,
    VerifyEvidenceRequest,
    VerifyEvidenceResponse,
)
from backend.app.services import capture as capture_svc
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
