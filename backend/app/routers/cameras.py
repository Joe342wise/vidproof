from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from backend.app.models import (
    CameraRecord,
    EnrollCameraRequest,
    EnrollCameraResponse,
)
from backend.app.services import enrollment as enrollment_svc

router = APIRouter(prefix="/camera", tags=["cameras"])


@router.get("/owner-public-key")
def get_owner_public_key():
    """Return the server's owner X25519 public key (base64). Used by the enrollment form."""
    pub = enrollment_svc.get_owner_public_key()
    if pub is None:
        return JSONResponse({"ok": False, "ownerPublicKey": None,
                             "detail": "Owner keypair not set up on this server."}, status_code=404)
    return {"ok": True, "ownerPublicKey": pub}


@router.post("/enroll", response_model=EnrollCameraResponse, status_code=201)
def enroll_camera(req: EnrollCameraRequest):
    try:
        record = enrollment_svc.enroll_camera(
            camera_id=req.cameraId,
            device_serial=req.deviceSerial,
            operator_id=req.operatorId,
            owner_public_key_b64=req.ownerPublicKey,
            device_public_key_b64=req.devicePublicKeyEd25519,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"File I/O error: {exc}")

    return EnrollCameraResponse(
        ok=True,
        cameraId=record["cameraId"],
        cameraJsonPath=record["_cameraJsonPath"],
        privateKeyPath=record["_privateKeyPath"],
        publicKeyEd25519=record["publicKeyEd25519"],
    )


@router.get("/", response_model=list[CameraRecord])
def list_cameras():
    return enrollment_svc.list_cameras()


@router.get("/{camera_id}", response_model=CameraRecord)
def get_camera(camera_id: str):
    record = enrollment_svc.get_camera(camera_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Camera '{camera_id}' not found")
    return record


@router.delete("/{camera_id}", status_code=204)
def delete_camera(camera_id: str):
    try:
        enrollment_svc.delete_camera(camera_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
