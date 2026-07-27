from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Camera
# ---------------------------------------------------------------------------

class EnrollCameraRequest(BaseModel):
    cameraId: str
    deviceSerial: str
    operatorId: str
    ownerPublicKey: str  # base64 X25519 public key


class EnrollCameraResponse(BaseModel):
    ok: bool
    cameraId: str
    cameraJsonPath: str
    privateKeyPath: str


class CameraRecord(BaseModel):
    cameraId: str
    deviceSerial: str
    publicKeyEd25519: str
    prnuReferenceHash: str
    ownerPublicKey: str
    authorizationPolicy: str
    enrollmentTimestamp: str
    operatorId: str


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

class EvidenceListItem(BaseModel):
    evidenceId: str
    cameraId: str
    captureTimestamp: str
    encryptedFileHash: str
    fabricTxId: str


class EvidenceRecord(BaseModel):
    evidenceId: str
    cameraId: str
    objectUri: str
    encryptedFileHash: str
    plaintextHash: str
    encryptionAlgo: str
    nonce: str
    authTag: str
    wrappedKey: str
    captureTimestamp: str
    deviceSignature: str
    prnuCaptureScore: float
    tsaTokenRef: str
    fabricTxId: str


class CaptureResponse(BaseModel):
    ok: bool
    evidenceId: str
    plaintextHash: str
    encryptedFileHash: str
    objectUri: str


class IngestResponse(BaseModel):
    ok: bool
    evidenceId: str
    encryptedFileHash: str
    fabricTxId: str | None


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

class VerifyEvidenceRequest(BaseModel):
    verifierId: str = "system"
    includeDecryption: bool = False


class VerificationResult(BaseModel):
    verificationId: str
    evidenceId: str
    verifiedAt: str
    verifierId: str
    encryptedFileHashValid: bool
    deviceSignatureValid: bool
    decryptionAttempted: bool
    decryptionValid: bool
    decryptedPlaintextHash: str | None
    plaintextHashMatchesEvidence: bool
    prnuChecked: bool
    prnuScore: float | None
    primaryDecision: str
    notes: str


class VerifyEvidenceResponse(BaseModel):
    ok: bool
    result: VerificationResult
