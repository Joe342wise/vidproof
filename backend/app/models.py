from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Camera
# ---------------------------------------------------------------------------

class EnrollCameraRequest(BaseModel):
    cameraId: str
    deviceSerial: str
    operatorId: str
    ownerPublicKey: str           # base64 raw X25519 public key (32 bytes)
    devicePublicKeyEd25519: str | None = None  # base64 raw Ed25519 public key (32 bytes); if omitted the server generates a keypair


class EnrollCameraResponse(BaseModel):
    ok: bool
    cameraId: str
    cameraJsonPath: str
    privateKeyPath: str | None    # None when the device supplied its own public key
    publicKeyEd25519: str


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
    tsaTokenHash: str = ""
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


class ExportRequest(BaseModel):
    includeDecryption: bool = False


class BulkExportRequest(BaseModel):
    evidenceIds: list[str]
    includeDecryption: bool = False


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

class VerifyEvidenceRequest(BaseModel):
    verifierId: str = "system"
    includeDecryption: bool = False
    overridePublicKeyEd25519: str | None = None  # base64 raw Ed25519 key; overrides the enrolled camera record


class VerificationResult(BaseModel):
    verificationId: str
    evidenceId: str
    verifiedAt: str
    verifierId: str
    publicKeySource: str = "enrolled"  # "enrolled" | "override"
    encryptedFileHashValid: bool
    deviceSignatureValid: bool
    decryptionAttempted: bool
    decryptionValid: bool
    decryptedPlaintextHash: str | None
    plaintextHashMatchesEvidence: bool
    prnuChecked: bool
    prnuScore: float | None
    tsaChecked: bool = False
    tsaValid: bool | None = None
    tsaDetail: str | None = None
    primaryDecision: str
    failedChecks: list[str] = []
    notes: str


class VerifyEvidenceResponse(BaseModel):
    ok: bool
    result: VerificationResult


class AttackDemoRequest(BaseModel):
    attackType: str  # "bit_flip" | "forge_signature" | "metadata_injection"


class AttackDemoResponse(BaseModel):
    ok: bool
    attackType: str
    attackDescription: str
    result: VerificationResult
