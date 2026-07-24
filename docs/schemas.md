# Draft Schemas

## Camera Asset

```json
{
  "cameraId": "cam-001",
  "deviceSerial": "string",
  "publicKeyEd25519": "base64",
  "prnuReferenceHash": "sha256-hex",
  "ownerPublicKey": "base64",
  "authorizationPolicy": "string",
  "enrollmentTimestamp": "RFC3339",
  "operatorId": "string"
}
```

## Evidence Asset

```json
{
  "evidenceId": "ev-001",
  "cameraId": "cam-001",
  "objectUri": "storage/evidence/ev-001.enc",
  "encryptedFileHash": "sha256-hex",
  "plaintextHash": "sha256-hex",
  "encryptionAlgo": "AES-256-GCM",
  "nonce": "base64",
  "wrappedKey": "base64",
  "captureTimestamp": "RFC3339",
  "deviceSignature": "base64",
  "prnuCaptureScore": 0.0,
  "tsaTokenRef": "string",
  "fabricTxId": "string"
}
```

## Custody Record

```json
{
  "evidenceId": "ev-001",
  "actorId": "string",
  "actorRole": "camera|owner|investigator|system",
  "actionType": "REGISTER|ACCESS|VERIFY|EXPORT|FAILURE",
  "timestamp": "RFC3339",
  "evidenceHash": "sha256-hex",
  "deviceSignature": "base64",
  "prnuScore": 0.0,
  "tsaTokenHash": "sha256-hex",
  "digitalSignature": "base64",
  "previousTxRef": "string"
}
```
