# Local Schema Contract

These schemas are stable for the first file-mode capture-and-verify milestone. `camera.json` and `evidence.json` are write-once records. `verification-result.json` is produced each time a verifier checks an evidence item, so one evidence item can have many verification results over its lifetime.

## camera.json

Created during enrollment. The public key becomes the camera identity used for primary source-authentication verification.

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

## evidence.json

Created once during capture. This record describes the exact bytes that were signed and encrypted. Do not mutate this file during verification or export; write a new `verification-result.json` instead.

```json
{
  "evidenceId": "ev-001",
  "cameraId": "cam-001",
  "objectUri": "storage/evidence/ev-001.enc",
  "encryptedFileHash": "sha256-hex",
  "plaintextHash": "sha256-hex",
  "encryptionAlgo": "AES-256-GCM",
  "nonce": "base64",
  "authTag": "base64",
  "wrappedKey": "base64",
  "captureTimestamp": "RFC3339",
  "deviceSignature": "base64",
  "prnuCaptureScore": 0.0,
  "tsaTokenRef": "string",
  "fabricTxId": "string"
}
```

`plaintextHash` is the SHA-256 hash of the exact byte stream passed into signing and encryption. `encryptedFileHash` is the long-term integrity check for the stored encrypted evidence file. AES-256-GCM requires both `nonce` and `authTag` to decrypt and authenticate the ciphertext.

## verification-result.json

Produced by each verification run. This is append-only audit output and maps directly to a future `LogVerification` Fabric transaction.

```json
{
  "verificationId": "ver-001",
  "evidenceId": "ev-001",
  "verifiedAt": "RFC3339",
  "verifierId": "string",
  "encryptedFileHashValid": true,
  "deviceSignatureValid": true,
  "decryptionAttempted": true,
  "decryptionValid": true,
  "decryptedPlaintextHash": "sha256-hex",
  "plaintextHashMatchesEvidence": true,
  "prnuChecked": false,
  "prnuScore": null,
  "primaryDecision": "PASS|FAIL",
  "notes": "string"
}
```

## custody-record.json

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
