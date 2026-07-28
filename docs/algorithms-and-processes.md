# Algorithms And Processes

This document defines the step-by-step processes that VidProof will implement. It is the working reference for developers and for the project report methodology chapter.

## 1. System-Level Flow

### Purpose

Capture surveillance footage, prove it was attested by an enrolled camera device, encrypt it for privacy, preserve integrity records, and support later forensic verification.

### End-To-End Process

1. Enroll a camera device.
2. Generate or register the camera's Ed25519 signing public key.
3. Capture video in 10-second segments.
4. Hash the exact plaintext bytes that will be encrypted.
5. Sign the plaintext hash with the camera private key.
6. Encrypt the video segment using AES-256-GCM.
7. Hash the encrypted evidence file.
8. Store encrypted evidence and immutable metadata.
9. Timestamp the signed capture record using RFC 3161.
10. Register evidence and custody records in Hyperledger Fabric through the Go adapter.
11. Verify evidence later using hashes, signatures, timestamps, and ledger history.
12. Decrypt only when an authorized investigator needs to view or analyze the footage.
13. Run PRNU only as a secondary forensic signal, not as the primary pass/fail gate.

## 2. Camera Enrollment Algorithm

### Purpose

Create a trusted camera identity before any footage is accepted as evidence.

### Inputs

- Camera ID or generated camera ID.
- Device serial or local device identifier.
- Operator ID.
- Owner/investigator public key.
- Optional PRNU reference frames or clips.

### Outputs

- `camera.json`.
- Ed25519 private key stored on the camera device.
- Ed25519 public key registered in metadata and Fabric.
- Optional PRNU reference fingerprint and hash.
- Fabric camera registration transaction.

### Steps

1. Start trusted pairing ceremony on the Raspberry Pi or file-mode simulator.
2. Generate an Ed25519 key pair.
3. Store the private key in a restricted local path on the camera device.
4. Export the public key in base64 format.
5. Capture PRNU reference frames if PRNU testing is enabled.
6. Extract the PRNU reference fingerprint from reference material.
7. Hash the PRNU reference fingerprint using SHA-256.
8. Create `camera.json` containing camera ID, serial, public key, owner public key, PRNU reference hash, operator ID, and enrollment timestamp.
9. Send camera registration data to the Python FastAPI backend.
10. Backend sends registration data to the Go Fabric adapter.
11. Go adapter submits `RegisterCamera` transaction to Fabric.
12. Store the resulting Fabric transaction ID in local metadata.

### Security Notes

- The Ed25519 private key must never be uploaded to the backend, Fabric, dashboard, or storage layer.
- For the prototype, file permissions protect the private key.
- For production, use a hardware secure element or TPM.

## 3. File-Mode Capture Algorithm

### Purpose

Allow development and testing without the Raspberry Pi by treating a sample `.mp4` file as the captured segment.

### Inputs

- Sample video file path.
- `camera.json`.
- Camera private key.
- Owner/investigator public key.

### Outputs

- Encrypted evidence file.
- `evidence.json`.
- Optional local verification result.

### Steps

1. Read the sample video file as bytes.
2. Treat those bytes as the exact plaintext byte stream for the segment.
3. Compute `plaintextHash = SHA-256(plaintextBytes)`.
4. Sign `plaintextHash` using the camera Ed25519 private key.
5. Generate a fresh 256-bit AES key for this evidence item.
6. Generate a fresh AES-GCM nonce.
7. Encrypt `plaintextBytes` using AES-256-GCM.
8. Capture the AES-GCM authentication tag.
9. Wrap the AES key using the registered owner/investigator public key.
10. Write the ciphertext to `storage/evidence/<evidenceId>.enc`.
11. Compute `encryptedFileHash = SHA-256(ciphertextFileBytes)`.
12. Create immutable `evidence.json` with hashes, signature, nonce, auth tag, wrapped key, file URI, and capture timestamp.
13. Store `evidence.json` under `storage/metadata/`.

### Security Notes

- `evidence.json` is write-once. Verification must not mutate it.
- The plaintext hash is valid only for the exact bytes passed into encryption.
- The encrypted file hash is the long-term storage-integrity check.

> **Design note — signature placement.** VidProof signs the plaintext block
> hash before encryption. The encrypted video block is stored as ciphertext
> only, while the device signature is stored in immutable evidence metadata
> (`evidence.json`) and anchored in Hyperledger Fabric. The signature remains
> part of the forensic proof even though it is not embedded inside the
> encrypted video bytes. This keeps the decryption layer independent of the
> authentication layer and allows signature verification without decrypting.

## 4. Pi-Mode Capture Algorithm

### Purpose

Replace file input with real Raspberry Pi camera capture while reusing the same signing, encryption, and metadata logic.

### Inputs

- Raspberry Pi Camera Module v2.
- Camera private key.
- Camera metadata.
- Owner/investigator public key.

### Outputs

- 10-second encrypted video segments.
- One immutable `evidence.json` per segment.
- Capture registration events.

### Steps

1. Start camera service on the Raspberry Pi.
2. Capture footage in 10-second chunks.
3. Serialize the captured segment into the exact byte stream that will be encrypted.
4. Pass the byte stream into the same capture pipeline used by file mode.
5. Compute plaintext hash.
6. Sign plaintext hash with camera private key.
7. Encrypt segment using AES-256-GCM.
8. Store or upload encrypted segment.
9. Write or upload `evidence.json`.
10. Repeat for the next 10-second segment.

### Security Notes

- The capture source changes between file mode and Pi mode; the cryptographic pipeline should not change.
- At 10-second segments, continuous recording creates about 360 capture records per hour per camera.
- Multi-camera scaling must be tested before claiming production readiness.

## 5. SHA-256 Hashing Algorithm

### Purpose

Produce fixed-length integrity identifiers for plaintext input, encrypted files, PRNU references, TSA tokens, and export packages.

### Inputs

- Any byte stream.

### Output

- SHA-256 digest in hex format.

### Steps

1. Initialize SHA-256 digest state.
2. Read input bytes in chunks.
3. Update digest state with each chunk.
4. Return final digest as lowercase hex.

### Usage In VidProof

- `plaintextHash`: hash of exact bytes before signing and encryption.
- `encryptedFileHash`: hash of stored encrypted evidence file.
- `prnuReferenceHash`: hash of PRNU reference fingerprint.
- `tsaTokenHash`: hash of RFC 3161 timestamp response token.
- `exportPackageHash`: hash of final forensic export package.

## 6. Ed25519 Device Signing Algorithm

### Purpose

Prove that an enrolled camera device private key attested to a specific plaintext hash.

### Inputs

- `plaintextHash` as bytes.
- Camera Ed25519 private key.

### Output

- Device signature in base64 format.

### Signing Steps

1. Load camera private key from restricted local storage.
2. Convert `plaintextHash` from hex to bytes.
3. Sign the hash bytes using Ed25519.
4. Encode the signature as base64.
5. Store signature in `evidence.json`.

### Verification Steps

1. Load camera public key from `camera.json` or Fabric camera record.
2. Load `plaintextHash` and `deviceSignature` from `evidence.json`.
3. Convert public key and signature from base64.
4. Verify Ed25519 signature over the hash bytes.
5. Return `deviceSignatureValid = true` if verification succeeds.
6. Return `deviceSignatureValid = false` if verification fails.

### Security Claim

Signature verification proves the footage hash was attested by the enrolled private key. It does not, by itself, prove the physical sensor captured the footage.

## 7. AES-256-GCM Encryption Algorithm

### Purpose

Encrypt video evidence while providing authentication of ciphertext integrity.

### Inputs

- Plaintext video bytes.
- Fresh 256-bit AES key.
- Fresh nonce.
- Optional associated data.

### Outputs

- Ciphertext.
- AES-GCM nonce.
- AES-GCM authentication tag.

### Encryption Steps

1. Generate 32 random bytes for AES-256 key.
2. Generate a fresh nonce suitable for AES-GCM.
3. Initialize AES-GCM cipher.
4. Encrypt plaintext video bytes.
5. Store ciphertext as encrypted evidence file.
6. Store nonce and authentication tag in `evidence.json`.
7. Wrap the AES key for the owner/investigator.

### Decryption Steps

1. Load encrypted evidence file.
2. Load nonce and authentication tag from `evidence.json`.
3. Unwrap AES key using authorized private key.
4. Initialize AES-GCM cipher.
5. Decrypt and authenticate ciphertext.
6. If authentication fails, mark `decryptionValid = false`.
7. If authentication succeeds, compute hash of decrypted plaintext and compare with `plaintextHash`.

### Security Notes

- Never reuse the same AES-GCM nonce with the same key.
- Store nonce and auth tag; both are required for decryption and authentication.
- Decryption is not required to prove provenance, only to view/analyze footage.

## 8. Key Wrapping Process

### Purpose

Protect the per-evidence AES key so only an authorized owner/investigator can decrypt footage.

### Inputs

- Per-evidence AES key.
- Owner/investigator public key.

### Outputs

- Wrapped AES key stored in metadata.

### Steps

1. Generate a fresh AES key for the evidence segment.
2. Load the registered owner/investigator public key.
3. Encrypt or wrap the AES key using the owner/investigator public key.
4. Store the wrapped key in `evidence.json`.
5. Do not store the raw AES key after encryption completes.

### Security Notes

- If the owner/investigator private key is lost, the evidence becomes undecryptable.
- This is an intentional privacy-preserving tradeoff.

## 9. Local Capture-And-Verify Round Trip

### Purpose

Prove the core architecture works before adding Fabric, TSA, PRNU, or Pi hardware.

### Inputs

- Sample video file.
- Enrolled camera key pair.
- Owner/investigator key pair.

### Outputs

- Encrypted evidence.
- `evidence.json`.
- `verification-result.json`.

### Steps

1. Run file-mode capture algorithm.
2. Load `camera.json`.
3. Load `evidence.json`.
4. Recompute SHA-256 hash of encrypted evidence file.
5. Compare recomputed hash with `encryptedFileHash`.
6. Verify Ed25519 device signature using enrolled public key.
7. If decryption is requested, unwrap AES key.
8. Decrypt ciphertext using AES-GCM nonce and auth tag.
9. Hash decrypted plaintext.
10. Compare decrypted plaintext hash with `plaintextHash`.
11. Write a new `verification-result.json`.

### Pass Conditions

- Encrypted file hash matches.
- Device signature is valid.
- AES-GCM authentication succeeds if decryption is attempted.
- Decrypted plaintext hash matches original plaintext hash if decryption is attempted.

## 10. Verification Result Process

### Purpose

Record each verification run without changing the original evidence record.

### Inputs

- `camera.json`.
- `evidence.json`.
- Encrypted evidence file.
- Optional investigator private key for decryption.

### Output

- New `verification-result.json`.

### Steps

1. Generate verification ID.
2. Record verifier identity and verification timestamp.
3. Verify encrypted evidence file hash.
4. Verify device signature.
5. If requested, attempt decryption.
6. If decryption succeeds, hash decrypted plaintext.
7. Compare decrypted plaintext hash with `evidence.json`.
8. Optionally run PRNU if decrypted frames are available.
9. Set `primaryDecision = PASS` only if primary checks pass.
10. Write verification result as a separate append-only record.

### Security Notes

- Never edit `evidence.json` during verification.
- Every verification result can later map to a Fabric `LogVerification` transaction.

## 11. Hyperledger Fabric Logging Process

### Purpose

Anchor camera, evidence, and custody records in an append-only permissioned ledger.

### Components

- Go chaincode inside Fabric peer.
- Go Fabric adapter HTTP service.
- Python FastAPI backend as caller.

### Register Camera Steps

1. Python backend receives camera enrollment record.
2. Backend sends JSON to Go Fabric adapter.
3. Adapter submits `RegisterCamera` transaction.
4. Chaincode stores camera public key, PRNU reference hash, owner public key, and enrollment metadata.
5. Adapter returns transaction ID.
6. Backend stores transaction ID in local metadata.

### Register Evidence Steps

1. Python backend receives `evidence.json`.
2. Backend validates required fields.
3. Backend sends evidence registration request to Go Fabric adapter.
4. Adapter submits `RegisterEvidence` transaction.
5. Chaincode stores evidence hashes, signature, camera ID, TSA reference, and storage URI.
6. Adapter returns transaction ID.

### Log Verification Steps

1. Python backend creates `verification-result.json`.
2. Backend sends verification result to Go Fabric adapter.
3. Adapter submits `LogVerification` transaction.
4. Chaincode appends verification event to custody history.
5. Adapter returns transaction ID.

### Security Notes

- Fabric stores hashes, signatures, metadata, and custody events.
- Fabric must not store raw video or decrypted footage.

## 12. Go Fabric Adapter Process

### Purpose

Keep Fabric SDK usage in Go while allowing the main backend to stay Python.

### Inputs

- JSON requests from Python FastAPI backend.

### Outputs

- JSON responses containing status, Fabric transaction IDs, or ledger query results.

### Steps

1. Receive HTTP request.
2. Validate request body.
3. Connect to Fabric Gateway using configured identity.
4. Select channel and chaincode.
5. Submit or evaluate transaction.
6. Return JSON response to Python backend.

### Planned Endpoints

- `POST /camera/register`.
- `POST /evidence/register`.
- `POST /custody/log`.
- `POST /verification/log`.
- `GET /evidence/{id}/history`.

## 13. RFC 3161 Timestamping Process

### Purpose

Provide independently verifiable proof that a record existed at a specific time.

### Inputs

- Hash of signed capture record, evidence record, or export package.

### Outputs

- Timestamp request file.
- Timestamp response token.
- TSA token hash.
- Verification instructions.

### Timestamp Request Steps

1. Select record to timestamp.
2. Hash record using SHA-256.
3. Create RFC 3161 timestamp request using OpenSSL.
4. Send request to local self-hosted TSA responder.
5. Receive timestamp response token.
6. Hash the timestamp token.
7. Store token reference and token hash in metadata/Fabric.

### Timestamp Verification Steps

1. Load original record hash.
2. Load timestamp response token.
3. Load TSA certificate.
4. Use OpenSSL to verify token signature and message imprint.
5. Return timestamp validity result.

### Security Notes

- The TSA proves existence time of a hash, not the meaning of the evidence.
- Timestamping complements signatures and Fabric custody records.

## 14. Forensic Export Process

### Purpose

Create a self-contained package that a third party can verify independently.

### Inputs

- Encrypted evidence file.
- `camera.json` or Fabric camera record.
- `evidence.json`.
- Verification results.
- Fabric custody history.
- RFC 3161 timestamp tokens.
- Optional investigator private key if decrypted viewing is authorized.

### Outputs

- Export package archive.
- Export manifest.
- Export verification result.
- Fabric `LogExport` transaction.

### Steps

1. Retrieve encrypted evidence file.
2. Retrieve immutable evidence metadata.
3. Retrieve Fabric evidence history.
4. Verify encrypted file hash.
5. Verify device signature.
6. Verify RFC 3161 timestamp token.
7. Verify Fabric custody history.
8. Decrypt only if legally authorized and needed for viewing/analysis.
9. If decrypted, optionally run export-time PRNU comparison.
10. Generate export manifest.
11. Hash export package contents.
12. Request RFC 3161 timestamp for export package hash.
13. Log export event to Fabric.
14. Package encrypted evidence, metadata, signatures, hashes, TSA tokens, certificates, verification results, and instructions.
15. Securely delete temporary plaintext.

### Export Package Contents

- Encrypted video file.
- `camera.json` or camera public-key record.
- `evidence.json`.
- `verification-result.json` records.
- Device signature verification result.
- PRNU result if performed.
- Fabric transaction IDs and custody history.
- RFC 3161 timestamp tokens and TSA certificate.
- Export manifest.
- Verification instructions.

## 15. PRNU Secondary Evaluation Process

### Purpose

Measure whether footage is statistically consistent with the enrolled physical camera sensor.

### Inputs

- PRNU reference fingerprint.
- Decrypted frames from test footage.
- Same-camera and different-camera footage samples.

### Outputs

- PRNU correlation score.
- Same-camera vs different-camera comparison table.
- PRNU limitations report.

### Enrollment Steps

1. Capture reference frames or clips from the enrolled camera.
2. Extract noise residuals from frames.
3. Aggregate residuals into a reference fingerprint.
4. Store fingerprint locally.
5. Hash fingerprint and store hash in metadata/Fabric.

### Comparison Steps

1. Extract frames from test footage.
2. Compute noise residuals from test frames.
3. Compare test residuals with reference fingerprint.
4. Calculate correlation score.
5. Record score in verification result.
6. Report PRNU as secondary evidence only.

### Security Notes

- PRNU is not the primary gate.
- PRNU is affected by compression, resolution, lighting, and camera processing.
- Report actual measured results; do not assume literature accuracy applies.

## 16. Storage Process

### Purpose

Keep encrypted evidence, metadata, and Fabric state clearly separated.

### Storage Types

- Encrypted evidence files: `storage/evidence/` or object storage.
- Application metadata: `storage/metadata/` or metadata database.
- Fabric CouchDB: internal Fabric world state only.

### Steps

1. Write encrypted video file to evidence storage.
2. Write immutable `evidence.json` to metadata storage.
3. Write append-only verification result files to metadata storage.
4. Submit relevant hashes and records to Fabric.
5. Never place raw or decrypted video in Fabric CouchDB.

## 17. Dashboard Process

### Purpose

Provide a simple investigator/admin interface without a separate frontend build system.

### Components

- Streamlit dashboard.
- Python FastAPI backend.

### Planned Views

1. Camera enrollment page.
2. Evidence list page.
3. Evidence detail page.
4. Verification page.
5. Custody history page.
6. Timestamp verification page.
7. Export generation page.
8. PRNU evaluation page.

### Security Notes

- Dashboard must not handle raw private keys directly.
- Sensitive operations should happen in backend/workstation code.

## 18. Failure Handling Processes

### Hash Mismatch

1. Mark encrypted file integrity as failed.
2. Do not proceed to primary pass decision.
3. Write failed verification result.
4. Log failure to Fabric when Fabric is enabled.

### Signature Failure

1. Mark source authentication as failed.
2. Treat evidence as not attested by enrolled key.
3. Write failed verification result.
4. Log failure to Fabric when Fabric is enabled.

### AES-GCM Authentication Failure

1. Mark decryption as failed.
2. Do not trust decrypted bytes.
3. Write failed verification result.
4. Log failure to Fabric when Fabric is enabled.

### TSA Verification Failure

1. Mark timestamp as invalid or unverifiable.
2. Keep hash/signature results separate.
3. Write failed timestamp verification result.
4. Log failure to Fabric when Fabric is enabled.

### PRNU Low Correlation

1. Record PRNU score.
2. Do not automatically reject evidence solely because of PRNU.
3. Flag result as secondary forensic concern.
4. Include score in report.

## 19. First Milestone Algorithm

### Goal

Build the smallest working proof of the architecture before Fabric, TSA, PRNU, or Pi hardware.

### Steps

1. Create file-mode camera enrollment.
2. Generate camera Ed25519 key pair.
3. Generate owner/investigator key pair or placeholder wrapping key.
4. Read sample `.mp4` file.
5. Hash plaintext bytes.
6. Sign plaintext hash.
7. Encrypt bytes with AES-256-GCM.
8. Store encrypted file and immutable `evidence.json`.
9. Verify encrypted file hash.
10. Verify device signature.
11. Decrypt using stored nonce, auth tag, and unwrapped AES key.
12. Verify decrypted plaintext hash matches `evidence.json`.
13. Write `verification-result.json`.

### Completion Criteria

- A sample video can be converted into encrypted evidence.
- The evidence can be verified without Fabric.
- Tampering with encrypted bytes causes verification failure.
- Tampering with signature causes signature verification failure.
- Tampering with AES-GCM tag causes decryption/authentication failure.
