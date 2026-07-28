# Software Development Plan

This plan covers VidProof's software implementation: schemas, file-mode enrollment, signing, encryption, verification, FastAPI backend, Streamlit dashboard, Go Fabric adapter, Go chaincode, RFC 3161 timestamping, forensic export, and attack testing.

## Guiding Principles

- Build file mode before Pi mode.
- Prove local cryptographic correctness before adding Fabric.
- Keep `evidence.json` immutable.
- Write a new `verification-result.json` for every verification run.
- Keep signing and PRNU claims separate.
- Keep Python responsible for evidence workflow and forensic logic.
- Keep Go responsible only for Fabric adapter and chaincode.
- Do not store raw or decrypted video in Fabric or metadata storage.
- Treat the video source as swappable input: file-mode and Pi-mode both feed bytes into the same security pipeline.

## Shared Contracts

The software track must preserve these contracts for hardware integration:

- `camera.json` identifies an enrolled camera and its public key.
- `evidence.json` is the immutable capture-time evidence record.
- `verification-result.json` records each verification run separately.
- `custody-record.json` represents actions that will later map to Fabric custody events.
- File-mode and Pi-mode must both produce the same kind of video byte input for signing and encryption.
- The dashboard must not handle private keys directly.
- PRNU results must be labeled secondary and must not replace signature verification.
- System-workaround alignment fixes are tracked in `docs/system-workaround-alignment-fixes.md` and must be treated as implementation requirements.
- Export must run verification before final package generation.
- Failed evidence blocks must be shown with specific reasons and must not be silently included or excluded.

## Phase 0: Environment Setup

### Goal

Make the software project runnable on a development machine.

### Tasks

1. Create Python virtual environment.
2. Install backend dependencies from `backend/requirements.txt`.
3. Install forensic dependencies from `forensics/requirements.txt`.
4. Install dashboard dependencies from `dashboard/requirements.txt`.
5. Confirm Go toolchain is available.
6. Confirm OpenSSL is available.
7. Create local sample folders for input videos, metadata, exports, and keys.

### Deliverables

- Working Python environment.
- Working Go toolchain.
- Local project folders ready for development.

### Acceptance Criteria

- `python3 -m py_compile` passes for Python files.
- `go test ./...` passes in Go modules.
- Backend health endpoint can start locally.
- Dashboard can start locally.

## Phase 1: Stable Local Schemas

### Goal

Freeze local JSON formats before writing capture and verification code.

### Tasks

1. Review `docs/schemas.md`.
2. Confirm required fields for `camera.json`.
3. Confirm required fields for `evidence.json`.
4. Confirm required fields for `verification-result.json`.
5. Confirm required fields for `custody-record.json`.
6. Add sample JSON fixtures under a future `samples/` or `tests/fixtures/` directory.

### Deliverables

- Final first-milestone schema contract.
- Example JSON fixtures.

### Acceptance Criteria

- Capture code can write `evidence.json` without schema changes.
- Verification code can write `verification-result.json` without schema changes.
- AES-GCM `nonce` and `authTag` fields are present.

## Phase 2: File-Mode Enrollment

### Goal

Create the root camera identity without needing Raspberry Pi hardware.

### Tasks

1. Implement an enrollment script in Python.
2. Generate Ed25519 camera key pair.
3. Store camera private key locally with restricted permissions.
4. Export public key as base64.
5. Generate or accept owner/investigator public key.
6. Create `camera.json`.
7. Add basic validation for required camera fields.

### Deliverables

- `camera.json`.
- Camera private key file.
- Camera public key in metadata.

### Acceptance Criteria

- Running enrollment creates a valid `camera.json`.
- Private key is not written into `camera.json`.
- Public key can be used by the verifier.

## Phase 3: File-Mode Capture And Verify Round Trip

### Goal

Build the smallest complete proof that the architecture works.

### Tasks

1. Add a file-mode capture script that accepts a sample `.mp4`.
2. Read the sample video as bytes.
3. Compute SHA-256 plaintext hash.
4. Sign plaintext hash using the camera private key.
5. Generate fresh AES-256-GCM key.
6. Generate fresh AES-GCM nonce.
7. Encrypt video bytes.
8. Store ciphertext under `storage/evidence/`.
9. Store AES-GCM auth tag in `evidence.json`.
10. Store wrapped key placeholder or implement real key wrapping.
11. Compute encrypted file hash.
12. Write immutable `evidence.json`.
13. Add a verifier that loads `camera.json`, `evidence.json`, and encrypted evidence.
14. Verify encrypted file hash.
15. Verify Ed25519 device signature.
16. Decrypt ciphertext when a local authorized key is available.
17. Compare decrypted plaintext hash with `plaintextHash`.
18. Write `verification-result.json`.

### Deliverables

- File-mode capture command.
- File-mode verification command.
- Encrypted evidence output.
- Immutable `evidence.json`.
- Append-only `verification-result.json`.

### Acceptance Criteria

- Untampered sample evidence verifies successfully.
- Modified encrypted bytes cause hash or AES-GCM verification failure.
- Modified signature causes signature verification failure.
- Modified auth tag causes AES-GCM authentication failure.
- Verification does not mutate `evidence.json`.

## Phase 4: Python FastAPI Backend

### Goal

Expose the working local workflow through API endpoints.

### Tasks

1. Add configuration for storage paths and key paths.
2. Add endpoint for camera enrollment.
3. Add endpoint for file-mode evidence registration.
4. Add endpoint to list evidence metadata.
5. Add endpoint to verify one evidence item.
6. Add endpoint to retrieve verification results.
7. Add consistent error responses.
8. Add API support for export preview: selected evidence IDs, verification run, pass/fail results, and user inclusion choices.
9. Add API support for camera status and block counts for the dashboard.

### Deliverables

- FastAPI service with core local endpoints.
- API request/response schemas.

### Acceptance Criteria

- Backend can create or load camera records.
- Backend can trigger file-mode capture.
- Backend can trigger verification.
- Backend returns structured JSON errors.
- Backend can provide export-preview data before package generation.
- Backend can report evidence verification status as `Verified`, `Failed`, or `Not Yet Checked`.

## Phase 5: Streamlit Dashboard

### Goal

Provide a simple operator/investigator interface for demos and testing.

### Tasks

1. Build dashboard page layout.
2. Add camera enrollment view.
3. Add evidence list view.
4. Add evidence detail view.
5. Add verification trigger.
6. Display verification results.
7. Clearly label PRNU as secondary.
8. Display chain-of-custody placeholder until Fabric is integrated.
9. Add camera cards showing status: `Recording`, `Off`, or `Error/Unreachable`.
10. Add total blocks received per camera.
11. Add `Verification Status` badge to evidence list: `Verified`, `Failed`, or `Not Yet Checked`.
12. Add export flow that shows per-block verification results before final package generation.
13. Add include/exclude controls for failed blocks.

### Deliverables

- Streamlit dashboard connected to FastAPI.

### Acceptance Criteria

- User can view enrolled camera metadata.
- User can view evidence records.
- User can run verification from dashboard.
- User can see pass/fail status and reason.
- User can see camera status and block counts.
- User can see failed export blocks and choose whether to include or exclude them.

## Phase 6: Go Chaincode

### Goal

Implement Fabric smart contract records for cameras, evidence, and custody events.

### Tasks

1. Define Go structs matching local schemas.
2. Implement `RegisterCamera`.
3. Implement `RegisterEvidence`.
4. Implement `LogAccess`.
5. Implement `LogVerification`.
6. Implement `LogExport`.
7. Implement `GetEvidenceHistory`.
8. Implement `VerifyEvidenceHash`.
9. Add evidence-linked event indexing so verification, access, export, and failure events can be queried by evidence ID.
10. Add unit tests where possible.

### Deliverables

- Go chaincode package.
- Chaincode functions for core ledger operations.

### Acceptance Criteria

- Chaincode builds.
- Registering a camera stores public key metadata.
- Registering evidence stores hashes/signatures, not raw video.
- Verification logs are append-only events.
- `GetEvidenceHistory(evidenceID)` returns evidence registration, verification, access, export, and failure events related to that evidence ID.

## Phase 7: Fabric Test Network And Go Adapter

### Goal

Connect the Python backend to Fabric through the Go adapter.

### Tasks

1. Bring up Fabric test network.
2. Deploy Go chaincode.
3. Configure Fabric identity for adapter.
4. Implement adapter endpoint `POST /camera/register`.
5. Implement adapter endpoint `POST /evidence/register`.
6. Implement adapter endpoint `POST /verification/log`.
7. Implement adapter endpoint `POST /custody/log`.
8. Implement adapter endpoint `GET /evidence/{id}/history`.
9. Update FastAPI backend to call adapter.
10. Add dashboard display for Fabric transaction IDs and history.
11. Wire backend operations to Fabric: enrollment -> `RegisterCamera`, capture/ingest -> `RegisterEvidence`, verification -> `LogVerification`, export -> `LogExport`.
12. Add failure logging for verification and export failures.

### Deliverables

- Running Fabric test network.
- Go adapter connected to Fabric.
- Python-to-Go HTTP integration.

### Acceptance Criteria

- Camera enrollment creates a Fabric transaction.
- Evidence registration creates a Fabric transaction.
- Verification result creates a Fabric transaction.
- Evidence history can be queried through the backend.
- Export creates a Fabric transaction recording selected blocks, pass/fail status, and inclusion decisions.
- Fabric-unavailable cases are visible to the user and do not silently disappear.

## Phase 8: RFC 3161 Timestamping

### Goal

Add independently verifiable timestamp proofs.

### Tasks

1. Configure local OpenSSL TSA responder.
2. Create timestamp request for signed capture record hash.
3. Store timestamp token reference in metadata.
4. Store TSA token hash in Fabric.
5. Add timestamp verification command.
6. Add timestamp verification result to dashboard.
7. Timestamp verification results when verification is performed.
8. Timestamp export package hash when export is finalized.

### Deliverables

- Local RFC 3161 TSA setup.
- Timestamp request and response files.
- Timestamp verification workflow.

### Acceptance Criteria

- Timestamp token verifies using OpenSSL.
- Timestamp token hash is stored in metadata/Fabric.
- Invalid or missing token is reported clearly.
- Capture, verification, and export timestamp states are visible in the dashboard/export package.

## Phase 9: Forensic Export Package

### Goal

Generate a package that a third party can independently verify.

### Tasks

1. Define export manifest format.
2. Allow selecting one or more evidence blocks.
3. Run verification for each selected block before final packaging.
4. Show per-block verification results before package generation.
5. Let the user include or exclude failed blocks.
6. Collect encrypted evidence files for included blocks.
7. Collect camera metadata or public-key records.
8. Collect immutable evidence metadata.
9. Collect verification results generated during export.
10. Collect Fabric transaction IDs/history.
11. Collect RFC 3161 timestamp tokens and TSA certificate.
12. Add verification instructions.
13. Hash export package.
14. Timestamp export package hash.
15. Log export event and inclusion decisions to Fabric.
16. Create export archive.

### Deliverables

- Export package archive.
- Export manifest.
- Export verification instructions.

### Acceptance Criteria

- Export package contains enough data for independent verification.
- Export process does not require decrypted video by default.
- Temporary plaintext is deleted when decryption is used.
- Export does not silently package unchecked blocks.
- Failed blocks are clearly marked with failure reasons.
- User include/exclude decisions are recorded in the export manifest and logged to Fabric when available.

## Phase 10: Attack Scenario Testing

### Goal

Demonstrate that the prototype detects expected failures.

### Tests

| Test | Expected Result |
|---|---|
| Modify encrypted video bytes | Hash mismatch or AES-GCM failure |
| Modify device signature | Signature verification failure |
| Modify AES-GCM auth tag | Decryption/authentication failure |
| Use evidence not attested by enrolled key | Primary source-authentication failure |
| Change local system timestamp | RFC 3161 timestamp remains authoritative |
| Delete encrypted evidence file | Retrieval failure |
| Edit local metadata after Fabric logging | Fabric/local mismatch detected |
| Forge custody event | Fabric identity/signature rejection |
| PRNU different-camera test | Lower or inconsistent correlation, reported as secondary |
| Export failed block | Failed block is shown with reason and include/exclude choice |
| Export without prior verification | Export flow runs verification before packaging |

### Deliverables

- Test scripts or manual test instructions.
- Test result table.
- Screenshots/logs for report.

### Acceptance Criteria

- Each planned attack has a documented result.
- Failures are reported clearly by backend/dashboard.
- Results can be included in Chapter 4.
- Failed blocks are never silently dropped or silently included.

## Software Build Order

1. Stable local schemas.
2. File-mode enrollment.
3. File-mode capture-and-verify round trip.
4. Python FastAPI backend.
5. Streamlit dashboard.
6. Go chaincode.
7. Fabric test network and Go adapter.
8. RFC 3161 timestamping.
9. Export pre-verification and failed-block handling.
10. Forensic export package.
11. Attack scenario testing.

## Immediate Software Priority

1. Freeze schemas.
2. Implement file-mode enrollment.
3. Implement file-mode capture-and-verify round trip.

Do not start Fabric, TSA, PRNU, or full Pi integration until the local cryptographic round trip works reliably.
