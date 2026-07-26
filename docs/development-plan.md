# Development Plan

This plan describes the practical build sequence for VidProof. The goal is to prove the security-critical workflow first, then add backend orchestration, dashboard support, Fabric logging, timestamping, Pi capture, and PRNU evaluation.

## Guiding Principles

- Build file mode before Pi mode.
- Prove local cryptographic correctness before adding Fabric.
- Keep `evidence.json` immutable.
- Write a new `verification-result.json` for every verification run.
- Keep signing and PRNU claims separate.
- Keep Python responsible for evidence workflow and forensic logic.
- Keep Go responsible only for Fabric adapter and chaincode.
- Do not store raw or decrypted video in Fabric or metadata storage.

## Team Responsibilities

| Role | Primary Responsibility |
|---|---|
| Software Dev A | Python security path: enrollment, signing, encryption, verification, export workflow |
| Software Dev B | FastAPI backend, Streamlit dashboard, Go Fabric adapter, Go chaincode |
| IoT Developer | Raspberry Pi capture, camera setup, system service, real footage collection, PRNU test data |

The responsibilities can overlap, but each module should have one clear owner during implementation.

## Parallel Work Plan

The three developers can work in parallel after the schema and interface contracts are agreed. Milestones 1 to 3 are the main dependency chain; other setup work can happen beside them.

### Shared Start: Contract Freeze

Before major implementation, all developers should agree on:

- `camera.json`.
- `evidence.json`.
- `verification-result.json`.
- `custody-record.json`.
- Folder layout for keys, metadata, evidence, exports, and sample videos.
- FastAPI request/response shapes for enrollment, capture, verification, and evidence listing.
- Go Fabric adapter endpoint names and JSON request/response shapes.

This shared start prevents each developer from building incompatible inputs and outputs.

### Sprint 1: Foundations

| Developer | Work |
|---|---|
| Software Dev A | Freeze schemas, implement file-mode enrollment, generate Ed25519 camera keys, create `camera.json` |
| Software Dev B | Build FastAPI skeleton, Streamlit skeleton, Go Fabric adapter health endpoint, Go chaincode struct placeholders |
| IoT Developer | Set up Raspberry Pi, verify camera module, capture sample 10-second clips, document camera settings |

### Sprint 1 Dependencies

- Dev A owns the schema contract with input from Dev B and the IoT Developer.
- Dev B can build placeholder API/dashboard screens before the crypto workflow is complete.
- IoT Developer can collect footage immediately because file-mode and Pi-mode both produce video bytes.

### Sprint 2: Local Proof Of Architecture

| Developer | Work |
|---|---|
| Software Dev A | Implement file-mode capture-and-verify round trip: hash, sign, AES-256-GCM encrypt, verify, decrypt, write `verification-result.json` |
| Software Dev B | Wrap Dev A's scripts/workflow in FastAPI endpoints, add dashboard evidence list and verification status views |
| IoT Developer | Implement Pi `get_video_segment()` function and make its output match file-mode input expectations |

### Sprint 2 Dependencies

- Dev B should not finalize API responses until Dev A's `evidence.json` and `verification-result.json` outputs are stable.
- IoT work should focus only on producing compatible 10-second video segments, not duplicating crypto logic.

### Sprint 3: Ledger And Export Integration

| Developer | Work |
|---|---|
| Software Dev A | Implement forensic export package and verification instructions |
| Software Dev B | Implement Go chaincode, Fabric test network, Go adapter endpoints, Python-to-Go integration |
| IoT Developer | Integrate real Pi-mode capture with backend upload and collect PRNU reference/test footage |

### Sprint 3 Dependencies

- Fabric integration should begin only after local evidence records verify correctly.
- Export package generation should use existing `evidence.json` and `verification-result.json` records, not define new record shapes.

### Sprint 4: Evaluation And Presentation Readiness

| Developer | Work |
|---|---|
| Software Dev A | Build attack test scripts and export verification tests |
| Software Dev B | Add Fabric history display, timestamp status display, dashboard polish |
| IoT Developer | Run PRNU evaluation under actual Pi compression settings and document same-camera/different-camera scores |

### Sprint 4 Dependencies

- PRNU results must remain secondary and should not block primary signature verification.
- Dashboard should clearly separate hash validation, signature validation, timestamp validation, Fabric history, and PRNU score.

### Work That Should Not Start Too Early

- Do not build full Fabric integration before local file-mode evidence verifies correctly.
- Do not finalize forensic export before `verification-result.json` is stable.
- Do not make PRNU a pass/fail gate.
- Do not build Pi-specific crypto code that differs from file-mode crypto code.
- Do not make dashboard screens handle private keys directly.

## Milestone 0: Repository And Environment Setup

### Goal

Make the project runnable on a development machine.

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

## Milestone 1: Stable Local Schemas

### Goal

Freeze the local JSON formats before writing capture and verification code.

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

## Milestone 2: File-Mode Enrollment

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

## Milestone 3: File-Mode Capture And Verify Round Trip

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

## Milestone 4: Python FastAPI Backend

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

### Deliverables

- FastAPI service with core local endpoints.
- API request/response schemas.

### Acceptance Criteria

- Backend can create or load camera records.
- Backend can trigger file-mode capture.
- Backend can trigger verification.
- Backend returns structured JSON errors.

## Milestone 5: Streamlit Dashboard

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

### Deliverables

- Streamlit dashboard connected to FastAPI.

### Acceptance Criteria

- User can view enrolled camera metadata.
- User can view evidence records.
- User can run verification from dashboard.
- User can see pass/fail status and reason.

## Milestone 6: Go Chaincode

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
9. Add unit tests where possible.

### Deliverables

- Go chaincode package.
- Chaincode functions for core ledger operations.

### Acceptance Criteria

- Chaincode builds.
- Registering a camera stores public key metadata.
- Registering evidence stores hashes/signatures, not raw video.
- Verification logs are append-only events.

## Milestone 7: Fabric Test Network And Go Adapter

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

### Deliverables

- Running Fabric test network.
- Go adapter connected to Fabric.
- Python-to-Go HTTP integration.

### Acceptance Criteria

- Camera enrollment creates a Fabric transaction.
- Evidence registration creates a Fabric transaction.
- Verification result creates a Fabric transaction.
- Evidence history can be queried through the backend.

## Milestone 8: RFC 3161 Timestamping

### Goal

Add independently verifiable timestamp proofs.

### Tasks

1. Configure local OpenSSL TSA responder.
2. Create timestamp request for signed capture record hash.
3. Store timestamp token reference in metadata.
4. Store TSA token hash in Fabric.
5. Add timestamp verification command.
6. Add timestamp verification result to dashboard.

### Deliverables

- Local RFC 3161 TSA setup.
- Timestamp request and response files.
- Timestamp verification workflow.

### Acceptance Criteria

- Timestamp token verifies using OpenSSL.
- Timestamp token hash is stored in metadata/Fabric.
- Invalid or missing token is reported clearly.

## Milestone 9: Forensic Export Package

### Goal

Generate a package that a third party can independently verify.

### Tasks

1. Define export manifest format.
2. Collect encrypted evidence file.
3. Collect camera metadata or public-key record.
4. Collect immutable evidence metadata.
5. Collect verification results.
6. Collect Fabric transaction IDs/history.
7. Collect RFC 3161 timestamp tokens and TSA certificate.
8. Add verification instructions.
9. Hash export package.
10. Timestamp export package hash.
11. Log export event to Fabric.
12. Create export archive.

### Deliverables

- Export package archive.
- Export manifest.
- Export verification instructions.

### Acceptance Criteria

- Export package contains enough data for independent verification.
- Export process does not require decrypted video by default.
- Temporary plaintext is deleted when decryption is used.

## Milestone 10: Raspberry Pi Capture Mode

### Goal

Replace file input with real camera input while keeping the cryptographic pipeline unchanged.

### Tasks

1. Set up Raspberry Pi OS and camera module.
2. Install Python dependencies on Pi.
3. Implement `get_video_segment()` using `picamera2` or selected capture tool.
4. Capture 10-second segments.
5. Feed captured bytes into the existing signing/encryption pipeline.
6. Upload encrypted evidence and metadata to backend.
7. Add systemd service for continuous capture if needed.

### Deliverables

- Pi-mode capture command/service.
- Real encrypted evidence from camera.

### Acceptance Criteria

- Pi captures valid 10-second segments.
- Pi-generated evidence verifies through the same verifier as file-mode evidence.
- Capture source is the only meaningful difference between file mode and Pi mode.

## Milestone 11: PRNU Secondary Evaluation

### Goal

Measure camera-sensor consistency under actual project conditions.

### Tasks

1. Capture reference clips from enrolled camera.
2. Capture test clips from same camera.
3. Capture test clips from different camera if available.
4. Extract PRNU reference fingerprint.
5. Compute same-camera correlation scores.
6. Compute different-camera correlation scores.
7. Compare scores under actual compression settings.
8. Add PRNU results to verification output as secondary evidence.
9. Document limitations.

### Deliverables

- PRNU comparison script.
- PRNU score table.
- PRNU evaluation section for report.

### Acceptance Criteria

- PRNU results are measured, not assumed.
- PRNU is not used as the primary pass/fail gate.
- Report clearly states compression and sensor limitations.

## Milestone 12: Attack Scenario Testing

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

### Deliverables

- Test scripts or manual test instructions.
- Test result table.
- Screenshots/logs for report.

### Acceptance Criteria

- Each planned attack has a documented result.
- Failures are reported clearly by backend/dashboard.
- Results can be included in Chapter 4.

## Milestone 13: Report And Presentation Preparation

### Goal

Ensure the implementation and report tell the same story.

### Tasks

1. Update report technology stack from Node/React to Python/FastAPI/Streamlit/Go.
2. Explain device signing as primary authentication.
3. Explain PRNU as secondary forensic signal.
4. Explain why evidence verification does not require decryption.
5. Explain 10-second segment transaction volume limitation.
6. Include screenshots of dashboard and verification results.
7. Include attack test results.
8. Include limitations and future work.

### Deliverables

- Updated methodology chapter.
- Updated system architecture diagram.
- Evaluation results.
- Presentation demo script.

### Acceptance Criteria

- Report no longer contradicts implementation.
- Examiner-facing claims are precise and defensible.
- Demo can show enrollment, capture, verification, and failure detection.

## Recommended Immediate Work

Start with Milestones 1 to 3:

1. Freeze schemas.
2. Implement file-mode enrollment.
3. Implement file-mode capture-and-verify round trip.

Do not start Fabric, TSA, PRNU, or Pi integration until the local cryptographic round trip works reliably.
