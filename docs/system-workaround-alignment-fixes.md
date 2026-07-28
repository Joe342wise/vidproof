# System Workaround Alignment Fixes

This document compares the current VidProof implementation against `../System-Work-around.md` and defines the fixes required to bring the implementation fully in line with the intended system workflow.

## Summary Verdict

The current implementation is aligned with the core cryptographic foundation:

- Camera/device identity is based on Ed25519 signing keys.
- Footage bytes are hashed before encryption.
- The plaintext hash is signed before encryption.
- Evidence is encrypted with AES-256-GCM.
- Encrypted evidence is stored separately from metadata.
- Verification checks encrypted-file hash and device signature.
- Decryption is optional and only needed for viewing or deeper analysis.
- PRNU remains secondary and is not a pass/fail gate.

The implementation is not yet fully aligned with the complete operating workflow in `System-Work-around.md`. The main missing work is around pairing, storage semantics, Fabric logging coverage, timestamping, export-time verification, failed-block handling, and UI behavior.

## Alignment Already Achieved

| Workaround Requirement | Current Status |
|---|---|
| Camera generates signing key pair | Implemented through enrollment scripts/services. |
| Private key remains local to device/prototype environment | Implemented at prototype level with local private-key files. |
| Camera signs footage block/hash before encryption | Implemented: plaintext bytes are hashed and the hash is signed before AES-GCM encryption. |
| AES-256-GCM encryption | Implemented in file-mode and edge capture pipelines. |
| Encrypted evidence stored separately from metadata | Implemented through `storage/evidence/` and `storage/metadata/`. |
| Verification checks encrypted file hash | Implemented in `forensics/verify.py`. |
| Verification checks camera signature | Implemented in `forensics/verify.py`. |
| Verification result records specific check outcomes | Implemented through `verification-result.json`. |
| Export package includes encrypted evidence and verification materials | Partly implemented through `forensics/export_package.py`. |

## Fix 1: Pairing Scope And Enrollment Flow

### Gap

`System-Work-around.md` expects camera-to-owner pairing using QR code or Bluetooth as the CaCTUs trust-establishment layer. Current VidProof enrollment generates/registers keys but does not implement QR or Bluetooth pairing.

### Required Decision

For the prototype, treat QR/Bluetooth pairing as an optional extension unless the presentation requires a live pairing demonstration.

### Required Implementation Fix

Add one of these paths:

1. **Prototype path:** document manual trusted pairing, where the owner public key is provided during enrollment and the camera public key is displayed/exported for verification.
2. **QR path:** generate a QR code containing camera ID and camera public key; owner device scans it and registers trust.
3. **Bluetooth path:** exchange camera public key and owner public key over a local Bluetooth pairing session.

### Acceptance Criteria

- The enrollment process clearly establishes how the owner trusts the camera public key.
- The camera private key never leaves the camera device.
- The report clearly states whether QR/Bluetooth is implemented or simulated.

## Fix 2: Storage Semantics: CouchDB Versus Prototype File Storage

### Gap

`System-Work-around.md` says encrypted signed blocks are uploaded to CouchDB. The current implementation stores encrypted evidence as files and metadata as JSON. Fabric may use CouchDB internally, but application evidence is not stored in CouchDB.

### Required Decision

Use filesystem/object storage for the prototype unless CouchDB application storage is explicitly required by the supervisor.

### Required Implementation Fix

Choose one of these:

1. **Prototype path:** keep filesystem/object storage and update report wording to say CouchDB is represented by local evidence storage in the prototype.
2. **CouchDB path:** add an application-level CouchDB storage adapter for encrypted `.enc` blobs and metadata references.

### Acceptance Criteria

- The report no longer conflates Fabric CouchDB world state with application evidence storage.
- Encrypted evidence remains unreadable to the storage layer.
- Verification uses `encryptedFileHash` regardless of whether storage is filesystem, object storage, or CouchDB.

## Fix 3: Signature Placement Wording

### Gap

`System-Work-around.md` says the signed block is encrypted. Current implementation encrypts the video bytes and stores the signature in `evidence.json` rather than embedding the signature inside the encrypted file.

### Required Decision

Keep the current design because it is cleaner for verification and export.

### Required Documentation Fix

Use this wording:

> VidProof signs the plaintext block hash before encryption. The encrypted video block is stored as ciphertext, while the device signature is stored in immutable evidence metadata and anchored in Fabric. The signature remains part of the forensic proof even though it is not embedded inside the encrypted video bytes.

### Acceptance Criteria

- Documentation does not imply that signature bytes are inside the encrypted video file.
- Export package includes both encrypted video and signature-bearing metadata.

## Fix 4: Fabric Logging Across The Full Workflow

### Gap

Fabric support exists, but the main workflow does not consistently log every required event.

Current gaps include:

- Camera enrollment does not consistently submit `RegisterCamera`.
- File-mode capture does not consistently submit `RegisterEvidence`.
- Verification does not consistently submit `LogVerification`.
- Export does not consistently submit `LogExport`.
- Failure events are not consistently logged.

### Required Implementation Fix

Wire Fabric logging into these backend operations:

1. Camera enrollment -> `RegisterCamera`.
2. Evidence capture/ingest -> `RegisterEvidence`.
3. Evidence verification -> `LogVerification`.
4. Export request -> `LogExport`.
5. Verification/export failures -> custody or verification failure event.

### Acceptance Criteria

- Every evidence-related action has a local result and a Fabric transaction when Fabric is available.
- If Fabric is unavailable, the system records the local operation and clearly marks Fabric logging as unavailable/pending.
- The dashboard displays Fabric transaction IDs where available.

## Fix 5: Evidence-Linked History In Chaincode

### Gap

Current Fabric history retrieval focuses on the evidence asset key. Verification, access, and export events are stored under separate keys, so `GetEvidenceHistory(evidenceID)` may not return the full chain of custody for that evidence item.

### Required Implementation Fix

Add an evidence-linked event index in chaincode.

Recommended approach:

- Store evidence asset under `ev:<evidenceID>`.
- Store verification event under `ver:<verificationID>`.
- Store custody/export event under `custody:<txID>`.
- Also append an index record under a composite key such as `evhist:<evidenceID>:<txID>`.

`GetEvidenceHistory(evidenceID)` should return:

- Evidence registration event.
- Verification events.
- Access events.
- Export events.
- Failure events.

### Acceptance Criteria

- Querying evidence history returns all ledger events related to the evidence ID.
- Verification and export events are visible in the chain-of-custody UI.
- History output can be included in forensic export packages.

## Fix 6: RFC 3161 Timestamp Integration

### Gap

Timestamp scripts and export packaging support exist, but timestamping is not fully integrated into the capture, verification, and export workflows.

### Required Implementation Fix

Timestamp these records:

1. Signed capture record or evidence record at capture/ingest time.
2. Verification result when verification is performed.
3. Export package hash when export is finalized.

Store:

- Timestamp token file.
- TSA token hash.
- TSA certificate or verification reference.
- Timestamp verification result.

### Acceptance Criteria

- Timestamp token is generated during capture/ingest or explicitly marked unavailable.
- Timestamp verification is shown in the UI.
- Export package includes timestamp token and verification instructions when available.

## Fix 7: Export-Time Verification Before Packaging

### Gap

`System-Work-around.md` requires export to run full verification before the final package is generated. Current export can package existing materials but does not force a fresh verification step before finalizing.

### Required Implementation Fix

Modify export flow:

1. User selects one or more evidence blocks.
2. System runs verification on each selected block.
3. System shows per-block result before package generation.
4. User confirms whether to proceed.
5. System generates export package.
6. System logs export decision to Fabric.

### Acceptance Criteria

- Export does not silently package unchecked blocks.
- User sees hash, decryption, signature, timestamp, and Fabric status before final package creation.
- Export package includes the verification result generated during that export flow.

## Fix 8: Failed Block Handling

### Gap

`System-Work-around.md` requires failed blocks to be visible, explained, optionally included, and logged. Current verification records failure reasons, but export UI does not yet provide include/exclude handling for failed blocks.

### Required Implementation Fix

Add export result screen with per-block choices:

- Include passed blocks by default.
- Mark failed blocks clearly.
- Show failure reasons: hash mismatch, invalid signature, decryption failure, invalid timestamp, Fabric unavailable, or PRNU warning.
- Allow user to include or exclude failed blocks.
- Log final inclusion decision to Fabric.

### Acceptance Criteria

- Failed blocks are never silently dropped.
- Failed blocks are never silently included.
- Failure reason is visible in UI and export manifest.
- User inclusion/exclusion decision is logged.

## Fix 9: UI Alignment With Workaround

### Gap

The dashboard has core pages, but the workaround requires specific dashboard behavior.

### Required Implementation Fix

Add or refine dashboard sections:

1. Main dashboard with camera cards.
2. Each camera card shows status: `Recording`, `Off`, `Error/Unreachable`.
3. Each camera card shows total blocks received.
4. Evidence list includes `Verification Status`: `Verified`, `Failed`, `Not Yet Checked`.
5. Selecting evidence enables export.
6. Export screen shows verification result before final packaging.

### Acceptance Criteria

- UI exposes the same states described in `System-Work-around.md`.
- Most blocks remain `Not Yet Checked` until verification/export occurs.
- User can see why a block failed before final export.

## Fix 10: Multi-Block Export Support

### Gap

`System-Work-around.md` expects export of one or more blocks. Current export is centered on one evidence ID.

### Required Implementation Fix

Add multi-evidence export support:

1. Allow selecting multiple evidence IDs.
2. Run verification for each selected evidence block.
3. Generate one package containing multiple blocks and their metadata.
4. Record per-block pass/fail status.
5. Log export event with selected block list and inclusion decisions.

### Acceptance Criteria

- Export can handle one or many blocks.
- Each block has its own verification result.
- Export manifest clearly identifies all included and excluded blocks.

## Recommended Implementation Order

1. Wire Fabric logging into enrollment, capture/ingest, verification, and export.
2. Add evidence-linked Fabric history indexing.
3. Integrate RFC 3161 timestamp generation and verification.
4. Modify export to run verification before packaging.
5. Add failed-block include/exclude behavior.
6. Add UI status columns and camera cards.
7. Decide and document CouchDB versus filesystem/object storage.
8. Add QR/Bluetooth pairing only if required for demo or report scope.
9. Add multi-block export support after single-block export flow is correct.

## Final Acceptance Criteria

VidProof is fully aligned with `System-Work-around.md` when:

- Camera trust establishment is implemented or explicitly documented as prototype manual pairing.
- Camera key pair generation and private-key protection are clear.
- Each captured block is signed before encryption.
- Each encrypted block is stored unreadable to the storage layer.
- Each evidence record is logged to Fabric.
- Each verification/export event is logged to Fabric.
- RFC 3161 timestamp tokens are generated and verified.
- Export runs verification before packaging.
- Failed blocks are visible, explained, selectable, and logged.
- Export package includes video, signature, hash, ledger record, timestamp token, and verification instructions.
- Third parties can independently verify source, integrity, and timing from the export package.
