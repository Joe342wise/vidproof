# Hardware Development Plan

This plan covers VidProof's hardware implementation: Raspberry Pi setup, camera module setup, capture testing, 10-second segment generation, upload integration, PRNU data collection, and real-hardware validation.

## Guiding Principles

- Keep hardware capture separate from cryptographic processing.
- Pi-mode must feed the same signing/encryption pipeline as file mode.
- Capture failure must not produce a valid `evidence.json`.
- The Pi should not run Fabric, Node, or dashboard code.
- The camera private key must never leave the Pi once deployed.
- PRNU data collection must record camera settings and compression details.
- A file-mode fallback should always be available for demos.

## Shared Contracts

The hardware track must satisfy these software-facing contracts:

- Produce 10-second video segments as bytes or files.
- Preserve the exact bytes that will be signed and encrypted.
- Provide camera ID and capture metadata needed for `evidence.json`.
- Upload encrypted evidence and metadata to the FastAPI backend.
- Collect PRNU reference/test clips without treating PRNU as the primary gate.

## Phase 0: Hardware Inventory And Preparation

### Goal

Confirm that the required physical components are available and functional.

### Tasks

1. Confirm Raspberry Pi 4 availability.
2. Confirm Raspberry Pi Camera Module v2 availability.
3. Prepare microSD card and power supply.
4. Confirm network connectivity method: Ethernet or Wi-Fi.
5. Prepare a development workstation for SSH access.
6. Label the camera device with its intended camera ID.

### Deliverables

- Hardware inventory checklist.
- Assigned camera ID.
- Ready Raspberry Pi device.

### Acceptance Criteria

- Pi boots successfully.
- Camera module is physically connected.
- Device can be accessed over SSH or local terminal.

## Phase 1: Raspberry Pi OS And Camera Setup

### Goal

Prepare the Pi as a reliable edge capture device.

### Tasks

1. Install Raspberry Pi OS.
2. Update system packages.
3. Enable camera interface if required by the OS version.
4. Install `picamera2` or chosen capture tooling.
5. Install Python runtime and project dependencies needed on the Pi.
6. Confirm system time synchronization or document time-source limitations.
7. Create local directories for keys, captured segments, temporary files, and logs.

### Deliverables

- Configured Raspberry Pi OS.
- Working camera software stack.

### Acceptance Criteria

- Pi can capture a test image.
- Pi can capture a short video clip.
- Captured video can be copied to the development machine.

## Phase 2: Basic 10-Second Capture Test

### Goal

Prove that the Pi can produce the fixed-length video segments expected by the software pipeline.

### Tasks

1. Capture a 10-second video segment.
2. Repeat capture several times to confirm consistency.
3. Record resolution, frame rate, codec, bitrate, and file format.
4. Save sample clips for file-mode testing.
5. Measure approximate file size per 10-second segment.

### Deliverables

- Sample 10-second clips.
- Camera settings note.
- File size estimate for storage planning.

### Acceptance Criteria

- Pi reliably produces playable 10-second clips.
- Clips can be processed by the file-mode software pipeline.
- Camera settings are documented for report reproducibility.

## Phase 3: Pi Capture Function

### Goal

Implement a hardware capture function that can replace file-mode input without changing the cryptographic pipeline.

### Tasks

1. Implement `get_video_segment()` for Pi-mode capture.
2. Ensure it returns or writes the exact bytes to be signed and encrypted.
3. Keep capture logic separate from hashing/signing/encryption logic.
4. Add logging for segment start time, end time, file path, and capture errors.
5. Handle camera capture failure without corrupting evidence metadata.

### Deliverables

- Pi-mode capture function.
- Capture logs.

### Acceptance Criteria

- Pi-mode capture can feed the same software pipeline used by file mode.
- Capture failure does not produce a valid `evidence.json`.
- Capture source is the only meaningful difference between file mode and Pi mode.

## Phase 4: Device Key Storage On Pi

### Goal

Store the camera signing key on the Pi with prototype-level protection.

### Tasks

1. Copy or generate the camera Ed25519 private key on the Pi.
2. Store the private key in a restricted directory.
3. Apply restrictive file permissions.
4. Confirm application process can read the key.
5. Confirm normal users cannot casually read the key.
6. Document that production should use a TPM or secure element.

### Deliverables

- Pi-local camera private key.
- Key storage note.

### Acceptance Criteria

- Pi can sign capture hashes using the local private key.
- Private key is not sent to backend, dashboard, Fabric, or storage layer.
- Prototype limitation is documented.

## Phase 5: Pi-To-Backend Upload

### Goal

Send encrypted evidence and metadata from the Pi to the backend.

### Tasks

1. Configure backend URL on Pi.
2. Capture segment.
3. Run signing and encryption pipeline locally or call local edge script.
4. Upload encrypted evidence file.
5. Upload `evidence.json`.
6. Handle failed uploads by retrying or storing pending records locally.
7. Confirm backend receives and stores the evidence.

### Deliverables

- Pi upload script or service.
- Backend-received Pi evidence.

### Acceptance Criteria

- Pi-generated evidence appears in backend evidence list.
- Pi-generated evidence verifies using the same verifier as file-mode evidence.
- Network failure does not silently discard captured evidence.

## Phase 6: Continuous Capture Service

### Goal

Run capture repeatedly as a prototype surveillance device.

### Tasks

1. Create a loop that captures 10-second segments continuously.
2. Add safe stop behavior.
3. Add local logging.
4. Add optional systemd service.
5. Monitor disk usage.
6. Monitor CPU and memory usage.
7. Confirm transaction volume assumptions for continuous recording.

### Deliverables

- Continuous capture script or service.
- Resource usage notes.

### Acceptance Criteria

- Pi can capture multiple consecutive 10-second segments.
- Each segment produces a separate evidence record.
- Continuous mode does not overwrite evidence or metadata.

## Phase 7: PRNU Data Collection

### Goal

Collect real footage required for PRNU secondary evaluation.

### Tasks

1. Capture reference clips from the enrolled camera.
2. Capture same-camera test clips under similar conditions.
3. Capture same-camera test clips under varied lighting if possible.
4. Capture different-camera clips if another camera is available.
5. Record camera settings for each clip.
6. Transfer clips to the software environment for PRNU processing.

### Deliverables

- PRNU reference footage.
- Same-camera test footage.
- Different-camera test footage where available.
- Camera settings table.

### Acceptance Criteria

- PRNU evaluation has real Pi-generated data.
- Compression settings are known and documented.
- PRNU can be reported as measured evidence, not assumed performance.

## Phase 8: Hardware Validation And Demo Readiness

### Goal

Prepare the hardware setup for presentation and evaluation.

### Tasks

1. Test camera enrollment on or for the Pi.
2. Test Pi capture and upload.
3. Test backend verification of Pi evidence.
4. Test dashboard display of Pi evidence.
5. Prepare a short live demo script.
6. Prepare fallback sample clips in case hardware fails during presentation.

### Deliverables

- Working Pi demo path.
- Fallback file-mode demo path.
- Hardware limitations note.

### Acceptance Criteria

- Demo can show real Pi evidence if hardware is available.
- Demo can fall back to file-mode evidence if hardware fails.
- The report clearly distinguishes software verification from hardware capture.

## Hardware Build Order

1. Hardware inventory and preparation.
2. Raspberry Pi OS and camera setup.
3. Basic 10-second capture test.
4. Pi capture function.
5. Device key storage on Pi.
6. Pi-to-backend upload.
7. Continuous capture service.
8. PRNU data collection.
9. Hardware validation and demo readiness.

## Integration With Software

- Copy hardware sample clips into the software environment and process them through file mode first.
- Pi-mode must call the same signing, hashing, encryption, and metadata code used by file mode.
- The backend should not care whether evidence came from file mode or Pi mode.
- Fabric integration should happen only after local software verification works.
- PRNU should be evaluated with real Pi footage after the hardware capture path is stable.

## Immediate Hardware Priority

1. Confirm Raspberry Pi and Camera Module v2 availability.
2. Install and configure Raspberry Pi OS.
3. Capture basic 10-second clips.
4. Record camera settings and copy clips to the software environment.
