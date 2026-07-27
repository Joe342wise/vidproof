# Raspberry Pi Integration

This document explains how a Raspberry Pi camera node fits into the VidProof system — the enrollment flow, the per-capture signing pipeline, the network transfer options, and what the cryptographic chain guarantees against each attacker position.

---

## Core Principle

The Pi is not a dumb camera that streams video to a server. It is a **signing device** — the only machine that ever holds the Ed25519 private key and touches plaintext video. Everything the backend, Fabric, and dashboard see is already hashed, signed, and encrypted before it leaves the Pi.

This is what gives the system its forensic property: even a fully compromised backend cannot forge evidence from a legitimate camera.

---

## Enrollment (one-time per camera)

```
Pi                                        Backend / Operator
────────────────────────────────────      ─────────────────────────────────
1. Generate Ed25519 keypair
   private.pem  → stays on Pi (0600)
   public key   ───────────────────────→  stored in camera.json
                                          registered to Fabric via adapter
```

The operator runs `forensics/enroll.py` (or the dashboard Cameras page) with the camera's **public key** as input. The private key is generated on the Pi, stored at `storage/keys/<cameraId>.private.pem` with mode `0600`, and never transmitted anywhere.

The enrolled `camera.json` record (containing the public key) is what verifiers use later to check the device signature.

---

## Per-Capture Signing Pipeline

Every time the Pi records a segment, it runs through this pipeline locally before sending anything to the backend:

```
Pi                                              Backend / Storage
──────────────────────────────────────          ──────────────────────────────
1. picamera2 records a video segment
   → plaintext_bytes  (never leaves Pi)

2. plaintextHash = SHA-256(plaintext)

3. deviceSignature = Ed25519.sign(
       plaintextHash,
       private.pem)
   → signing happens on-device
   → private key never leaves

4. aes_key, ciphertext, nonce, authTag
       = AES-256-GCM.encrypt(plaintext)
   → plaintext discarded after this step

5. wrappedKey = X25519 + HKDF-SHA256 + AES-KW(
       aes_key,
       owner_pubkey_b64)
   → aes_key discarded after this step

6. Write <evidenceId>.enc  ──────────────────→  storage/evidence/
7. Write evidence.json     ──────────────────→  storage/metadata/evidence/
   (chmod 0444 — immutable on arrival)
```

Steps 1–5 are entirely local on the Pi. The backend receives only the **ciphertext file** and the **evidence record**. It has no way to read the video or forge the signature.

---

## `edge/capture.py` vs `forensics/capture.py`

The only difference between Pi mode and file mode is how `plaintext_bytes` is obtained. The entire cryptographic pipeline that follows is identical — same `crypto_core.py` functions, same `evidence.json` schema, same output.

```python
# forensics/capture.py — file mode (used in development and testing)
def get_video_segment_file_mode(path: Path) -> bytes:
    return path.read_bytes()

# edge/capture.py — Pi mode
def get_video_segment_pi_mode(duration: int = 10) -> bytes:
    from picamera2 import Picamera2
    from picamera2.encoders import H264Encoder
    import io
    cam = Picamera2()
    cam.configure(cam.create_video_configuration())
    buf = io.BytesIO()
    cam.start_and_record_video(buf, duration=duration, encoder=H264Encoder())
    return buf.getvalue()
```

After obtaining the bytes, `run_capture()` from `forensics/crypto_core.py` is called identically in both modes.

This is a deliberate design constraint (from `CLAUDE.md`): **file-mode and Pi-mode must use identical cryptographic code; only the video source changes.** This means every tamper test and attack scenario validated in file mode is also valid for Pi mode.

---

## Network Transfer Options

Because the Pi runs the full crypto pipeline locally, it produces two artifacts:

- `<evidenceId>.enc` — AES-256-GCM ciphertext
- `evidence.json` — hashes, signature, timestamps (immutable)

There are two ways to get these to the backend.

### Option A — HTTP Push (recommended for production)

The Pi POSTs pre-signed, pre-encrypted evidence directly to the backend. This requires a dedicated endpoint that accepts already-processed evidence rather than raw video:

```
Pi                                  Backend
──────────────────────────          ─────────────────────────────────
POST /evidence/ingest
  multipart body:
    evidence_json   (the record)
    enc_file        (.enc bytes)
                                    Validate schema
                                    Write to storage (chmod 0444)
                                    Register to Fabric
                                    Stamp with TSA (optional)
```

This is distinct from `POST /evidence/capture`, which accepts raw video and runs the crypto server-side. The ingest endpoint is for pre-signed evidence from an edge device.

### Option B — Shared Storage / rsync (simpler for prototype)

```
Pi ─── rsync ──→ storage/ on VPS
```

The Pi rsyncs `storage/evidence/` and `storage/metadata/evidence/` directly to the VPS after each capture. The backend reads from the filesystem as normal. No new endpoint needed.

This is the fastest approach for an academic prototype and is what the development plan uses until the full edge integration sprint.

---

## What the Cryptographic Chain Guarantees

| Attacker position | What they can obtain | Can they forge evidence? |
|---|---|---|
| Intercepts network traffic | Ciphertext + evidence.json | No — no private key, no AES key |
| Fully compromises the backend | Ciphertext + evidence.json + wrapped key | No — cannot unwrap key without owner X25519 private key; cannot forge signature without camera private key |
| Replays an old `.enc` file | The same ciphertext from a prior capture | Detected — `evidenceId` and `capturedAt` are part of the signed record; a new evidence.json with those fields changed will fail signature verification |
| Replaces `.enc` with different video | New ciphertext | Detected — `encryptedFileHash` in evidence.json will not match |
| Replaces `evidence.json` with tampered record | Modified metadata | Detected — `deviceSignature` will not verify against the enrolled public key |
| Physically steals the Pi | Private key + future captures | **This is the only break.** Physical security of the Pi is the root of trust. |

The last row is why enrollment matters: each camera has its own keypair. Compromising one Pi does not affect evidence from other enrolled cameras.

---

## What Is Left to Implement

The build plan (Sprint 6) specifies:

1. **Extract `crypto_core.py`** into a top-level `vidproof_crypto/` package installable with `pip install -e .` so both `forensics/` and `edge/` import from the same source without path manipulation.

2. **`edge/capture.py`** — implement `get_video_segment_pi_mode()` using `picamera2`; call `run_capture()` from `vidproof_crypto`.

3. **`POST /evidence/ingest` backend endpoint** — accepts pre-signed, pre-encrypted evidence (evidence.json + .enc file); writes to storage and triggers Fabric registration. This is the HTTP push path for the Pi.

4. **Push script on the Pi** — runs after each capture, POSTs to `/evidence/ingest`, logs success or falls back to local queue if the backend is unreachable.

---

## Demo Strategy for Project Defense

For the defense, run in **file mode** and explain the Pi substitution verbally:

1. Show `forensics/capture.py` and `edge/capture.py` side by side — the only difference is the first four lines that obtain `plaintext_bytes`.
2. Run the full capture → verify → attack demo pipeline using a sample `.mp4`.
3. Point to `get_video_segment_pi_mode()` and explain that on a real Pi, `picamera2` fills the same `bytes` variable, and the cryptographic pipeline from that point is byte-for-byte identical.
4. Emphasize that the private key never appears in any network request, log, or database record — show the attack demo page as proof that tampering with the outputs is always detected.

This is a defensible position: the cryptographic design is the contribution, and the `picamera2` integration is a two-function swap that does not affect the security properties.
