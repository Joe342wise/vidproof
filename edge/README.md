# Edge Capture Module

Runs on the Raspberry Pi camera device.

Responsibilities:

- Generate or load the enrolled Ed25519 private key.
- Capture video in fixed segments.
- Hash the exact plaintext byte stream that will be encrypted.
- Sign that hash with the device private key.
- Encrypt the segment using AES-256-GCM with a fresh key.
- Wrap the segment key with the registered owner public key.
- Send metadata to the backend and store/upload the encrypted segment.

The private signing key must not leave the device. For production, move it into a hardware secure element or TPM.
