# Architecture Contract

## Primary Authentication

Each enrolled camera has an Ed25519 key pair generated during enrollment. The private key remains on the camera device. The public key is registered with the system and anchored in Fabric.

For each captured segment, the device signs the SHA-256 hash of the exact plaintext byte stream that is about to be encrypted. The signed hash is the primary source-authentication record.

The prototype uses 10-second signed segments. This creates about 360 Fabric transactions per hour per continuously recording camera and is intended for a single-camera test network.

## Encryption

Video segments are encrypted with AES-256-GCM using a fresh per-segment key. The per-segment key is wrapped with the registered owner or investigator public key.

The encrypted file hash is the main long-term storage-integrity check. Plaintext hashes are capture-time validation records and must be interpreted only against the exact capture bytes that entered encryption.

## PRNU Scope

PRNU is secondary. It is not a hard gate for evidence acceptance. It provides a measured forensic signal for physical sensor attribution and must be reported with same-camera and different-camera scores under the actual compression pipeline.

Do not merge PRNU and signing claims. Signing catches footage not attested by the enrolled device key. PRNU reports whether footage is statistically consistent with the enrolled sensor.

## Plaintext Exposure

Plaintext exists on the Pi before encryption because capture requires it. Export-time decryption is only required when an authorized investigator needs to view or further analyze footage. Provenance verification does not require decryption.

## Storage Split

Application evidence storage contains encrypted video files and application metadata. Fabric CouchDB is internal to Hyperledger Fabric and must not store raw evidence files.
