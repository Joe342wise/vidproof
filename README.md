# VidProof

Prototype implementation for a privacy-preserving and evidence-based IoT surveillance verification system.

The architecture uses cryptographic device signing as the primary source-authentication mechanism and PRNU as a secondary forensic signal. Encrypted evidence is stored as files, metadata is stored separately, and chain-of-custody records are anchored in Hyperledger Fabric with RFC 3161 timestamp support.

## Core Modules

- `edge/` - Raspberry Pi capture, hashing, signing, encryption, and upload workflow.
- `backend/` - API/orchestration service for metadata, Fabric submissions, TSA calls, exports, and dashboard support.
- `forensics/` - Python CLI tools for PRNU, signing verification helpers, hash verification, and export-time analysis.
- `chaincode/` - Hyperledger Fabric smart contract for camera, evidence, and custody records.
- `frontend/` - React dashboard for enrollment, evidence status, verification, and export.
- `infra/fabric/` - Fabric test-network notes and deployment configuration.
- `infra/tsa/` - OpenSSL RFC 3161 TSA configuration and scripts.
- `storage/` - Local prototype storage for encrypted evidence files and metadata.
- `docs/` - Architecture contracts, schemas, and implementation notes.

## Authentication Claim

The system proves that footage was attested by an enrolled camera device private key. PRNU is retained as a supplementary forensic signal for physical sensor attribution, measured under actual compression settings, but is not the primary pass/fail gate.

Signing and PRNU make separate claims: signing verifies attestation by the enrolled key, while PRNU reports whether footage is statistically consistent with the enrolled physical sensor.

## First Implementation Milestones

1. Implement camera enrollment and key generation.
2. Implement edge capture signing, hashing, and AES-256-GCM encryption.
3. Store encrypted files and metadata.
4. Bring up the Fabric test network and chaincode.
5. Add local RFC 3161 timestamping.
6. Build forensic export verification.
7. Add dashboard and PRNU evaluation.
