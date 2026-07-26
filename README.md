# VidProof

Prototype implementation for a privacy-preserving and evidence-based IoT surveillance verification system.

The architecture uses cryptographic device signing as the primary source-authentication mechanism and PRNU as a secondary forensic signal. Encrypted evidence is stored as files, metadata is stored separately, and chain-of-custody records are anchored in Hyperledger Fabric with RFC 3161 timestamp support.

## Core Modules

- `edge/` - Raspberry Pi capture, hashing, signing, encryption, and upload workflow.
- `backend/` - Python FastAPI orchestration service for metadata, TSA calls, exports, and dashboard support.
- `forensics/` - Python CLI tools for PRNU, signing verification helpers, hash verification, and export-time analysis.
- `fabric-adapter/` - Go HTTP service wrapping the official Fabric Gateway Go client.
- `chaincode/` - Go Hyperledger Fabric smart contract for camera, evidence, and custody records.
- `dashboard/` - Streamlit dashboard for enrollment, evidence status, verification, and export.
- `infra/fabric/` - Fabric test-network notes and deployment configuration.
- `infra/tsa/` - OpenSSL RFC 3161 TSA configuration and scripts.
- `storage/` - Local prototype storage for encrypted evidence files and metadata.
- `docs/` - Architecture contracts, schemas, and implementation notes.

## Key Docs

- `docs/architecture-contract.md` - high-level technical contract and stack split.
- `docs/schemas.md` - stable local JSON schema contract.
- `docs/algorithms-and-processes.md` - step-by-step algorithms and workflows for the full system.
- `docs/software-development-plan.md` - software build plan and acceptance criteria.
- `docs/hardware-development-plan.md` - hardware build plan and acceptance criteria.
- `docs/python-cli-contract.md` - JSON contract for local Python CLI utilities.

## Authentication Claim

The system proves that footage was attested by an enrolled camera device private key. PRNU is retained as a supplementary forensic signal for physical sensor attribution, measured under actual compression settings, but is not the primary pass/fail gate.

Signing and PRNU make separate claims: signing verifies attestation by the enrolled key, while PRNU reports whether footage is statistically consistent with the enrolled physical sensor.

## First Implementation Milestones

1. Implement camera enrollment and key generation.
2. Implement edge capture signing, hashing, and AES-256-GCM encryption.
3. Store encrypted files and metadata.
4. Build the Python FastAPI backend around the working local workflow.
5. Add the Streamlit dashboard.
6. Bring up the Fabric test network, Go chaincode, and Go adapter.
7. Add local RFC 3161 timestamping.
8. Build forensic export verification and PRNU evaluation.
