# Go Hyperledger Fabric Chaincode

Use Go for VidProof chaincode so the Fabric adapter and smart contract share one Fabric-specific language.

Planned smart contract functions:

- `RegisterCamera`
- `RegisterEvidence`
- `LogAccess`
- `LogVerification`
- `LogExport`
- `GetEvidenceHistory`
- `VerifyEvidenceHash`

The chaincode should store metadata, hashes, signatures, public keys, TSA token hashes, and custody records. It must never store raw or decrypted video evidence.
