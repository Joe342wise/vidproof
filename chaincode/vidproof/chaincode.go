package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract implements the VidProof chaincode.
type SmartContract struct {
	contractapi.Contract
}

// CameraRecord mirrors the local camera.json schema (all fields stored on-chain).
type CameraRecord struct {
	CameraID            string `json:"cameraId"`
	DeviceSerial        string `json:"deviceSerial"`
	PublicKeyEd25519    string `json:"publicKeyEd25519"`
	PRNUReferenceHash   string `json:"prnuReferenceHash"`
	OwnerPublicKey      string `json:"ownerPublicKey"`
	AuthorizationPolicy string `json:"authorizationPolicy"`
	EnrollmentTimestamp string `json:"enrollmentTimestamp"`
	OperatorID          string `json:"operatorId"`
}

// FabricEvidenceRecord stores evidence metadata on-chain.
// nonce, authTag, and wrappedKey are intentionally excluded — decryption
// material must never leave the local operator system.
type FabricEvidenceRecord struct {
	EvidenceID        string  `json:"evidenceId"`
	CameraID          string  `json:"cameraId"`
	ObjectURI         string  `json:"objectUri"`
	EncryptedFileHash string  `json:"encryptedFileHash"`
	PlaintextHash     string  `json:"plaintextHash"`
	EncryptionAlgo    string  `json:"encryptionAlgo"`
	CaptureTimestamp  string  `json:"captureTimestamp"`
	DeviceSignature   string  `json:"deviceSignature"`
	PRNUCaptureScore  float64 `json:"prnuCaptureScore"`
	TSATokenRef       string  `json:"tsaTokenRef"`
}

// VerificationEvent is written for each verification run.
type VerificationEvent struct {
	VerificationID         string   `json:"verificationId"`
	EvidenceID             string   `json:"evidenceId"`
	VerifiedAt             string   `json:"verifiedAt"`
	VerifierID             string   `json:"verifierId"`
	EncryptedFileHashValid bool     `json:"encryptedFileHashValid"`
	DeviceSignatureValid   bool     `json:"deviceSignatureValid"`
	PrimaryDecision        string   `json:"primaryDecision"`
	PRNUScore              *float64 `json:"prnuScore,omitempty"`
}

// CustodyEvent records access or export actions.
type CustodyEvent struct {
	EventType  string `json:"eventType"` // "access" or "export"
	EvidenceID string `json:"evidenceId"`
	ActorID    string `json:"actorId"`
	Timestamp  string `json:"timestamp"`
	Notes      string `json:"notes,omitempty"`
}

// RegisterCamera writes a camera record to the ledger.
// Returns an error if cameraID is empty or already registered.
func (s *SmartContract) RegisterCamera(ctx contractapi.TransactionContextInterface, cameraID, cameraJSON string) error {
	if cameraID == "" {
		return fmt.Errorf("chaincode: RegisterCamera: cameraId must not be empty")
	}
	existing, err := ctx.GetStub().GetState("cam:" + cameraID)
	if err != nil {
		return fmt.Errorf("chaincode: RegisterCamera: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("chaincode: RegisterCamera: camera %s already registered", cameraID)
	}
	var rec CameraRecord
	if err := json.Unmarshal([]byte(cameraJSON), &rec); err != nil {
		return fmt.Errorf("chaincode: RegisterCamera: invalid JSON: %w", err)
	}
	return ctx.GetStub().PutState("cam:"+cameraID, []byte(cameraJSON))
}

// RegisterEvidence writes an evidence record to the ledger.
// Returns an error if evidenceID is empty or already registered.
func (s *SmartContract) RegisterEvidence(ctx contractapi.TransactionContextInterface, evidenceID, evidenceJSON string) error {
	if evidenceID == "" {
		return fmt.Errorf("chaincode: RegisterEvidence: evidenceId must not be empty")
	}
	existing, err := ctx.GetStub().GetState("ev:" + evidenceID)
	if err != nil {
		return fmt.Errorf("chaincode: RegisterEvidence: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("chaincode: RegisterEvidence: evidence %s already registered", evidenceID)
	}
	var rec FabricEvidenceRecord
	if err := json.Unmarshal([]byte(evidenceJSON), &rec); err != nil {
		return fmt.Errorf("chaincode: RegisterEvidence: invalid JSON: %w", err)
	}
	return ctx.GetStub().PutState("ev:"+evidenceID, []byte(evidenceJSON))
}

// LogVerification appends a verification result to the ledger keyed by verificationID.
func (s *SmartContract) LogVerification(ctx contractapi.TransactionContextInterface, verificationID, verificationJSON string) error {
	if verificationID == "" {
		return fmt.Errorf("chaincode: LogVerification: verificationId must not be empty")
	}
	var ev VerificationEvent
	if err := json.Unmarshal([]byte(verificationJSON), &ev); err != nil {
		return fmt.Errorf("chaincode: LogVerification: invalid JSON: %w", err)
	}
	return ctx.GetStub().PutState("ver:"+verificationID, []byte(verificationJSON))
}

// LogAccess records a custody access event; the Fabric transaction ID is used as key.
func (s *SmartContract) LogAccess(ctx contractapi.TransactionContextInterface, custodyJSON string) error {
	var ev CustodyEvent
	if err := json.Unmarshal([]byte(custodyJSON), &ev); err != nil {
		return fmt.Errorf("chaincode: LogAccess: invalid JSON: %w", err)
	}
	txID := ctx.GetStub().GetTxID()
	return ctx.GetStub().PutState("custody:access:"+txID, []byte(custodyJSON))
}

// LogExport records a custody export event; the Fabric transaction ID is used as key.
func (s *SmartContract) LogExport(ctx contractapi.TransactionContextInterface, custodyJSON string) error {
	var ev CustodyEvent
	if err := json.Unmarshal([]byte(custodyJSON), &ev); err != nil {
		return fmt.Errorf("chaincode: LogExport: invalid JSON: %w", err)
	}
	txID := ctx.GetStub().GetTxID()
	return ctx.GetStub().PutState("custody:export:"+txID, []byte(custodyJSON))
}

// GetEvidenceHistory returns the full ledger history for an evidence key as a JSON array.
func (s *SmartContract) GetEvidenceHistory(ctx contractapi.TransactionContextInterface, evidenceID string) (string, error) {
	if evidenceID == "" {
		return "", fmt.Errorf("chaincode: GetEvidenceHistory: evidenceId must not be empty")
	}
	iter, err := ctx.GetStub().GetHistoryForKey("ev:" + evidenceID)
	if err != nil {
		return "", fmt.Errorf("chaincode: GetEvidenceHistory: %w", err)
	}
	defer iter.Close()

	type historyEntry struct {
		TxID      string          `json:"txId"`
		Timestamp string          `json:"timestamp"`
		IsDelete  bool            `json:"isDelete"`
		Value     json.RawMessage `json:"value,omitempty"`
	}

	var entries []historyEntry
	for iter.HasNext() {
		mod, err := iter.Next()
		if err != nil {
			return "", fmt.Errorf("chaincode: GetEvidenceHistory: iterate: %w", err)
		}
		entry := historyEntry{
			TxID:     mod.TxId,
			IsDelete: mod.IsDelete,
		}
		if mod.Timestamp != nil {
			entry.Timestamp = mod.Timestamp.AsTime().UTC().Format("2006-01-02T15:04:05Z")
		}
		if !mod.IsDelete && len(mod.Value) > 0 {
			entry.Value = json.RawMessage(mod.Value)
		}
		entries = append(entries, entry)
	}

	out, err := json.Marshal(entries)
	if err != nil {
		return "", fmt.Errorf("chaincode: GetEvidenceHistory: marshal: %w", err)
	}
	return string(out), nil
}

// VerifyEvidenceHash checks the stored encryptedFileHash against hashHex using a
// constant-time comparison to avoid timing side-channels.
func (s *SmartContract) VerifyEvidenceHash(ctx contractapi.TransactionContextInterface, evidenceID, hashHex string) (bool, error) {
	if evidenceID == "" {
		return false, fmt.Errorf("chaincode: VerifyEvidenceHash: evidenceId must not be empty")
	}
	data, err := ctx.GetStub().GetState("ev:" + evidenceID)
	if err != nil {
		return false, fmt.Errorf("chaincode: VerifyEvidenceHash: %w", err)
	}
	if data == nil {
		return false, nil
	}
	var rec FabricEvidenceRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return false, fmt.Errorf("chaincode: VerifyEvidenceHash: unmarshal: %w", err)
	}
	return subtle.ConstantTimeCompare([]byte(rec.EncryptedFileHash), []byte(hashHex)) == 1, nil
}

func main() {
	cc, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		panic(fmt.Sprintf("chaincode: NewChaincode: %v", err))
	}
	if err := cc.Start(); err != nil {
		panic(fmt.Sprintf("chaincode: Start: %v", err))
	}
}
