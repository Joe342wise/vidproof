package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	cid "github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// Minimal in-memory ChaincodeStubInterface — no external mocking framework.
// ---------------------------------------------------------------------------

type mockStub struct {
	state map[string][]byte
	txID  string
}

// Compile-time interface check.
var _ shim.ChaincodeStubInterface = (*mockStub)(nil)

func newMockStub(txID string) *mockStub {
	return &mockStub{state: make(map[string][]byte), txID: txID}
}

func (s *mockStub) GetArgs() [][]byte                            { return nil }
func (s *mockStub) GetStringArgs() []string                      { return nil }
func (s *mockStub) GetFunctionAndParameters() (string, []string) { return "", nil }
func (s *mockStub) GetArgsSlice() ([]byte, error)                { return nil, nil }
func (s *mockStub) GetTxID() string                              { return s.txID }
func (s *mockStub) GetChannelID() string                         { return "mychannel" }

func (s *mockStub) InvokeChaincode(name string, args [][]byte, channel string) pb.Response {
	return pb.Response{}
}

func (s *mockStub) GetState(key string) ([]byte, error) { return s.state[key], nil }
func (s *mockStub) PutState(key string, value []byte) error {
	s.state[key] = append([]byte(nil), value...)
	return nil
}
func (s *mockStub) DelState(key string) error                              { delete(s.state, key); return nil }
func (s *mockStub) SetStateValidationParameter(key string, ep []byte) error { return nil }
func (s *mockStub) GetStateValidationParameter(key string) ([]byte, error)  { return nil, nil }

func (s *mockStub) GetStateByRange(startKey, endKey string) (shim.StateQueryIteratorInterface, error) {
	return nil, errors.New("not implemented")
}
func (s *mockStub) GetStateByRangeWithPagination(start, end string, size int32, bm string) (shim.StateQueryIteratorInterface, *pb.QueryResponseMetadata, error) {
	return nil, nil, errors.New("not implemented")
}
func (s *mockStub) GetStateByPartialCompositeKey(t string, keys []string) (shim.StateQueryIteratorInterface, error) {
	return nil, errors.New("not implemented")
}
func (s *mockStub) GetStateByPartialCompositeKeyWithPagination(t string, keys []string, size int32, bm string) (shim.StateQueryIteratorInterface, *pb.QueryResponseMetadata, error) {
	return nil, nil, errors.New("not implemented")
}
func (s *mockStub) CreateCompositeKey(t string, attrs []string) (string, error) { return "", nil }
func (s *mockStub) SplitCompositeKey(k string) (string, []string, error)        { return "", nil, nil }

func (s *mockStub) GetQueryResult(query string) (shim.StateQueryIteratorInterface, error) {
	return nil, errors.New("not implemented")
}
func (s *mockStub) GetQueryResultWithPagination(query string, size int32, bm string) (shim.StateQueryIteratorInterface, *pb.QueryResponseMetadata, error) {
	return nil, nil, errors.New("not implemented")
}

func (s *mockStub) GetHistoryForKey(key string) (shim.HistoryQueryIteratorInterface, error) {
	return nil, errors.New("GetHistoryForKey not implemented in test stub")
}

func (s *mockStub) GetPrivateData(col, key string) ([]byte, error)                  { return nil, nil }
func (s *mockStub) GetPrivateDataHash(col, key string) ([]byte, error)              { return nil, nil }
func (s *mockStub) PutPrivateData(col, key string, val []byte) error                { return nil }
func (s *mockStub) DelPrivateData(col, key string) error                            { return nil }
func (s *mockStub) SetPrivateDataValidationParameter(col, key string, ep []byte) error { return nil }
func (s *mockStub) GetPrivateDataValidationParameter(col, key string) ([]byte, error) { return nil, nil }
func (s *mockStub) GetPrivateDataByRange(col, start, end string) (shim.StateQueryIteratorInterface, error) {
	return nil, errors.New("not implemented")
}
func (s *mockStub) GetPrivateDataByPartialCompositeKey(col, t string, keys []string) (shim.StateQueryIteratorInterface, error) {
	return nil, errors.New("not implemented")
}
func (s *mockStub) GetPrivateDataQueryResult(col, query string) (shim.StateQueryIteratorInterface, error) {
	return nil, errors.New("not implemented")
}

func (s *mockStub) GetCreator() ([]byte, error)          { return nil, nil }
func (s *mockStub) GetTransient() (map[string][]byte, error) { return nil, nil }
func (s *mockStub) GetBinding() ([]byte, error)          { return nil, nil }
func (s *mockStub) GetDecorations() map[string][]byte    { return nil }

func (s *mockStub) GetSignedProposal() (*pb.SignedProposal, error) { return nil, nil }
func (s *mockStub) GetTxTimestamp() (*timestamppb.Timestamp, error) { return nil, nil }
func (s *mockStub) PurgePrivateData(col, key string) error { return nil }
func (s *mockStub) SetEvent(name string, payload []byte) error { return nil }

// mockContext satisfies contractapi.TransactionContextInterface.
type mockContext struct{ stub *mockStub }

func (m *mockContext) GetStub() shim.ChaincodeStubInterface { return m.stub }
func (m *mockContext) GetClientIdentity() cid.ClientIdentity { return nil }

func newTestContext(t *testing.T) (*SmartContract, *mockContext) {
	t.Helper()
	stub := newMockStub(fmt.Sprintf("tx-%s", t.Name()))
	return &SmartContract{}, &mockContext{stub: stub}
}

// ---------------------------------------------------------------------------
// RegisterCamera
// ---------------------------------------------------------------------------

func TestRegisterCamera(t *testing.T) {
	cam := CameraRecord{CameraID: "cam-001", DeviceSerial: "SN001"}
	camJSON, _ := json.Marshal(cam)

	tests := []struct {
		name     string
		cameraID string
		json     string
		wantErr  bool
	}{
		{"happy path", "cam-001", string(camJSON), false},
		{"empty id", "", string(camJSON), true},
		{"invalid json", "cam-002", `{bad}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc, ctx := newTestContext(t)
			err := sc.RegisterCamera(ctx, tc.cameraID, tc.json)
			if (err != nil) != tc.wantErr {
				t.Errorf("RegisterCamera() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestRegisterCamera_Duplicate(t *testing.T) {
	sc, ctx := newTestContext(t)
	cam := CameraRecord{CameraID: "cam-dup"}
	camJSON, _ := json.Marshal(cam)

	if err := sc.RegisterCamera(ctx, "cam-dup", string(camJSON)); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}
	if err := sc.RegisterCamera(ctx, "cam-dup", string(camJSON)); err == nil {
		t.Error("expected error on duplicate registration, got nil")
	}
}

// ---------------------------------------------------------------------------
// RegisterEvidence
// ---------------------------------------------------------------------------

func TestRegisterEvidence(t *testing.T) {
	ev := FabricEvidenceRecord{EvidenceID: "ev-001", CameraID: "cam-001", EncryptedFileHash: "abc123"}
	evJSON, _ := json.Marshal(ev)

	tests := []struct {
		name       string
		evidenceID string
		json       string
		wantErr    bool
	}{
		{"happy path", "ev-001", string(evJSON), false},
		{"empty id", "", string(evJSON), true},
		{"invalid json", "ev-002", `{bad}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc, ctx := newTestContext(t)
			err := sc.RegisterEvidence(ctx, tc.evidenceID, tc.json)
			if (err != nil) != tc.wantErr {
				t.Errorf("RegisterEvidence() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestRegisterEvidence_Duplicate(t *testing.T) {
	sc, ctx := newTestContext(t)
	ev := FabricEvidenceRecord{EvidenceID: "ev-dup"}
	evJSON, _ := json.Marshal(ev)

	if err := sc.RegisterEvidence(ctx, "ev-dup", string(evJSON)); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}
	if err := sc.RegisterEvidence(ctx, "ev-dup", string(evJSON)); err == nil {
		t.Error("expected error on duplicate registration, got nil")
	}
}

// ---------------------------------------------------------------------------
// LogVerification
// ---------------------------------------------------------------------------

func TestLogVerification(t *testing.T) {
	sc, ctx := newTestContext(t)
	ver := VerificationEvent{VerificationID: "ver-001", EvidenceID: "ev-001", PrimaryDecision: "PASS"}
	verJSON, _ := json.Marshal(ver)

	tests := []struct {
		name           string
		verificationID string
		json           string
		wantErr        bool
	}{
		{"happy path", "ver-001", string(verJSON), false},
		{"empty id", "", string(verJSON), true},
		{"invalid json", "ver-002", `{bad}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := sc.LogVerification(ctx, tc.verificationID, tc.json)
			if (err != nil) != tc.wantErr {
				t.Errorf("LogVerification() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// VerifyEvidenceHash
// ---------------------------------------------------------------------------

func TestVerifyEvidenceHash(t *testing.T) {
	sc, ctx := newTestContext(t)

	const storedHash = "deadbeef1234"
	ev := FabricEvidenceRecord{EvidenceID: "ev-hash", EncryptedFileHash: storedHash}
	evJSON, _ := json.Marshal(ev)
	if err := sc.RegisterEvidence(ctx, "ev-hash", string(evJSON)); err != nil {
		t.Fatalf("seed evidence: %v", err)
	}

	tests := []struct {
		name       string
		evidenceID string
		hashHex    string
		want       bool
		wantErr    bool
	}{
		{"matching hash", "ev-hash", storedHash, true, false},
		{"wrong hash", "ev-hash", "wronghash", false, false},
		{"not found returns false", "ev-missing", storedHash, false, false},
		{"empty evidence id", "", storedHash, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sc.VerifyEvidenceHash(ctx, tc.evidenceID, tc.hashHex)
			if (err != nil) != tc.wantErr {
				t.Errorf("VerifyEvidenceHash() error = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("VerifyEvidenceHash() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetEvidenceHistory
// ---------------------------------------------------------------------------

func TestGetEvidenceHistory_EmptyID(t *testing.T) {
	sc, ctx := newTestContext(t)
	_, err := sc.GetEvidenceHistory(ctx, "")
	if err == nil {
		t.Error("expected error for empty evidenceId, got nil")
	}
}

func TestGetEvidenceHistory_StubNotImplemented(t *testing.T) {
	sc, ctx := newTestContext(t)
	// mockStub.GetHistoryForKey returns an error — verify it surfaces cleanly.
	_, err := sc.GetEvidenceHistory(ctx, "ev-001")
	if err == nil {
		t.Error("expected error from stub GetHistoryForKey, got nil")
	}
}
