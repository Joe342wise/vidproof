package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	cid "github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	queryresult "github.com/hyperledger/fabric-protos-go/ledger/queryresult"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// mockKVIterator — satisfies shim.StateQueryIteratorInterface.
// ---------------------------------------------------------------------------

type mockKVIterator struct {
	items []*queryresult.KV
	pos   int
}

var _ shim.StateQueryIteratorInterface = (*mockKVIterator)(nil)

func (it *mockKVIterator) HasNext() bool { return it.pos < len(it.items) }
func (it *mockKVIterator) Close() error  { return nil }
func (it *mockKVIterator) Next() (*queryresult.KV, error) {
	if !it.HasNext() {
		return nil, fmt.Errorf("mockKVIterator: no more items")
	}
	kv := it.items[it.pos]
	it.pos++
	return kv, nil
}

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
func (s *mockStub) DelState(key string) error                               { delete(s.state, key); return nil }
func (s *mockStub) SetStateValidationParameter(key string, ep []byte) error { return nil }
func (s *mockStub) GetStateValidationParameter(key string) ([]byte, error)  { return nil, nil }

func (s *mockStub) GetStateByRange(startKey, endKey string) (shim.StateQueryIteratorInterface, error) {
	return nil, errors.New("not implemented")
}
func (s *mockStub) GetStateByRangeWithPagination(start, end string, size int32, bm string) (shim.StateQueryIteratorInterface, *pb.QueryResponseMetadata, error) {
	return nil, nil, errors.New("not implemented")
}

// CreateCompositeKey produces: \x00objectType\x00attr0\x00attr1\x00...
// This matches Fabric's actual composite key format.
func (s *mockStub) CreateCompositeKey(objectType string, attrs []string) (string, error) {
	var b strings.Builder
	b.WriteByte(0x00)
	b.WriteString(objectType)
	for _, a := range attrs {
		b.WriteByte(0x00)
		b.WriteString(a)
	}
	b.WriteByte(0x00)
	return b.String(), nil
}

// SplitCompositeKey is the inverse of CreateCompositeKey.
func (s *mockStub) SplitCompositeKey(compositeKey string) (string, []string, error) {
	if len(compositeKey) < 2 || compositeKey[0] != 0x00 {
		return "", nil, fmt.Errorf("invalid composite key")
	}
	// Strip leading and trailing \x00, then split on \x00.
	inner := compositeKey[1 : len(compositeKey)-1]
	parts := strings.Split(inner, "\x00")
	if len(parts) == 0 {
		return "", nil, nil
	}
	return parts[0], parts[1:], nil
}

// GetStateByPartialCompositeKey scans state for keys whose prefix matches.
func (s *mockStub) GetStateByPartialCompositeKey(objectType string, keys []string) (shim.StateQueryIteratorInterface, error) {
	prefix, _ := s.CreateCompositeKey(objectType, keys)
	// Remove trailing \x00 so the prefix matches any continuation.
	prefix = prefix[:len(prefix)-1]

	var items []*queryresult.KV
	for k, v := range s.state {
		if strings.HasPrefix(k, prefix) {
			cp := make([]byte, len(v))
			copy(cp, v)
			items = append(items, &queryresult.KV{Key: k, Value: cp})
		}
	}
	return &mockKVIterator{items: items}, nil
}

func (s *mockStub) GetStateByPartialCompositeKeyWithPagination(t string, keys []string, size int32, bm string) (shim.StateQueryIteratorInterface, *pb.QueryResponseMetadata, error) {
	return nil, nil, errors.New("not implemented")
}

func (s *mockStub) GetQueryResult(query string) (shim.StateQueryIteratorInterface, error) {
	return nil, errors.New("not implemented")
}
func (s *mockStub) GetQueryResultWithPagination(query string, size int32, bm string) (shim.StateQueryIteratorInterface, *pb.QueryResponseMetadata, error) {
	return nil, nil, errors.New("not implemented")
}

// GetHistoryForKey is intentionally not implemented — it requires a live peer.
// GetEvidenceHistory degrades gracefully when this returns an error.
func (s *mockStub) GetHistoryForKey(key string) (shim.HistoryQueryIteratorInterface, error) {
	return nil, errors.New("GetHistoryForKey not implemented in test stub")
}

func (s *mockStub) GetPrivateData(col, key string) ([]byte, error)                    { return nil, nil }
func (s *mockStub) GetPrivateDataHash(col, key string) ([]byte, error)                { return nil, nil }
func (s *mockStub) PutPrivateData(col, key string, val []byte) error                  { return nil }
func (s *mockStub) DelPrivateData(col, key string) error                              { return nil }
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

func (s *mockStub) GetCreator() ([]byte, error)             { return nil, nil }
func (s *mockStub) GetTransient() (map[string][]byte, error) { return nil, nil }
func (s *mockStub) GetBinding() ([]byte, error)             { return nil, nil }
func (s *mockStub) GetDecorations() map[string][]byte       { return nil }

func (s *mockStub) GetSignedProposal() (*pb.SignedProposal, error)    { return nil, nil }
func (s *mockStub) GetTxTimestamp() (*timestamppb.Timestamp, error)   { return nil, nil }
func (s *mockStub) PurgePrivateData(col, key string) error            { return nil }
func (s *mockStub) SetEvent(name string, payload []byte) error        { return nil }

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
// LogVerification — primary key + evidence index
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

func TestLogVerification_WritesEvidenceIndex(t *testing.T) {
	sc, ctx := newTestContext(t)
	ver := VerificationEvent{
		VerificationID:  "ver-idx",
		EvidenceID:      "ev-idx",
		PrimaryDecision: "PASS",
		VerifiedAt:      "2024-01-01T12:00:00Z",
	}
	verJSON, _ := json.Marshal(ver)

	if err := sc.LogVerification(ctx, "ver-idx", string(verJSON)); err != nil {
		t.Fatalf("LogVerification: %v", err)
	}

	// Primary key must exist.
	if v, _ := ctx.stub.GetState("ver:ver-idx"); v == nil {
		t.Error("expected primary key ver:ver-idx to exist")
	}

	// Composite index key must exist.
	ck, _ := ctx.stub.CreateCompositeKey("evhist", []string{"ev-idx", "ver", "ver-idx"})
	if v, _ := ctx.stub.GetState(ck); v == nil {
		t.Error("expected composite index key to exist")
	}
}

// ---------------------------------------------------------------------------
// LogExport — primary key + evidence index
// ---------------------------------------------------------------------------

func TestLogExport_WritesEvidenceIndex(t *testing.T) {
	sc, ctx := newTestContext(t)
	ctx.stub.txID = "tx-export-001"

	ev := CustodyEvent{
		EventType:  "export",
		EvidenceID: "ev-export",
		ActorID:    "alice",
		Timestamp:  "2024-01-01T13:00:00Z",
	}
	evJSON, _ := json.Marshal(ev)

	if err := sc.LogExport(ctx, string(evJSON)); err != nil {
		t.Fatalf("LogExport: %v", err)
	}

	// Primary custody key must exist.
	if v, _ := ctx.stub.GetState("custody:export:tx-export-001"); v == nil {
		t.Error("expected primary custody key to exist")
	}

	// Composite index key must exist.
	ck, _ := ctx.stub.CreateCompositeKey("evhist", []string{"ev-export", "custody", "tx-export-001"})
	if v, _ := ctx.stub.GetState(ck); v == nil {
		t.Error("expected composite index key to exist")
	}
}

func TestLogAccess_WritesEvidenceIndex(t *testing.T) {
	sc, ctx := newTestContext(t)
	ctx.stub.txID = "tx-access-001"

	ev := CustodyEvent{
		EventType:  "access",
		EvidenceID: "ev-access",
		ActorID:    "bob",
		Timestamp:  "2024-01-01T14:00:00Z",
	}
	evJSON, _ := json.Marshal(ev)

	if err := sc.LogAccess(ctx, string(evJSON)); err != nil {
		t.Fatalf("LogAccess: %v", err)
	}

	ck, _ := ctx.stub.CreateCompositeKey("evhist", []string{"ev-access", "custody", "tx-access-001"})
	if v, _ := ctx.stub.GetState(ck); v == nil {
		t.Error("expected composite index key to exist")
	}
}

// ---------------------------------------------------------------------------
// GetEvidenceHistory — combined results from composite index
// ---------------------------------------------------------------------------

func TestGetEvidenceHistory_EmptyID(t *testing.T) {
	sc, ctx := newTestContext(t)
	_, err := sc.GetEvidenceHistory(ctx, "")
	if err == nil {
		t.Error("expected error for empty evidenceId, got nil")
	}
}

func TestGetEvidenceHistory_NoEvents_ReturnsEmptyArray(t *testing.T) {
	sc, ctx := newTestContext(t)
	// GetHistoryForKey fails (stub), GetStateByPartialCompositeKey returns nothing.
	out, err := sc.GetEvidenceHistory(ctx, "ev-none")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var entries []histEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestGetEvidenceHistory_CombinedEvents(t *testing.T) {
	sc, ctx := newTestContext(t)
	ctx.stub.txID = "tx-ev-combined"

	const eid = "ev-combined"

	// Log a verification event.
	ver := VerificationEvent{
		VerificationID:  "ver-combined",
		EvidenceID:      eid,
		PrimaryDecision: "PASS",
		VerifiedAt:      "2024-06-01T10:00:00Z",
	}
	verJSON, _ := json.Marshal(ver)
	if err := sc.LogVerification(ctx, "ver-combined", string(verJSON)); err != nil {
		t.Fatalf("LogVerification: %v", err)
	}

	// Log an export event.
	exp := CustodyEvent{
		EventType:  "export",
		EvidenceID: eid,
		ActorID:    "alice",
		Timestamp:  "2024-06-01T11:00:00Z",
	}
	expJSON, _ := json.Marshal(exp)
	if err := sc.LogExport(ctx, string(expJSON)); err != nil {
		t.Fatalf("LogExport: %v", err)
	}

	out, err := sc.GetEvidenceHistory(ctx, eid)
	if err != nil {
		t.Fatalf("GetEvidenceHistory: %v", err)
	}

	var entries []histEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("invalid JSON output: %v — raw: %s", err, out)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (verification + export), got %d", len(entries))
	}

	types := map[string]bool{}
	for _, e := range entries {
		types[e.EventType] = true
	}
	if !types["verification"] {
		t.Error("expected a 'verification' entry in history")
	}
	if !types["export"] {
		t.Error("expected an 'export' entry in history")
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
