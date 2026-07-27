package fabric

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Config holds all configurable paths and identifiers for the Fabric connection.
// All fields have defaults for the fabric-samples test-network layout; override
// via FABRIC_* environment variables.
type Config struct {
	// Path to the test-network organizations directory.
	CryptoPath string
	// User identity cert directory (msp/signcerts).
	CertPath string
	// User private key directory (msp/keystore).
	KeyPath string
	// Peer TLS CA cert (tls/ca.crt).
	TLSCertPath string
	// Peer gRPC endpoint (host:port).
	PeerEndpoint string
	// Peer hostname for TLS SNI.
	GatewayPeer string
	// Membership Service Provider ID.
	MSPID string
	// Channel name.
	ChannelName string
	// Chaincode name.
	ChaincodeName string
}

// DefaultConfig returns Config populated from FABRIC_* env vars, falling back
// to test-network paths relative to the current working directory.
func DefaultConfig() Config {
	base := envOr("FABRIC_CRYPTO_PATH",
		"../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com")
	return Config{
		CryptoPath:    base,
		CertPath:      envOr("FABRIC_CERT_PATH", filepath.Join(base, "users/User1@org1.example.com/msp/signcerts")),
		KeyPath:       envOr("FABRIC_KEY_PATH", filepath.Join(base, "users/User1@org1.example.com/msp/keystore")),
		TLSCertPath:   envOr("FABRIC_TLS_CERT_PATH", filepath.Join(base, "peers/peer0.org1.example.com/tls/ca.crt")),
		PeerEndpoint:  envOr("FABRIC_PEER_ENDPOINT", "localhost:7051"),
		GatewayPeer:   envOr("FABRIC_GATEWAY_PEER", "peer0.org1.example.com"),
		MSPID:         envOr("FABRIC_MSP_ID", "Org1MSP"),
		ChannelName:   envOr("FABRIC_CHANNEL", "mychannel"),
		ChaincodeName: envOr("FABRIC_CHAINCODE", "vidproof"),
	}
}

// Gateway wraps the Fabric client.Gateway and the underlying gRPC connection.
type Gateway struct {
	gw       *client.Gateway
	conn     *grpc.ClientConn
	contract *client.Contract
}

// NewGateway opens a gRPC connection to the peer, loads identity material, and
// returns a connected Gateway. The caller must call Close() when done.
func NewGateway(cfg Config) (*Gateway, error) {
	conn, err := newGRPCConnection(cfg)
	if err != nil {
		return nil, fmt.Errorf("adapter: fabric: grpc: %w", err)
	}

	id, err := newIdentity(cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("adapter: fabric: identity: %w", err)
	}

	sign, err := newSign(cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("adapter: fabric: sign: %w", err)
	}

	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("adapter: fabric: connect: %w", err)
	}

	contract := gw.GetNetwork(cfg.ChannelName).GetContract(cfg.ChaincodeName)
	return &Gateway{gw: gw, conn: conn, contract: contract}, nil
}

// Close releases the gateway and gRPC connection.
func (g *Gateway) Close() {
	g.gw.Close()
	g.conn.Close()
}

// ---------------------------------------------------------------------------
// Transaction methods — each maps to one chaincode function.
// ---------------------------------------------------------------------------

// RegisterCamera submits a RegisterCamera transaction and returns the Fabric tx ID.
func (g *Gateway) RegisterCamera(ctx context.Context, cameraID, cameraJSON string) (string, error) {
	txID, err := g.submit(ctx, "RegisterCamera", cameraID, cameraJSON)
	if err != nil {
		return "", fmt.Errorf("adapter: fabric: RegisterCamera: %w", err)
	}
	return txID, nil
}

// RegisterEvidence submits a RegisterEvidence transaction and returns the Fabric tx ID.
func (g *Gateway) RegisterEvidence(ctx context.Context, evidenceID, evidenceJSON string) (string, error) {
	txID, err := g.submit(ctx, "RegisterEvidence", evidenceID, evidenceJSON)
	if err != nil {
		return "", fmt.Errorf("adapter: fabric: RegisterEvidence: %w", err)
	}
	return txID, nil
}

// LogVerification submits a LogVerification transaction and returns the Fabric tx ID.
func (g *Gateway) LogVerification(ctx context.Context, verificationID, verificationJSON string) (string, error) {
	txID, err := g.submit(ctx, "LogVerification", verificationID, verificationJSON)
	if err != nil {
		return "", fmt.Errorf("adapter: fabric: LogVerification: %w", err)
	}
	return txID, nil
}

// LogAccess submits a LogAccess transaction and returns the Fabric tx ID.
func (g *Gateway) LogAccess(ctx context.Context, custodyJSON string) (string, error) {
	txID, err := g.submit(ctx, "LogAccess", custodyJSON)
	if err != nil {
		return "", fmt.Errorf("adapter: fabric: LogAccess: %w", err)
	}
	return txID, nil
}

// LogExport submits a LogExport transaction and returns the Fabric tx ID.
func (g *Gateway) LogExport(ctx context.Context, custodyJSON string) (string, error) {
	txID, err := g.submit(ctx, "LogExport", custodyJSON)
	if err != nil {
		return "", fmt.Errorf("adapter: fabric: LogExport: %w", err)
	}
	return txID, nil
}

// GetEvidenceHistory evaluates GetEvidenceHistory (read-only) and returns the
// raw JSON history array from the chaincode.
func (g *Gateway) GetEvidenceHistory(ctx context.Context, evidenceID string) (json.RawMessage, error) {
	result, err := g.contract.EvaluateTransaction("GetEvidenceHistory", evidenceID)
	if err != nil {
		return nil, fmt.Errorf("adapter: fabric: GetEvidenceHistory: %w", err)
	}
	return json.RawMessage(result), nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// submit calls SubmitAsync, waits for commit, and returns the Fabric tx ID.
func (g *Gateway) submit(ctx context.Context, fn string, args ...string) (string, error) {
	submitResult, commit, err := g.contract.SubmitAsync(fn, client.WithArguments(args...))
	_ = submitResult
	if err != nil {
		return "", fmt.Errorf("submit %s: %w", fn, fabricError(err))
	}
	status, err := commit.Status()
	if err != nil {
		return "", fmt.Errorf("commit status %s: %w", fn, fabricError(err))
	}
	if !status.Successful {
		return "", fmt.Errorf("commit %s: transaction failed with code %v", fn, status.Code)
	}
	return commit.TransactionID(), nil
}

// fabricError maps Fabric SDK error types to descriptive messages, preserving %w
// wrapping for errors.Is/As checks at the call site.
func fabricError(err error) error {
	return err // callers use errors.As if they need type-specific handling
}

func newGRPCConnection(cfg Config) (*grpc.ClientConn, error) {
	certPEM, err := os.ReadFile(cfg.TLSCertPath)
	if err != nil {
		return nil, fmt.Errorf("read TLS cert %s: %w", cfg.TLSCertPath, err)
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse TLS cert: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	creds := credentials.NewClientTLSFromCert(pool, cfg.GatewayPeer)
	conn, err := grpc.NewClient(cfg.PeerEndpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("grpc.NewClient(%s): %w", cfg.PeerEndpoint, err)
	}
	return conn, nil
}

func newIdentity(cfg Config) (*identity.X509Identity, error) {
	certPEM, err := readFirstFile(cfg.CertPath)
	if err != nil {
		return nil, fmt.Errorf("read cert dir %s: %w", cfg.CertPath, err)
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	id, err := identity.NewX509Identity(cfg.MSPID, cert)
	if err != nil {
		return nil, fmt.Errorf("NewX509Identity: %w", err)
	}
	return id, nil
}

func newSign(cfg Config) (identity.Sign, error) {
	keyPEM, err := readFirstFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read key dir %s: %w", cfg.KeyPath, err)
	}
	pk, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	sign, err := identity.NewPrivateKeySign(pk)
	if err != nil {
		return nil, fmt.Errorf("NewPrivateKeySign: %w", err)
	}
	return sign, nil
}

// readFirstFile returns the bytes of the first file found in dir.
// Fabric's keystore directory contains exactly one key file with a generated name.
func readFirstFile(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			return os.ReadFile(filepath.Join(dir, e.Name()))
		}
	}
	return nil, fmt.Errorf("no files found in %s", dir)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
