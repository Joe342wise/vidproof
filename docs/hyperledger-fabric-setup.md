# Hyperledger Fabric Setup Reference

Validated research for VidProof's Milestone 6–7 work: test network, Go chaincode, and the Go Gateway SDK. All commands are sourced from official Hyperledger Fabric documentation (v2.5 / v2.4+ Gateway).

---

## 1. Prerequisites

Install on the VPS before anything else:

| Tool | Minimum | Notes |
|---|---|---|
| Docker | 19.03+ | Add your user to the `docker` group (`sudo usermod -aG docker $USER`) |
| Docker Compose | 1.27+ (or Compose V2) | `sudo apt-get install docker-compose` on Ubuntu |
| Go | 1.22+ | Match the version in `fabric-adapter/go.mod` and `chaincode/vidproof/go.mod` |
| Git | any recent | For cloning fabric-samples |
| curl | any | For the install script |

**Linux post-install for Docker:**
```bash
sudo systemctl start docker
sudo usermod -aG docker $USER
newgrp docker          # apply group without logout
```

---

## 2. Install Fabric Binaries and Samples

The official install script downloads binaries (`peer`, `orderer`, `cryptogen`, `fabric-ca-client`, etc.) and Docker images:

```bash
curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
chmod +x install-fabric.sh
./install-fabric.sh docker binary samples
```

This installs Fabric **2.5.16** and CA **1.5.17** by default and clones `fabric-samples/` into the current directory.

Add the binaries to PATH:
```bash
export PATH=$PWD/fabric-samples/bin:$PATH
export FABRIC_CFG_PATH=$PWD/fabric-samples/config/
```

---

## 3. Bring Up the Test Network

```bash
cd fabric-samples/test-network

# Tear down any prior run first — always
./network.sh down

# Start peers + orderer (no channel yet)
./network.sh up

# Create the default channel 'mychannel'
./network.sh createChannel

# Or do both in one command
./network.sh up createChannel
```

Channel name rules: lowercase alphanumerics, dots, and dashes only; < 250 chars; must start with a letter.

The test network creates two peer organizations (`Org1`, `Org2`) and one orderer. Crypto material lands in:
```
test-network/organizations/peerOrganizations/
test-network/organizations/ordererOrganizations/
```

---

## 4. Go Chaincode Structure

### 4.1 Module setup

```
chaincode/vidproof/
├── go.mod
├── go.sum
└── chaincode.go   (or main.go)
```

`go.mod` minimum:
```go
module vidproof/chaincode

go 1.22

require (
    github.com/hyperledger/fabric-contract-api-go v1.2.2
    github.com/hyperledger/fabric-chaincode-go v0.0.0-20240124143825-7f6ced09b2a7
)
```

Vendor dependencies before packaging (required by Fabric's builder):
```bash
cd chaincode/vidproof
go mod tidy
go mod vendor
```

### 4.2 Contract pattern

```go
package main

import (
    "encoding/json"
    "fmt"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SmartContract struct {
    contractapi.Contract
}

// Transaction methods — each receives TransactionContextInterface as first arg.
// Return types can be (T, error) or just error.

func (s *SmartContract) RegisterCamera(ctx contractapi.TransactionContextInterface, cameraJSON string) error {
    return ctx.GetStub().PutState("cam:"+cameraId, []byte(cameraJSON))
}

func (s *SmartContract) GetCamera(ctx contractapi.TransactionContextInterface, cameraId string) (string, error) {
    data, err := ctx.GetStub().GetState("cam:" + cameraId)
    if err != nil {
        return "", fmt.Errorf("chaincode: GetCamera: %w", err)
    }
    if data == nil {
        return "", fmt.Errorf("chaincode: camera %s does not exist", cameraId)
    }
    return string(data), nil
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
```

Key stub methods:
- `ctx.GetStub().PutState(key, []byte)` — write
- `ctx.GetStub().GetState(key)` → `([]byte, error)` — read
- `ctx.GetStub().DelState(key)` — delete
- `ctx.GetStub().GetStateByRange("", "")` — range query
- `ctx.GetStub().GetHistoryForKey(key)` — full history (needed for `GetEvidenceHistory`)
- `ctx.GetStub().GetTxID()` — returns the Fabric transaction ID

---

## 5. Chaincode Lifecycle: Package → Deploy

These commands are run from `fabric-samples/test-network/`.

### 5.1 Environment variables (switch between orgs by re-exporting)

```bash
export PATH=${PWD}/../bin:$PATH
export FABRIC_CFG_PATH=$PWD/../config/

# Org1
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051
```

```bash
# Org2 (swap to approve from Org2's side)
export CORE_PEER_LOCALMSPID="Org2MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
export CORE_PEER_ADDRESS=localhost:9051
```

### 5.2 Package

```bash
peer lifecycle chaincode package vidproof.tar.gz \
  --path ../../chaincode/vidproof/ \
  --lang golang \
  --label vidproof_1.0
```

### 5.3 Install (run for each org)

```bash
# As Org1
peer lifecycle chaincode install vidproof.tar.gz

# As Org2 (re-export Org2 env vars first)
peer lifecycle chaincode install vidproof.tar.gz
```

### 5.4 Get the package ID

```bash
peer lifecycle chaincode queryinstalled
# Output: Package ID: vidproof_1.0:abc123..., Label: vidproof_1.0
export CC_PACKAGE_ID=vidproof_1.0:abc123...
```

### 5.5 Approve for each org

```bash
# Run as Org1, then re-run as Org2 with Org2 env vars
peer lifecycle chaincode approveformyorg \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --channelID mychannel \
  --name vidproof \
  --version 1.0 \
  --package-id $CC_PACKAGE_ID \
  --sequence 1 \
  --tls \
  --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
```

### 5.6 Check readiness (both orgs must show true)

```bash
peer lifecycle chaincode checkcommitreadiness \
  --channelID mychannel \
  --name vidproof \
  --version 1.0 \
  --sequence 1 \
  --tls \
  --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
  --output json
# Expected: {"approvals": {"Org1MSP": true, "Org2MSP": true}}
```

### 5.7 Commit

```bash
peer lifecycle chaincode commit \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --channelID mychannel \
  --name vidproof \
  --version 1.0 \
  --sequence 1 \
  --tls \
  --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
  --peerAddresses localhost:7051 \
  --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" \
  --peerAddresses localhost:9051 \
  --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
```

### 5.8 Verify committed

```bash
peer lifecycle chaincode querycommitted \
  --channelID mychannel \
  --name vidproof \
  --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
```

### 5.9 Shortcut via network.sh (for development)

The test network script wraps all of the above:
```bash
./network.sh deployCC -ccn vidproof -ccp ../../chaincode/vidproof -ccl go -c mychannel
```

Use this during early development; switch to manual lifecycle commands when you need sequence upgrades or custom endorsement policies.

---

## 6. Go Fabric Adapter: Gateway SDK

Requires Fabric **v2.4+** peers (Gateway service must be enabled — it is by default in 2.5).

### 6.1 Module dependency

```bash
cd fabric-adapter
go get github.com/hyperledger/fabric-gateway
go get google.golang.org/grpc
```

`go.mod` additions:
```
require (
    github.com/hyperledger/fabric-gateway v1.12.0
    google.golang.org/grpc v1.64.0
)
```

### 6.2 Crypto material paths (from test-network)

```go
const (
    // Point these at the test-network organizations directory
    cryptoPath  = "../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
    certPath    = cryptoPath + "/users/User1@org1.example.com/msp/signcerts"
    keyPath     = cryptoPath + "/users/User1@org1.example.com/msp/keystore"
    tlsCertPath = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
    peerEndpoint = "localhost:7051"
    gatewayPeer  = "peer0.org1.example.com"   // TLS SNI
    mspID        = "Org1MSP"
    channelName  = "mychannel"
    chaincodeName = "vidproof"
)
```

### 6.3 Full connection pattern

```go
package main

import (
    "crypto/x509"
    "os"

    "github.com/hyperledger/fabric-gateway/pkg/client"
    "github.com/hyperledger/fabric-gateway/pkg/hash"
    "github.com/hyperledger/fabric-gateway/pkg/identity"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func newGrpcConnection() *grpc.ClientConn {
    certPEM, err := os.ReadFile(tlsCertPath)
    if err != nil {
        panic(fmt.Errorf("adapter: read TLS cert: %w", err))
    }
    cert, err := identity.CertificateFromPEM(certPEM)
    if err != nil {
        panic(fmt.Errorf("adapter: parse TLS cert: %w", err))
    }
    pool := x509.NewCertPool()
    pool.AddCert(cert)
    creds := credentials.NewClientTLSFromCert(pool, gatewayPeer)
    conn, err := grpc.NewClient(peerEndpoint, grpc.WithTransportCredentials(creds))
    if err != nil {
        panic(fmt.Errorf("adapter: grpc dial: %w", err))
    }
    return conn
}

func newIdentity() *identity.X509Identity {
    certPEM, err := readFirstFile(certPath)
    if err != nil {
        panic(fmt.Errorf("adapter: read cert: %w", err))
    }
    cert, err := identity.CertificateFromPEM(certPEM)
    if err != nil {
        panic(fmt.Errorf("adapter: parse cert: %w", err))
    }
    id, err := identity.NewX509Identity(mspID, cert)
    if err != nil {
        panic(fmt.Errorf("adapter: new identity: %w", err))
    }
    return id
}

func newSign() identity.Sign {
    keyPEM, err := readFirstFile(keyPath)
    if err != nil {
        panic(fmt.Errorf("adapter: read key: %w", err))
    }
    pk, err := identity.PrivateKeyFromPEM(keyPEM)
    if err != nil {
        panic(fmt.Errorf("adapter: parse key: %w", err))
    }
    sign, err := identity.NewPrivateKeySign(pk)
    if err != nil {
        panic(fmt.Errorf("adapter: new sign: %w", err))
    }
    return sign
}

// readFirstFile reads the first file in a directory (keystore contains one key file with a generated name)
func readFirstFile(dir string) ([]byte, error) {
    entries, err := os.ReadDir(dir)
    if err != nil {
        return nil, err
    }
    return os.ReadFile(filepath.Join(dir, entries[0].Name()))
}
```

### 6.4 Gateway and contract setup (wire once at startup)

```go
conn := newGrpcConnection()
defer conn.Close()

gw, err := client.Connect(
    newIdentity(),
    client.WithSign(newSign()),
    client.WithHash(hash.SHA256),
    client.WithClientConnection(conn),
    client.WithEvaluateTimeout(5*time.Second),
    client.WithEndorseTimeout(15*time.Second),
    client.WithSubmitTimeout(5*time.Second),
    client.WithCommitStatusTimeout(1*time.Minute),
)
if err != nil {
    panic(fmt.Errorf("adapter: gateway connect: %w", err))
}
defer gw.Close()

network := gw.GetNetwork(channelName)
contract := network.GetContract(chaincodeName)
```

### 6.5 Submit (write) and Evaluate (read)

```go
// Write — waits for commit
result, err := contract.SubmitTransaction("RegisterCamera", cameraJSON)

// Read-only — does not go to orderer
result, err := contract.EvaluateTransaction("GetCamera", cameraId)

// Async submit — useful for fire-and-wait patterns
submitResult, commit, err := contract.SubmitAsync("RegisterEvidence",
    client.WithArguments(evidenceJSON))
status, err := commit.Status()       // blocks until committed
fmt.Println(commit.TransactionID())  // Fabric tx ID to store in metadata
```

### 6.6 Error handling

```go
var endorseErr *client.EndorseError
var submitErr *client.SubmitError
var commitStatusErr *client.CommitStatusError
var commitErr *client.CommitError

switch {
case errors.As(err, &endorseErr):
    // Endorsement rejected — check endorsement policy / chaincode logic
    log.Printf("adapter: endorse failed tx %s: %v", endorseErr.TransactionID, err)
case errors.As(err, &submitErr):
    // Orderer rejected the transaction
    log.Printf("adapter: submit failed tx %s: %v", submitErr.TransactionID, err)
case errors.As(err, &commitErr):
    // Transaction committed with failure status
    log.Printf("adapter: commit failed tx %s code %v: %v", commitErr.TransactionID, commitErr.Code, err)
case errors.As(err, &commitStatusErr):
    // Could not get commit status (timeout etc.)
    log.Printf("adapter: commit status failed tx %s: %v", commitStatusErr.TransactionID, err)
}
```

---

## 7. Identity: No Wallet in the Modern SDK

The old `fabric-sdk-go` had a wallet abstraction. **The modern `fabric-gateway` SDK does not use wallets.** Identity is just:
- An X.509 certificate PEM file (from `msp/signcerts/`)
- A private key PEM file (from `msp/keystore/`)
- An MSP ID string

For the test network, `cryptogen` generates all of this under `organizations/`. For production, `fabric-ca-client enroll` generates the same structure.

The adapter reads these files directly at startup — no wallet, no in-memory store needed.

---

## 8. Common Pitfalls

### Network / Docker

| Problem | Fix |
|---|---|
| Errors on `./network.sh up` after a previous failed run | Always run `./network.sh down` first to remove old containers and volumes |
| Nodes can't reach each other | Check Docker network; verify firewall isn't blocking inter-container traffic |
| macOS Docker file sharing errors | In Docker Desktop → Settings → uncheck "Use gRPC FUSE for file sharing"; use legacy osxfs |
| `crypto material` mount errors | Usually a stale Docker volume; `./network.sh down && ./network.sh up` |

### Chaincode Lifecycle

| Problem | Fix |
|---|---|
| `ENDORSEMENT_POLICY_FAILURE` during commit | Both orgs must have approved (`checkcommitreadiness` must show both `true`) before committing |
| Wrong `--package-id` in `approveformyorg` | Run `queryinstalled` and copy the exact ID including the hash suffix |
| Chaincode fails to build | Run `go mod tidy && go mod vendor` in the chaincode directory before packaging; Fabric's builder requires vendor/ |
| `sequence` mismatch on upgrade | Increment `--sequence` by 1 each time you deploy an updated version; re-approve and re-commit |
| Chaincode container not starting | Run `docker logs <chaincode-container>` — usually a Go compilation error in the chaincode |

### Gateway SDK

| Problem | Fix |
|---|---|
| `failed to create new connection` | Check `peerEndpoint` and `gatewayPeer` (SNI) match the peer's address and TLS cert |
| TLS handshake failure | The `tlsCertPath` must point to the peer's TLS CA cert, not the MSP cert |
| `keystore` directory has no files | `cryptogen` was not run or the path is wrong; list the keystore dir to confirm one file exists |
| `EndorseError` with chaincode not found | Chaincode name in `GetContract()` must exactly match `--name` used in `approveformyorg` and `commit` |
| Transactions succeeding but returning wrong data | Check `EvaluateTransaction` vs `SubmitTransaction` — evaluate never writes to ledger |
| Fabric Gateway service not available | Requires Fabric peer v2.4+; check peer is started with `FABRIC_LOGGING_SPEC` and not an old image |

### Go Chaincode

| Problem | Fix |
|---|---|
| `ctx.GetStub().GetState()` returns nil with no error | Key does not exist in world state — always check for nil before unmarshalling |
| `GetHistoryForKey` returns nothing | Only returns history for keys written after the chaincode was committed; re-submit some records |
| Panic in chaincode | Fabric catches panics but marks the transaction as failed; use `recover` or return errors instead |

---

## 9. Key Ports (test-network defaults)

| Service | Port |
|---|---|
| Org1 peer (peer0.org1) | 7051 |
| Org2 peer (peer0.org2) | 9051 |
| Orderer | 7050 |
| Org1 CA | 7054 |
| Org2 CA | 8054 |
| VidProof fabric-adapter | 8081 |

---

## Sources

- [Using the Fabric Test Network](https://hyperledger-fabric.readthedocs.io/en/latest/test_network.html)
- [Fabric Installation / Prerequisites](https://hyperledger-fabric.readthedocs.io/en/latest/prereqs.html)
- [Deploying a Smart Contract to a Channel](https://hyperledger-fabric.readthedocs.io/en/release-2.2/deploy_chaincode.html)
- [Fabric Chaincode Lifecycle](https://hyperledger-fabric.readthedocs.io/en/latest/chaincode_lifecycle.html)
- [Writing Your First Chaincode (Go / contractapi)](https://hyperledger-fabric.readthedocs.io/en/release-2.5/chaincode4ade.html)
- [Fabric Gateway — Getting Started](https://hyperledger.github.io/fabric-gateway/)
- [fabric-gateway pkg/client API](https://pkg.go.dev/github.com/hyperledger/fabric-gateway/pkg/client)
- [fabric-gateway GitHub](https://github.com/hyperledger/fabric-gateway)
- [fabric-samples asset-transfer-basic (Go Gateway app)](https://github.com/hyperledger/fabric-samples)
- [fabric-contract-api-go Getting Started](https://github.com/hyperledger/fabric-contract-api-go/blob/main/tutorials/getting-started.md)
- [Troubleshooting Common Issues](https://www.spydra.app/blog/troubleshooting-common-issues-in-hyperledger-fabric-a-guide-for-developers)
