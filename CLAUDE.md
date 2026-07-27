# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

VidProof is a prototype privacy-preserving IoT surveillance verification system. It proves footage was attested by an enrolled camera using Ed25519 device signing as the primary authentication mechanism. PRNU (Photo Response Non-Uniformity) is a secondary forensic signal only — it is never a pass/fail gate.

## Commands

### Python environment setup
Each Python module has its own `requirements.txt`. Install separately per module:
```bash
pip install -r backend/requirements.txt
pip install -r forensics/requirements.txt
pip install -r dashboard/requirements.txt
```

### Run the FastAPI backend (port 8000)
```bash
uvicorn backend.app.main:app --reload
```

### Run the Streamlit dashboard (port 8501)
```bash
streamlit run dashboard/app.py
```

### Run the Go Fabric adapter (port 8081)
```bash
go run . -C fabric-adapter
```

### Build and test Go modules
```bash
go build ./... -C fabric-adapter
go build ./... -C chaincode/vidproof
go test ./... -C fabric-adapter
go test ./... -C chaincode/vidproof
```

### Syntax-check Python files
```bash
python3 -m py_compile backend/app/main.py
python3 -m py_compile forensics/hash_file.py
python3 -m py_compile forensics/verify_signature.py
```

### Forensic CLI tools (called via subprocess or directly)
```bash
python forensics/hash_file.py <path>
python forensics/verify_signature.py <public-key-base64> <hash-hex> <signature-base64>
python forensics/prnu_compare.py <reference-path> <video-path>
```

## Architecture

The system has a strict language split: **Python owns everything except Fabric**.

```
edge/          → Raspberry Pi capture (not yet implemented)
backend/       → FastAPI orchestration (Python, port 8000)
forensics/     → CLI tools for hashing, signature verification, PRNU (Python)
dashboard/     → Streamlit operator UI (Python, port 8501)
fabric-adapter/→ Thin HTTP service wrapping Fabric Gateway Go client (Go, port 8081)
chaincode/     → Hyperledger Fabric smart contract (Go)
infra/fabric/  → Fabric test-network setup notes
infra/tsa/     → OpenSSL RFC 3161 TSA configuration
storage/evidence/   → Encrypted video files (.enc)
storage/metadata/   → evidence.json, verification-result.json
docs/          → Schema contracts, algorithm specs, development plan
```

**Python → Go boundary**: The FastAPI backend calls the Fabric adapter over HTTP with JSON. The adapter is the only component that touches the Fabric SDK.

**Forensic CLIs**: The backend may invoke `forensics/` scripts via subprocess. Every CLI writes exactly one JSON object to stdout: `{"ok": true, "result": {...}}` on success or `{"ok": false, "error": {"code": "...", "message": "..."}}` on failure. Non-zero exit codes still produce a JSON error object.

## Core Data Contracts

Four local JSON records drive all workflow logic. See `docs/schemas.md` for full field definitions.

| File | Mutability | Written by |
|---|---|---|
| `camera.json` | Write-once | Enrollment |
| `evidence.json` | Write-once (immutable) | Capture |
| `verification-result.json` | Append-only (new file per run) | Verifier |
| `custody-record.json` | Append-only | Backend / Fabric adapter |

**Critical invariant**: verification must never mutate `evidence.json`. Write a new `verification-result.json` instead.

## Cryptographic Pipeline

The capture-and-verify round trip (Milestone 3) is the foundation everything else builds on:

1. Read plaintext video bytes
2. `plaintextHash = SHA-256(plaintext)`
3. Sign `plaintextHash` with camera Ed25519 private key → `deviceSignature`
4. Encrypt with fresh AES-256-GCM key + nonce → ciphertext + `authTag`
5. Wrap AES key with owner/investigator public key → `wrappedKey`
6. Write `<evidenceId>.enc` to `storage/evidence/`
7. `encryptedFileHash = SHA-256(ciphertext file bytes)`
8. Write immutable `evidence.json`

Verification reverses this: check `encryptedFileHash`, then `deviceSignature`, then (optionally) AES-GCM decrypt and compare `plaintextHash`.

**Never reuse AES-GCM nonces.** Both `nonce` and `authTag` are required for decryption — both live in `evidence.json`.

## Build Order / Current State

The project is at Milestone 0 (scaffold). Milestones must be completed in order:

1. **M1** Freeze schemas → **M2** File-mode enrollment → **M3** File-mode capture+verify

Do not start Fabric, TSA, PRNU, or Pi integration until the local cryptographic round trip (M3) works. The Fabric adapter and chaincode are currently stub placeholders returning 501/Not Implemented.

## Key Design Constraints

- Camera Ed25519 private keys must never be sent to the backend, Fabric, or dashboard
- Fabric stores only hashes, signatures, and custody metadata — never raw or decrypted video
- PRNU results are always secondary; `primaryDecision` in `verification-result.json` is set by hash+signature checks only
- File-mode and Pi-mode must use identical cryptographic code; only the video source changes

## Go Conventions (fabric-adapter and chaincode)

### Imports
Group in this order, separated by blank lines: standard library → third-party → module-internal. Run `goimports` to enforce.

### Packages & layout
- `internal/` for anything not imported externally; short lowercase single-word package names
- Entry point stays thin: parse config, wire deps, start, shut down — all logic in packages
- `main` calls `run() error` and `log.Fatal`s on error; libraries return errors, never call `os.Exit`/`log.Fatal`

### Design
- Define interfaces at the point of use (the consumer package), not next to the implementation
- Verify interface compliance at compile time: `var _ MyInterface = (*myImpl)(nil)`
- `context.Context` is the first parameter of every function that does I/O or can block; never store it on a struct
- Validate inputs at the top of a function and return immediately on failure — don't let invalid state travel
- Declaration order within a file: constructor → exported methods → unexported methods → helpers

### Errors
- Wrap with `%w` across package boundaries: `fmt.Errorf("adapter: register camera: %w", err)`; package prefix makes origins grep-able
- Sentinel errors for expected failure modes, compared with `errors.Is`; named `ErrFoo`
- Handle errors once: either handle (log + degrade) or propagate with context, never both

### Style & naming
- `any` not `interface{}`; lines ≤ ~100 chars
- Guard clauses with early returns; no unnecessary `else` after a returning `if`
- Structs initialized with field names; `var` for zero-value structs
- Zero values must be safe or deliberately invalid — never let a zero value silently grant access
- No mutable globals; state owned by structs and injected

### Concurrency
- No fire-and-forget goroutines — every background goroutine has a `Stop()` path and waits for exit
- `defer` the unlock; keep critical sections small
- Buffered channels need a documented reason; prefer size 1

### Testing
- Table-driven tests with `t.Run`; cover both success and error paths
- `t.Fatal` for preconditions that make later checks meaningless; `t.Error` for assertions
- Fakes (small in-memory implementations) over mocks; compile-time compliance checks
- Time is injected so expiry logic is testable without sleeping
- Run with `-race`: `go test -race ./...`

### Security (especially relevant for the Fabric adapter)
- **Constant-time comparisons** for all secret material: `hmac.Equal` / `subtle.ConstantTimeCompare`, never `==`
- **`crypto/rand`** for any token or random value generation — never `math/rand`
- Secrets/hashes are never logged or serialized unintentionally; use `json:"-"` on sensitive fields
- Fail closed: unknown or zero-value roles/states must have zero privilege
- Bound request bodies before reading them (`io.LimitReader` with a named constant)
- Generic error messages outward; detailed structured log events inward — never log the credential itself

## Python Conventions (backend, forensics, dashboard)

- Use `pathlib.Path` over `os.path` string manipulation
- Pydantic models for all FastAPI request/response shapes; validate at the boundary, not deep inside handlers
- Forensic CLI scripts: always write one JSON object to stdout (`{"ok": true, "result": {...}}` or `{"ok": false, "error": {...}}`); non-zero exit still writes JSON
- `evidence.json` is write-once — no function that reads it should also write to it
