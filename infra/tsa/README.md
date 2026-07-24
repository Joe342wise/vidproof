# RFC 3161 TSA

Prototype target: self-hosted OpenSSL RFC 3161 timestamp authority.

Timestamp these records:

- Evidence registration after capture
- Capture-time signed record
- Forensic export package hash

Each exported package must include the TSA token, TSA certificate, and verification instructions.
