"""
Re-export shim — all crypto primitives now live in vidproof_crypto.

Existing code that imports from forensics.crypto_core continues to work
unchanged. New code (especially edge/) should import from vidproof_crypto
directly so it does not depend on the forensics package.
"""
from vidproof_crypto import (  # noqa: F401
    InvalidTag,
    InvalidUnwrap,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    sha256_bytes,
    sha256_file,
    sign_plaintext_hash,
    unwrap_aes_key,
    verify_ed25519_signature,
    wrap_aes_key,
)
