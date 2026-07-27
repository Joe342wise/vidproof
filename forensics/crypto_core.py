"""
Shared cryptographic primitives for VidProof capture and verification.
Not a CLI — imported by capture.py, verify.py, and backend services.
"""
import base64
import hashlib
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

_HKDF_INFO = b"vidproof-key-wrap"
_NONCE_SIZE = 12   # bytes; AES-GCM recommended nonce length
_TAG_SIZE = 16     # bytes; AES-GCM authentication tag length


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    """Return SHA-256 hex digest of a file, read in 1 MB streaming chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Return SHA-256 hex digest of in-memory bytes."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Ed25519 signing
# ---------------------------------------------------------------------------

def sign_plaintext_hash(hash_hex: str, privkey_pem_path: Path) -> str:
    """Sign the plaintext hash with the camera Ed25519 private key.

    Returns the signature as base64.
    Raises OSError if the key file cannot be read.
    Raises ValueError if the PEM is malformed.
    """
    pem = privkey_pem_path.read_bytes()
    private_key = load_pem_private_key(pem, password=None)
    message = bytes.fromhex(hash_hex)
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode()


def verify_ed25519_signature(hash_hex: str, signature_b64: str, public_key_b64: str) -> bool:
    """Verify an Ed25519 signature over a plaintext hash.

    Returns True if valid, False if signature does not match.
    Raises ValueError on malformed inputs.
    """
    from cryptography.exceptions import InvalidSignature
    public_key_bytes = base64.b64decode(public_key_b64)
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    message = bytes.fromhex(hash_hex)
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# AES-256-GCM encryption
# ---------------------------------------------------------------------------

def encrypt_aes_gcm(plaintext: bytes) -> tuple[bytes, bytes, str, str]:
    """Encrypt plaintext with AES-256-GCM using a fresh random key and nonce.

    Returns (aes_key_raw, ciphertext, nonce_b64, auth_tag_b64).
    The caller must wrap aes_key_raw immediately and not persist it in plaintext.
    The .enc file should contain only ciphertext (tag stored separately in evidence.json).
    """
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(_NONCE_SIZE)
    raw = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    # AESGCM.encrypt() returns ciphertext || tag (tag is always last 16 bytes)
    ciphertext = raw[:-_TAG_SIZE]
    auth_tag = raw[-_TAG_SIZE:]
    return (
        aes_key,
        ciphertext,
        base64.b64encode(nonce).decode(),
        base64.b64encode(auth_tag).decode(),
    )


def decrypt_aes_gcm(
    enc_path: Path,
    nonce_b64: str,
    auth_tag_b64: str,
    aes_key: bytes,
) -> bytes:
    """Decrypt an AES-256-GCM encrypted file.

    Raises cryptography.exceptions.InvalidTag if authentication fails
    (ciphertext or tag has been tampered with).
    """
    ciphertext = enc_path.read_bytes()
    nonce = base64.b64decode(nonce_b64)
    auth_tag = base64.b64decode(auth_tag_b64)
    # Reconstruct the ciphertext||tag format that AESGCM.decrypt expects
    raw = ciphertext + auth_tag
    return AESGCM(aes_key).decrypt(nonce, raw, None)


# ---------------------------------------------------------------------------
# X25519 key wrapping (ECDH + HKDF + AES-256-KW)
# ---------------------------------------------------------------------------

def wrap_aes_key(aes_key: bytes, owner_pubkey_b64: str) -> str:
    """Wrap a per-evidence AES key for the registered owner/investigator.

    Uses ephemeral X25519 ECDH → HKDF-SHA256 → AES-256-KW (RFC 3394).

    The returned base64 string encodes:
      ephemeral_pub_bytes[32] || wrapped_key_bytes[40]  =  72 bytes total

    The ephemeral public key must be stored alongside the wrapped key so the
    owner can reconstruct the shared secret during unwrapping.
    """
    owner_pub_bytes = base64.b64decode(owner_pubkey_b64)
    owner_pub = X25519PublicKey.from_public_bytes(owner_pub_bytes)

    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    shared_secret = ephemeral_priv.exchange(owner_pub)
    wrapping_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
        backend=default_backend(),
    ).derive(shared_secret)

    wrapped = aes_key_wrap(wrapping_key, aes_key, default_backend())
    # 32 bytes ephemeral pub + 40 bytes wrapped key = 72 bytes → 96 char base64
    payload = ephemeral_pub_bytes + wrapped
    return base64.b64encode(payload).decode()


def unwrap_aes_key(wrapped_key_b64: str, owner_privkey_pem_path: Path) -> bytes:
    """Unwrap a per-evidence AES key using the owner/investigator private key.

    Raises cryptography.hazmat.primitives.keywrap.InvalidUnwrap if the
    wrapped key has been tampered with.
    Raises OSError if the private key file cannot be read.
    """
    payload = base64.b64decode(wrapped_key_b64)
    ephemeral_pub_bytes = payload[:32]
    wrapped = payload[32:]

    pem = owner_privkey_pem_path.read_bytes()
    owner_priv = load_pem_private_key(pem, password=None)

    ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    shared_secret = owner_priv.exchange(ephemeral_pub)

    wrapping_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
        backend=default_backend(),
    ).derive(shared_secret)

    return aes_key_unwrap(wrapping_key, wrapped, default_backend())
