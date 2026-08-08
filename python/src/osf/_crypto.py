"""
Cryptographic primitives for OSF.

Hash/HMAC/CSPRNG use the Python standard library (byte-compatible with the
TS core, verified by KAT). AEAD (AES-256-GCM) and ECDH P-256 use the
`cryptography` package when present; if it is absent, only the
forward-secrecy / sealed-messaging features are unavailable — the OSF core,
login, coin, and defense-command paths remain fully functional on stdlib
alone.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import os
from typing import Optional, Tuple

try:  # optional: only needed for messaging forward-secrecy + sealed channel
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    _HAVE_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTOGRAPHY = False


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sign(key: bytes, data: str) -> str:
    """HMAC-SHA-256, hex. Matches planet-core hmacSign."""
    return _hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, data: str, signature_hex: str) -> bool:
    """Constant-time HMAC verification."""
    expected = hmac_sign(key, data)
    return _hmac.compare_digest(expected, signature_hex)


def random_nonce(byte_length: int = 32) -> str:
    """CSPRNG nonce as hex (os.urandom)."""
    return os.urandom(byte_length).hex()


def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)


# ---------------------------------------------------------------------------
# Optional AEAD + ECDH (forward secrecy). Guarded by _HAVE_CRYPTOGRAPHY.
# ---------------------------------------------------------------------------

def require_crypto() -> None:
    if not _HAVE_CRYPTOGRAPHY:
        raise RuntimeError(
            "This feature (sealed messaging / forward secrecy) requires the "
            "'cryptography' package.  Install with:  pip install cryptography"
        )


def aead_seal(key32: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """AES-256-GCM. Returns (iv, ciphertext_with_tag)."""
    require_crypto()
    iv = os.urandom(12)
    ct = AESGCM(key32).encrypt(iv, plaintext, aad)
    return iv, ct


def aead_open(key32: bytes, iv: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    require_crypto()
    return AESGCM(key32).decrypt(iv, ciphertext, aad)


def ecdh_generate() -> "ec.EllipticCurvePrivateKey":
    require_crypto()
    return ec.generate_private_key(ec.SECP256R1())


def ecdh_public_raw(priv) -> bytes:
    """Uncompressed SEC1 point (0x04 || X || Y), matches planet-core JWK x/y."""
    return priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def ecdh_shared(priv, peer_public_raw: bytes) -> bytes:
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public_raw)
    return priv.exchange(ec.ECDH(), peer)
