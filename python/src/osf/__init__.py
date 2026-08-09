"""
OSF — Orbital State Function. A time-synchronized mutual-authentication
primitive you can call in one line, like ``md5()``.

    import osf, time
    K = osf.keygen(int(time.time() * 1000))
    tag = osf.state_hash(K, int(time.time() * 1000), nonce="abc")

Higher-level, use-case wrappers hide the protocol:

    osf.login    — passwordless challenge/response
    osf.messaging— forward-secret sealed channel (needs `cryptography`)
    osf.coin     — transaction signing
    osf.defense  — on-device weapon/UAV command authentication
    osf.attack   — public "try to break it" harness

Reference implementation of OSF-CANON v1, validated byte-for-byte against the
planet-core TypeScript core (see tests/test_kat.py).

Rights: Winner Brothers Group · inventor/applicant 이정훈 (LEE JUNGHOON) ·
PCT WO 2025/127469 A1. Licensed PolyForm Noncommercial 1.0.0 (see LICENSE);
commercial/production use requires a separate license (LICENSE-COMMERCIAL.md).
"""
from __future__ import annotations

from ._canon import State, get_state_at, canonical_preimage, js_to_fixed_10
from .key import Key, keygen
from ._crypto import sha256_hex, hmac_sign, hmac_verify, random_nonce
from . import login, messaging, coin, defense, attack, v2, session, auth
from .v2 import tag, verify as verify_tag
from .auth import Authenticator

__version__ = "0.3.0"
__all__ = [
    "State", "Key", "keygen", "state", "state_hash",
    "tag", "verify_tag", "v2",
    "session", "auth", "Authenticator",
    "sha256_hex", "hmac_sign", "hmac_verify", "random_nonce",
    "login", "messaging", "coin", "defense", "attack",
    "get_state_at", "canonical_preimage", "js_to_fixed_10",
]


def state(key: "Key", timestamp_ms: int) -> "State":
    """Raw OSF state s_K(t). One-liner primitive."""
    return key.state_at(timestamp_ms)


def state_hash(key: "Key", timestamp_ms: int, nonce: str | None = None) -> str:
    """OSF-CANON **v1** tag: SHA-256(canonical(s_K(t)) || nonce).

    Kept for byte-compatibility with deployed v1 systems. New deployments
    should prefer :func:`osf.tag` (v2, HMAC-SHA-256) — see ``osf.tag``.
    """
    return key.state_hash(timestamp_ms, nonce)
