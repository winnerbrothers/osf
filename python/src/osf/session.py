# OSF (Orbital State Function)
# Copyright (c) 2026 Winner Brothers Group. All rights reserved.
# Inventor / applicant: LEE JUNGHOON (이정훈).  Patent: PCT WO 2025/127469 A1.
# Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
# requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
# https://github.com/winnerbrothers/osf

"""
Session layer — what happens *after* authentication succeeds.

``osf.login`` proves that a client holds the key K. That is authentication, and
it is a single moment in time. A real application then needs a *session*: a
bearer token the client presents on later requests, with an expiry, a way to
log out, and a way to invalidate everything at once. This module provides that.

Design
------
A token is signed by the **server's** secret (not by K), so verification is a
constant-time HMAC check with no OSF evaluation and no database round-trip:

    token = "osf1.<sid>.<subject_b64>.<issued>.<expires>.<mac>"
    mac   = HMAC-SHA-256(server_secret, "osf1|sid|subject_b64|issued|expires")

Expiry is inside the signed payload, so an expired token is rejected without
any lookup. Revocation *does* need state, so a store holds the set of live
session ids; the default is in-process memory, and any object implementing
``SessionStore`` can replace it (Redis, SQL, a signed cookie jar).

This split is deliberate: the common path (verify a valid token) is O(1) with
no I/O, while logout and "log out everywhere" remain exact rather than
best-effort.

Security notes
--------------
* ``server_secret`` is a server-side secret independent of any user's K.
  Rotating it invalidates every session at once — that is the intended
  emergency lever. Generate with :func:`new_secret` and keep it out of source.
* Tokens are bearer credentials. Transmit over TLS, store in an
  ``HttpOnly``/``Secure``/``SameSite`` cookie, and never log them.
* ``verify`` is constant-time and never reveals *why* a token failed to the
  caller beyond ``None``; the reason is available via :func:`inspect` for
  server-side logging.
"""
from __future__ import annotations

import base64
import hmac as _hmac
import hashlib
import os
from dataclasses import dataclass, field
from typing import Dict, Optional, Protocol, Set

TOKEN_VERSION = "osf1"
DEFAULT_TTL_MS = 3_600_000  # 1 hour


# ---------------------------------------------------------------------------
# secrets
# ---------------------------------------------------------------------------

def new_secret(byte_length: int = 32) -> str:
    """Generate a server signing secret (hex). Store outside source control."""
    return os.urandom(byte_length).hex()


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------

class SessionStore(Protocol):
    """Minimal interface a session store must satisfy."""

    def add(self, sid: str, subject: str, expires_ms: int) -> None: ...
    def is_live(self, sid: str) -> bool: ...
    def drop(self, sid: str) -> None: ...
    def drop_subject(self, subject: str) -> int: ...
    def purge_expired(self, now_ms: int) -> int: ...


@dataclass
class MemorySessionStore:
    """In-process store. Fine for a single instance; swap for Redis when scaling."""

    _live: Dict[str, tuple] = field(default_factory=dict)  # sid -> (subject, expires_ms)

    def add(self, sid: str, subject: str, expires_ms: int) -> None:
        self._live[sid] = (subject, expires_ms)

    def is_live(self, sid: str) -> bool:
        return sid in self._live

    def drop(self, sid: str) -> None:
        self._live.pop(sid, None)

    def drop_subject(self, subject: str) -> int:
        gone = [s for s, (subj, _) in self._live.items() if subj == subject]
        for s in gone:
            del self._live[s]
        return len(gone)

    def purge_expired(self, now_ms: int) -> int:
        gone = [s for s, (_, exp) in self._live.items() if exp <= now_ms]
        for s in gone:
            del self._live[s]
        return len(gone)

    def __len__(self) -> int:
        return len(self._live)


# ---------------------------------------------------------------------------
# token
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Session:
    """A verified session."""
    sid: str
    subject: str
    issued_ms: int
    expires_ms: int

    def remaining_ms(self, now_ms: int) -> int:
        return max(0, self.expires_ms - now_ms)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _payload(sid: str, subject_b64: str, issued: int, expires: int) -> str:
    return f"{TOKEN_VERSION}|{sid}|{subject_b64}|{issued}|{expires}"


def _mac(secret_hex: str, payload: str) -> str:
    return _hmac.new(bytes.fromhex(secret_hex), payload.encode(), hashlib.sha256).hexdigest()


def issue(
    subject: str,
    now_ms: int,
    server_secret: str,
    store: Optional[SessionStore] = None,
    ttl_ms: int = DEFAULT_TTL_MS,
) -> str:
    """Mint a session token for ``subject``. Call this after ``login_verify``."""
    if ttl_ms <= 0:
        raise ValueError("ttl_ms must be positive")
    sid = os.urandom(16).hex()
    subject_b64 = _b64(subject.encode())
    expires = int(now_ms) + int(ttl_ms)
    payload = _payload(sid, subject_b64, int(now_ms), expires)
    token = f"{payload.replace('|', '.')}.{_mac(server_secret, payload)}"
    if store is not None:
        store.add(sid, subject, expires)
    return token


def inspect(
    token: str,
    now_ms: int,
    server_secret: str,
    store: Optional[SessionStore] = None,
) -> tuple[Optional[Session], Optional[str]]:
    """Verify a token, returning ``(session, reason)``.

    Exactly one of the two is non-None. ``reason`` is for server-side logs —
    do not return it to the client.
    """
    parts = token.split(".")
    if len(parts) != 6 or parts[0] != TOKEN_VERSION:
        return None, "malformed"
    _, sid, subject_b64, issued_s, expires_s, mac = parts
    try:
        issued, expires = int(issued_s), int(expires_s)
    except ValueError:
        return None, "malformed"

    expected = _mac(server_secret, _payload(sid, subject_b64, issued, expires))
    if not _hmac.compare_digest(expected, mac):
        return None, "bad_signature"
    if now_ms >= expires:
        return None, "expired"
    if store is not None and not store.is_live(sid):
        return None, "revoked"
    try:
        subject = _unb64(subject_b64).decode()
    except Exception:
        return None, "malformed"
    return Session(sid=sid, subject=subject, issued_ms=issued, expires_ms=expires), None


def verify(
    token: str,
    now_ms: int,
    server_secret: str,
    store: Optional[SessionStore] = None,
) -> Optional[Session]:
    """Verify a token. Returns the `Session`, or ``None`` if it is not valid."""
    session, _ = inspect(token, now_ms, server_secret, store)
    return session


def refresh(
    token: str,
    now_ms: int,
    server_secret: str,
    store: Optional[SessionStore] = None,
    ttl_ms: int = DEFAULT_TTL_MS,
) -> Optional[str]:
    """Exchange a still-valid token for a fresh one (sliding expiry).

    The old session id is dropped, so a stolen copy of the previous token stops
    working the moment the legitimate client refreshes.
    """
    session = verify(token, now_ms, server_secret, store)
    if session is None:
        return None
    if store is not None:
        store.drop(session.sid)
    return issue(session.subject, now_ms, server_secret, store, ttl_ms)


def revoke(token: str, server_secret: str, store: SessionStore) -> bool:
    """Log out. Returns True if a live session was ended."""
    parts = token.split(".")
    if len(parts) != 6 or parts[0] != TOKEN_VERSION:
        return False
    _, sid, subject_b64, issued_s, expires_s, mac = parts
    # verify the signature so an attacker cannot revoke arbitrary session ids
    if not _hmac.compare_digest(
        _mac(server_secret, _payload(sid, subject_b64, issued_s, expires_s)), mac
    ):
        return False
    live = store.is_live(sid)
    store.drop(sid)
    return live


def revoke_all(subject: str, store: SessionStore) -> int:
    """Log a subject out everywhere. Returns how many sessions were ended."""
    return store.drop_subject(subject)
