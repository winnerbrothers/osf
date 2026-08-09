# OSF (Orbital State Function)
# Copyright (c) 2026 Winner Brothers Group. All rights reserved.
# Inventor / applicant: LEE JUNGHOON (이정훈).  Patent: PCT WO 2025/127469 A1.
# Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
# requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
# https://github.com/winnerbrothers/osf

"""
`Authenticator` — the batteries-included way to use OSF for login.

`osf.login` and `osf.session` are the two halves: one proves possession of the
key, the other issues and revokes the bearer token that follows. This module
wires them together so an application deals with four calls:

    auth = Authenticator()                       # server, once at startup
    K, record = auth.enroll("alice")             # sign-up
    challenge = auth.challenge()                 # login step 1
    proof     = auth.prove(K, challenge)         # login step 2 (client side)
    token     = auth.login("alice", challenge, proof)   # login step 3
    who       = auth.whoami(token)               # every later request
    auth.logout(token)

Split of responsibilities, so this is not mistaken for more than it is:

* The **client** holds ``K`` and never sends it. ``prove`` is the only call
  that touches ``K`` and in a real deployment it runs on the client.
* The **server** holds the registration record and the session secret. Because
  the record *is* K, a server compromise lets the server impersonate the user —
  this is a symmetric scheme, like TOTP seeds, not public-key. Protect the
  record store accordingly (HSM/enclave where it matters).
* Records are held in memory here. Point ``records`` at your own mapping
  (dict-like: ``__getitem__``/``__setitem__``/``__contains__``/``pop``) to use a
  database instead.
"""
from __future__ import annotations

import time
from typing import Dict, MutableMapping, Optional, Tuple

from . import login as _login, session as _session
from .key import Key, keygen


def _now() -> int:
    return int(time.time() * 1000)


class Authenticator:
    """Server-side OSF login + session manager."""

    def __init__(
        self,
        server_secret: Optional[str] = None,
        records: Optional[MutableMapping[str, dict]] = None,
        store: Optional[_session.SessionStore] = None,
        delta_ms: float = 500.0,
        session_ttl_ms: int = _session.DEFAULT_TTL_MS,
    ) -> None:
        #: HMAC secret for session tokens. Persist it — regenerating logs everyone out.
        self.server_secret = server_secret or _session.new_secret()
        #: subject -> registration record. SECRET (each record is a key).
        self.records: MutableMapping[str, dict] = records if records is not None else {}
        self.store: _session.SessionStore = store or _session.MemorySessionStore()
        self.delta_ms = delta_ms
        self.session_ttl_ms = session_ttl_ms
        self._challenges: Dict[str, _login.Challenge] = {}

    # -- enrollment ---------------------------------------------------------

    def enroll(self, subject: str, now_ms: Optional[int] = None) -> Tuple[Key, dict]:
        """Create a key for ``subject`` and register it.

        Returns ``(key, record)``. Give the **key** to the client (it is their
        credential); the **record** is what this server stores. In a real
        deployment the client generates the key and sends only the record.
        """
        now = _now() if now_ms is None else now_ms
        key = keygen(now)
        record = key.registration_record()
        self.records[subject] = record
        return key, record

    def register_record(self, subject: str, record: dict) -> None:
        """Register a record produced by a client that generated its own key."""
        self.records[subject] = record

    def is_enrolled(self, subject: str) -> bool:
        return subject in self.records

    # -- login --------------------------------------------------------------

    def challenge(self, now_ms: Optional[int] = None) -> _login.Challenge:
        """Step 1 (server): issue a one-time challenge."""
        now = _now() if now_ms is None else now_ms
        ch = _login.login_challenge(now)
        self._challenges[ch.nonce] = ch
        return ch

    @staticmethod
    def prove(key: Key, challenge: _login.Challenge, now_ms: Optional[int] = None) -> _login.Proof:
        """Step 2 (client): answer the challenge with the key. Never sends K."""
        now = _now() if now_ms is None else now_ms
        return _login.login_prove(key, challenge, now)

    def login(
        self,
        subject: str,
        challenge: _login.Challenge,
        proof: _login.Proof,
        now_ms: Optional[int] = None,
    ) -> Optional[str]:
        """Step 3 (server): verify the proof and issue a session token.

        Returns the token, or ``None`` if authentication failed. The challenge
        is consumed either way, so a captured proof cannot be replayed.
        """
        now = _now() if now_ms is None else now_ms
        issued = self._challenges.pop(challenge.nonce, None)
        if issued is None:
            return None                      # unknown or already-used challenge
        record = self.records.get(subject)
        if record is None:
            return None
        if not _login.login_verify(
            Key.from_record(record), issued, proof, now, delta_ms=self.delta_ms
        ):
            return None
        return _session.issue(
            subject, now, self.server_secret, self.store, ttl_ms=self.session_ttl_ms
        )

    # -- session ------------------------------------------------------------

    def whoami(self, token: str, now_ms: Optional[int] = None) -> Optional[str]:
        """Return the subject for a valid token, else ``None``."""
        now = _now() if now_ms is None else now_ms
        s = _session.verify(token, now, self.server_secret, self.store)
        return s.subject if s else None

    def session(self, token: str, now_ms: Optional[int] = None) -> Optional[_session.Session]:
        """Full session details (id, subject, issued, expires) or ``None``."""
        now = _now() if now_ms is None else now_ms
        return _session.verify(token, now, self.server_secret, self.store)

    def refresh(self, token: str, now_ms: Optional[int] = None) -> Optional[str]:
        """Slide the expiry: returns a new token and invalidates the old one."""
        now = _now() if now_ms is None else now_ms
        return _session.refresh(
            token, now, self.server_secret, self.store, ttl_ms=self.session_ttl_ms
        )

    def logout(self, token: str) -> bool:
        """End this session. True if a live session was ended."""
        return _session.revoke(token, self.server_secret, self.store)

    def logout_everywhere(self, subject: str) -> int:
        """End every session for ``subject``. Returns how many were ended."""
        return _session.revoke_all(subject, self.store)

    # -- housekeeping -------------------------------------------------------

    def purge(self, now_ms: Optional[int] = None) -> int:
        """Drop expired sessions and stale challenges. Call periodically."""
        now = _now() if now_ms is None else now_ms
        stale = [n for n, c in self._challenges.items()
                 if now - c.issued_at > max(self.delta_ms * 4, 30_000)]
        for n in stale:
            del self._challenges[n]
        return self.store.purge_expired(now) + len(stale)
