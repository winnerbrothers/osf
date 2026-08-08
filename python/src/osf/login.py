"""
OSF login — passwordless challenge/response authentication.

Replaces a shared password / TOTP secret with an OSF key. The verifier
(login server) stores the user's registration record at sign-up. At login
the server issues a random challenge; the client proves it holds K by
emitting H(s_K(t) || challenge_nonce); the server predicts the same state
and compares, within a freshness window Δ.

Security: an attacker who does not hold K cannot produce a valid tag except
by guessing the 159-bit output (forgery advantage <= q_H * 2^-159, ROM).
Replaying an old tag fails because the challenge nonce is fresh each time.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from .key import Key
from ._crypto import random_nonce


@dataclass(frozen=True)
class Challenge:
    nonce: str
    issued_at: int  # ms

    def to_dict(self) -> Dict:
        return {"nonce": self.nonce, "issued_at": self.issued_at}


@dataclass(frozen=True)
class Proof:
    client_ts: int
    tag: str
    nonce: str

    def to_dict(self) -> Dict:
        return {"client_ts": self.client_ts, "tag": self.tag, "nonce": self.nonce}


def login_challenge(now_ms: int) -> Challenge:
    """Server: issue a fresh challenge."""
    return Challenge(nonce=random_nonce(32), issued_at=now_ms)


def login_prove(key: Key, challenge: Challenge, now_ms: int) -> Proof:
    """Client: prove possession of K against the challenge."""
    tag = key.state_hash(now_ms, nonce=challenge.nonce)
    return Proof(client_ts=now_ms, tag=tag, nonce=challenge.nonce)


def login_verify(
    registered: Key,
    challenge: Challenge,
    proof: Proof,
    now_ms: int,
    delta_ms: float = 500.0,
) -> bool:
    """Server: verify a proof.

    Checks (1) the proof answers THIS challenge, (2) the client timestamp is
    fresh within Δ of both the challenge and server-now, (3) the predicted
    state tag matches.
    """
    if proof.nonce != challenge.nonce:
        return False
    if abs(proof.client_ts - challenge.issued_at) > delta_ms:
        return False
    if abs(now_ms - proof.client_ts) > delta_ms:
        return False
    expected = registered.state_hash(proof.client_ts, nonce=challenge.nonce)
    # constant-time compare
    if len(expected) != len(proof.tag):
        return False
    diff = 0
    for a, b in zip(expected, proof.tag):
        diff |= ord(a) ^ ord(b)
    return diff == 0
