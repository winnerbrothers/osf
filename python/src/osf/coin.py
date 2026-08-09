# OSF (Orbital State Function)
# Copyright (c) 2026 Winner Brothers Group. All rights reserved.
# Inventor / applicant: LEE JUNGHOON (이정훈).  Patent: PCT WO 2025/127469 A1.
# Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
# requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
# https://github.com/winnerbrothers/osf

"""
OSF coin / transaction signing.

A transaction is signed by binding its canonical form into the OSF state:

    sig = H( s_K(t) || H(canonical(tx)) )

Verification recomputes the same tag from K and checks freshness within Δ.
This is pure OSF (SHA-256 only) — no separate signing key.

Trust model: SYMMETRIC. The verifier (a coin issuer / clearing node) holds
the signer's registration record. v1 does NOT provide public verifiability;
a permissionless ledger where any node verifies without the secret would
require an added commitment/zero-knowledge layer (roadmap). Represented
honestly so no over-claim is made.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict

from .key import Key
from ._crypto import sha256_hex, random_nonce


def canonical_tx(tx: Dict) -> str:
    """Deterministic transaction encoding (sorted keys, no spaces)."""
    return json.dumps(tx, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class TxSignature:
    ts: int
    nonce: str
    tx_hash: str
    sig: str

    def to_dict(self) -> Dict:
        return {"ts": self.ts, "nonce": self.nonce, "tx_hash": self.tx_hash, "sig": self.sig}


def sign_tx(key: Key, tx: Dict, now_ms: int) -> TxSignature:
    """Sign a transaction with an OSF key at time ``now_ms``."""
    tx_hash = sha256_hex(canonical_tx(tx))
    # bind tx_hash as the nonce input to the state hash, plus a fresh salt
    salt = random_nonce(16)
    bound_nonce = sha256_hex(f"{tx_hash}|{salt}")
    sig = key.state_hash(now_ms, nonce=bound_nonce)
    return TxSignature(ts=now_ms, nonce=salt, tx_hash=tx_hash, sig=sig)


def verify_tx(
    registered: Key,
    tx: Dict,
    signature: TxSignature,
    now_ms: int,
    delta_ms: float = 500.0,
) -> bool:
    """Verify a transaction signature (issuer holds the registration record)."""
    tx_hash = sha256_hex(canonical_tx(tx))
    if tx_hash != signature.tx_hash:
        return False  # transaction body was altered
    if abs(now_ms - signature.ts) > delta_ms:
        return False  # stale / out of window
    bound_nonce = sha256_hex(f"{tx_hash}|{signature.nonce}")
    expected = registered.state_hash(signature.ts, nonce=bound_nonce)
    if len(expected) != len(signature.sig):
        return False
    diff = 0
    for a, b in zip(expected, signature.sig):
        diff |= ord(a) ^ ord(b)
    return diff == 0
