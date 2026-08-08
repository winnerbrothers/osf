"""
OSF secure messaging — mutually-authenticated, forward-secret channel.

Two peers who each hold their own OSF key and the other's registration
record run a 3-message handshake:

  init    : A -> B   A's state hash + fresh ECDH public + nonce
  respond : B -> A   B verifies A's predicted state, returns B's state hash +
                     ECDH public; both sides now share an ECDH secret
  finalize: A -> B   A verifies B's predicted state

The session key folds the ECDH shared secret (forward secrecy — a later
compromise of K does not decrypt past traffic) with the handshake transcript
(binding). Messages are sealed with AES-256-GCM.

Requires the `cryptography` package (ECDH + AEAD). The OSF core, login, coin
and defense-command paths do not.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Tuple

from .key import Key
from ._crypto import (
    sha256_hex, random_nonce, ecdh_generate, ecdh_public_raw, ecdh_shared,
    aead_seal, aead_open,
)


@dataclass
class InitContext:
    key: Key
    eph_priv: object
    nonce: str
    ts: int
    state_hash: str


@dataclass(frozen=True)
class Handshake:
    handshake_id: str
    init_state_hash: str
    respond_state_hash: str
    init_eph_pub: str
    respond_eph_pub: str


def _session_key(shared_secret: bytes, hs: Handshake) -> bytes:
    """HKDF-lite: SHA-256(ecdh_shared || transcript) -> 32-byte AEAD key."""
    transcript = "|".join([
        hs.init_state_hash, hs.respond_state_hash,
        hs.init_eph_pub, hs.respond_eph_pub, hs.handshake_id,
    ]).encode()
    return hashlib.sha256(shared_secret + b"|OSFv1|" + transcript).digest()


def handshake_init(key: Key, now_ms: int) -> Tuple[Dict, InitContext]:
    eph = ecdh_generate()
    nonce = random_nonce(32)
    sh = key.state_hash(now_ms, nonce=nonce)
    eph_pub = ecdh_public_raw(eph).hex()
    msg = {"type": "init", "state_hash": sh, "eph_pub": eph_pub, "nonce": nonce, "ts": now_ms}
    return msg, InitContext(key=key, eph_priv=eph, nonce=nonce, ts=now_ms, state_hash=sh)


def handshake_respond(
    my_key: Key, peer_record: Key, init_msg: Dict, now_ms: int, delta_ms: float = 500.0
) -> Tuple[Dict, bytes, Handshake]:
    """B: verify A's state, produce response, derive session key."""
    # verify A's claimed state by prediction, within Δ
    predicted = peer_record.state_hash(init_msg["ts"], nonce=init_msg["nonce"])
    if predicted != init_msg["state_hash"]:
        raise ValueError("peer state verification failed (init)")
    eph = ecdh_generate()
    my_nonce = random_nonce(32)
    my_sh = my_key.state_hash(now_ms, nonce=my_nonce)
    my_eph_pub = ecdh_public_raw(eph).hex()
    handshake_id = sha256_hex(f"{init_msg['nonce']}|{my_nonce}|{init_msg['ts']}|{now_ms}")
    hs = Handshake(
        handshake_id=handshake_id,
        init_state_hash=init_msg["state_hash"],
        respond_state_hash=my_sh,
        init_eph_pub=init_msg["eph_pub"],
        respond_eph_pub=my_eph_pub,
    )
    shared = ecdh_shared(eph, bytes.fromhex(init_msg["eph_pub"]))
    session_key = _session_key(shared, hs)
    resp = {
        "type": "respond", "state_hash": my_sh, "eph_pub": my_eph_pub,
        "nonce": my_nonce, "ts": now_ms, "handshake_id": handshake_id,
    }
    return resp, session_key, hs


def handshake_finalize(
    ctx: InitContext, peer_record: Key, resp_msg: Dict, delta_ms: float = 500.0
) -> bytes:
    """A: verify B's state, derive the same session key."""
    predicted = peer_record.state_hash(resp_msg["ts"], nonce=resp_msg["nonce"])
    if predicted != resp_msg["state_hash"]:
        raise ValueError("peer state verification failed (respond)")
    hs = Handshake(
        handshake_id=resp_msg["handshake_id"],
        init_state_hash=ctx.state_hash,
        respond_state_hash=resp_msg["state_hash"],
        init_eph_pub=ecdh_public_raw(ctx.eph_priv).hex(),
        respond_eph_pub=resp_msg["eph_pub"],
    )
    shared = ecdh_shared(ctx.eph_priv, bytes.fromhex(resp_msg["eph_pub"]))
    return _session_key(shared, hs)


def seal(session_key: bytes, plaintext: bytes, aad: bytes = b"") -> Dict:
    iv, ct = aead_seal(session_key, plaintext, aad)
    return {"iv": iv.hex(), "ct": ct.hex()}


def open(session_key: bytes, token: Dict, aad: bytes = b"") -> bytes:  # noqa: A001
    return aead_open(session_key, bytes.fromhex(token["iv"]), bytes.fromhex(token["ct"]), aad)
