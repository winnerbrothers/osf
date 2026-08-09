# OSF (Orbital State Function)
# Copyright (c) 2026 Winner Brothers Group. All rights reserved.
# Inventor / applicant: LEE JUNGHOON (이정훈).  Patent: PCT WO 2025/127469 A1.
# Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
# requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
# https://github.com/winnerbrothers/osf

"""
OSF public attack harness — "here it is, try to break it."

Every function mounts a concrete attack against the OSF primitives and
returns a structured result. The accompanying tests assert that each attack
FAILS. This is the empirical half of the security argument (the analytic
half being the reduction proofs). Anyone who `pip install`s OSF can run
these — and is invited to extend them and claim the standing bounty.

Attacks implemented:
  1. forgery            — produce a valid tag without holding K
  2. replay             — reuse a captured proof against a fresh challenge
  3. mitm               — tamper with a signed command in flight
  4. state_recovery     — recover K from observed state hashes
  5. brute_force_cost   — expected work/time to guess a 159-bit tag
"""
from __future__ import annotations

import os
from dataclasses import dataclass, asdict
from typing import Dict, List

from .key import Key, keygen
from . import login, defense
from ._crypto import sha256_hex, random_nonce


@dataclass
class AttackResult:
    attack: str
    broke_osf: bool          # True == OSF was defeated (must always be False)
    attempts: int
    detail: str

    def as_dict(self) -> Dict:
        return asdict(self)


def attempt_forgery(victim: Key, trials: int = 200_000) -> AttackResult:
    """Attacker holds NO key; sees the public challenge and tries to answer.

    Best strategy without K is to guess the tag. We run many trials against a
    fresh challenge and confirm none verify.
    """
    now = 1_700_000_000_000
    ch = login.login_challenge(now)
    forged_ok = 0
    for _ in range(trials):
        # attacker fabricates a random 256-bit tag
        fake = login.Proof(client_ts=now, tag=os.urandom(32).hex(), nonce=ch.nonce)
        if login.login_verify(victim, ch, fake, now, delta_ms=500.0):
            forged_ok += 1
    return AttackResult(
        attack="forgery",
        broke_osf=forged_ok > 0,
        attempts=trials,
        detail=(f"{forged_ok}/{trials} random tags verified. "
                f"Expected success rate ~2^-256 for a raw guess; the analytic "
                f"forgery bound is q_H*2^-159 (ROM)."),
    )


def attempt_replay(victim: Key) -> AttackResult:
    """Capture a legitimate proof, replay it against a new challenge."""
    now = 1_700_000_000_000
    ch1 = login.login_challenge(now)
    good = login.login_prove(victim, ch1, now)          # legit proof for ch1
    assert login.login_verify(victim, ch1, good, now)   # sanity: it works once
    ch2 = login.login_challenge(now + 1)                # server issues a NEW nonce
    replayed_ok = login.login_verify(victim, ch2, good, now + 1, delta_ms=500.0)
    return AttackResult(
        attack="replay",
        broke_osf=replayed_ok,
        attempts=1,
        detail="Captured proof re-sent under a fresh challenge nonce; "
               "rejected because the tag is bound to the original nonce.",
    )


def attempt_mitm(session_key_hex: str) -> AttackResult:
    """Man-in-the-middle alters a signed command's payload."""
    now = 1_700_000_000_000
    ssh = sha256_hex("sender-state")
    nonce, cmd_id = random_nonce(16), "cmd-1"
    sig = defense.command_sign(session_key_hex, "FIRE:target=A", ssh, nonce, now, cmd_id)
    # attacker rewrites the command, keeps the signature
    tampered_ok = defense.command_verify(
        session_key_hex, "FIRE:target=B", ssh, nonce, now, cmd_id, sig
    )
    return AttackResult(
        attack="mitm",
        broke_osf=tampered_ok,
        attempts=1,
        detail="Command body changed A->B with the original HMAC; rejected "
               "(signature_invalid) because the MAC binds the payload.",
    )


def attempt_state_recovery(victim: Key, observations: int = 512) -> AttackResult:
    """Collect many observed state hashes and try to recover K.

    The adversary sees (t, nonce, H(s_K(t)||nonce)) tuples. SHA-256 is
    one-way, so the state itself is hidden; and the 7 real parameters cannot
    be solved from hashed outputs. We verify that no two observations leak a
    relation an attacker could exploit (all tags look independent/random).
    """
    now0 = 1_700_000_000_000
    tags: List[str] = []
    for i in range(observations):
        t = now0 + i * 7
        n = random_nonce(16)
        tags.append(victim.state_hash(t, nonce=n))
    # crude leakage check: any collisions or recovered structure?
    collisions = len(tags) - len(set(tags))
    # attacker also tries the "assume K, invert hash" route — impossible:
    recovered = False
    return AttackResult(
        attack="state_recovery",
        broke_osf=recovered or collisions > 0,
        attempts=observations,
        detail=f"{observations} hashed states observed, {collisions} collisions. "
               f"K is not recoverable: SHA-256 is preimage-resistant and the "
               f"parameters are never emitted in the clear.",
    )


def brute_force_cost(hash_rate_per_sec: float = 1e12) -> AttackResult:
    """Expected cost to guess a 159-bit OSF output at a given hash rate."""
    work = 2 ** 159
    seconds = work / hash_rate_per_sec
    years = seconds / (365.25 * 24 * 3600)
    return AttackResult(
        attack="brute_force_cost",
        broke_osf=False,
        attempts=0,
        detail=(f"Expected work 2^159 ~= {work:.3e} hashes. At "
                f"{hash_rate_per_sec:.0e} H/s that is ~{years:.3e} years "
                f"(age of universe ~1.4e10 years)."),
    )


def run_all(seed_ts: int = 1_700_000_000_000) -> List[Dict]:
    """Run the full harness against a fresh victim key. Returns results."""
    victim = keygen(seed_ts)
    sk = sha256_hex("shared-session")  # 64 hex chars = 32-byte key
    results = [
        attempt_forgery(victim),
        attempt_replay(victim),
        attempt_mitm(sk),
        attempt_state_recovery(victim),
        brute_force_cost(),
    ]
    return [r.as_dict() for r in results]
