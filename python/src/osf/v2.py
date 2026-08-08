"""
OSF-CANON v2 — the recommended tag construction.

v1 computed ``SHA-256( canonical(s_K(t)) ‖ nonce )``: a raw hash keyed by
placing the secret directly in the hash input. It works, but its security
argument leans on the random-oracle model, it carries no domain separation,
and "custom use of a raw hash" is a pattern reviewers and certification bodies
push back on.

v2 keeps the same secret — the OSF state ``s_K(t)`` — but feeds it through a
standard MAC:

    key  = canonical_preimage(s_K(t))                 # the secret (high entropy)
    msg  = "OSF-CANON-v2|<domain>|<t>|<nonce>|<aad>"  # public, domain-separated
    tag  = HMAC-SHA-256(key, msg)

Why this is strictly better:

* **Standard-model proof.** HMAC is a PRF whenever the compression function is
  (Bellare, CRYPTO 2006) — no random-oracle idealisation required. The forgery
  bound therefore rests on a standard assumption instead of a heuristic.
* **No length-extension / raw-hash footgun.** HMAC's nested structure removes
  the whole class.
* **Domain separation.** A login tag can never be replayed as a transaction
  signature or a weapon command: the domain string is bound into every tag.
* **Approved construction.** HMAC-SHA-256 is an approved algorithm under FIPS
  140-3 (US) and appears on Korea's KCMVP approved-algorithm list — important
  because certification programmes validate *approved* algorithms only. OSF
  introduces no new cryptographic primitive; it is a protocol built on them.

v1 remains available (``osf.state_hash``) for byte-compatibility with already
deployed OSF-CANON v1 systems. New deployments should use v2.
"""
from __future__ import annotations

import hmac as _hmac
import hashlib
from typing import TYPE_CHECKING

from ._canon import State, canonical_preimage

if TYPE_CHECKING:  # pragma: no cover
    from .key import Key

#: Version label bound into every v2 message (domain separation across versions).
V2_LABEL = "OSF-CANON-v2"

#: Reserved domains. Any short ASCII string works; these are the built-ins.
DOMAIN_AUTH = "auth"      # entity authentication / login
DOMAIN_TX = "tx"          # transaction / coin signing
DOMAIN_CMD = "cmd"        # defense command authentication
DOMAIN_CHAN = "chan"      # channel / handshake binding


def v2_message(timestamp_ms: int, nonce: str, domain: str, aad: str = "") -> str:
    """The public, domain-separated message that gets MAC'd.

    ``aad`` is optional additional authenticated data (e.g. a transaction hash
    or a command payload hash) bound into the tag.
    """
    if "|" in domain:
        raise ValueError("domain must not contain '|'")
    return f"{V2_LABEL}|{domain}|{int(timestamp_ms)}|{nonce}|{aad}"


def tag_from_state(
    state: State, nonce: str, domain: str = DOMAIN_AUTH, aad: str = ""
) -> str:
    """OSF-CANON v2 tag from an already-computed state. Returns 64 hex chars."""
    key = canonical_preimage(state, None).encode("utf-8")   # the secret
    msg = v2_message(state.timestamp, nonce, domain, aad).encode("utf-8")
    return _hmac.new(key, msg, hashlib.sha256).hexdigest()


def tag(
    key: "Key", timestamp_ms: int, nonce: str, domain: str = DOMAIN_AUTH, aad: str = ""
) -> str:
    """OSF-CANON v2 tag for key ``K`` at time ``t``. The recommended primitive."""
    return tag_from_state(key.state_at(timestamp_ms), nonce, domain, aad)


def verify(
    key: "Key",
    timestamp_ms: int,
    nonce: str,
    candidate: str,
    domain: str = DOMAIN_AUTH,
    aad: str = "",
) -> bool:
    """Constant-time verification of a v2 tag."""
    expected = tag(key, timestamp_ms, nonce, domain, aad)
    return _hmac.compare_digest(expected, candidate)
