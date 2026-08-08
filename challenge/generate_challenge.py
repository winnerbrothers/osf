"""
OSF public forgery challenge — generator (run OFFLINE by the challenge author).

Produces a fully static, stateless, auto-verifiable forgery challenge:

  * Pick a fresh secret key K (never published until the challenge ends).
  * Publish N "observed" authentication transcripts {t_i, n_i, tag_i} — exactly
    what a network eavesdropper would see (tag_i = H(s_K(t_i) || n_i)).
  * Publish a fresh challenge (t*, n*) and ONLY commit_tag = SHA-256(tag*).
    The correct tag* and K stay secret.
  * A solver wins by producing tag* (forging the next valid auth from the
    transcripts alone). The browser verifies SHA-256(submission) == commit_tag
    — no server, no secret at runtime.
  * commit_K = SHA-256(canonical K) is published up front so the author cannot
    swap K later; K is revealed when the challenge ends and everyone can then
    recompute every transcript + tag* to confirm the challenge was honest.

Dogfoods the published package:  pip install planet-osf

Outputs:
  challenge.json   (PUBLIC — committed)
  secret.json      (SECRET — gitignored; the author keeps this)
"""
import json
import os
import time
import hashlib

import osf
from osf.key import Key

N_TRANSCRIPTS = 128
DELTA_MS = 500  # window the auth would use; informational for the challenge


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def canonical_k(K: Key) -> str:
    # stable, sorted encoding of the key params for the K-commitment
    return json.dumps(K.registration_record(), sort_keys=True, separators=(",", ":"))


def main() -> None:
    base = int(time.time() * 1000)
    K = osf.keygen(base)

    # N observed transcripts (what an eavesdropper collects over time)
    transcripts = []
    for i in range(N_TRANSCRIPTS):
        t = base + i * 37_000 + (int.from_bytes(os.urandom(2), "big"))  # spread over time
        n = os.urandom(32).hex()
        tag = osf.state_hash(K, t, nonce=n)
        transcripts.append({"t": t, "n": n, "tag": tag})

    # the fresh forgery target — tag* is NOT published, only its commitment
    t_star = base + N_TRANSCRIPTS * 37_000 + 12_345
    n_star = os.urandom(32).hex()
    tag_star = osf.state_hash(K, t_star, nonce=n_star)

    challenge = {
        "spec": "OSF forgery challenge v1",
        "package": "planet-osf",
        "rules_url": "./README.md",
        "delta_ms": DELTA_MS,
        "commit_k": sha256_hex(canonical_k(K)),      # tamper-evidence (K revealed at end)
        "transcripts": transcripts,                   # {t, n, tag} eavesdropped auths
        "challenge": {"t": t_star, "n": n_star},      # forge the tag for THIS (t*, n*)
        "commit_tag": sha256_hex(tag_star),           # win iff SHA-256(your tag) == this
        "note": (
            "Produce the OSF tag for (challenge.t, challenge.n) using ONLY the "
            "published transcripts. Submit it; the page verifies "
            "SHA-256(submission) == commit_tag entirely client-side."
        ),
    }

    secret = {
        "k": K.registration_record(),
        "canonical_k": canonical_k(K),
        "tag_star": tag_star,
        "t_star": t_star,
        "n_star": n_star,
    }

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "challenge.json"), "w", encoding="utf-8") as f:
        json.dump(challenge, f, indent=2)
    with open(os.path.join(here, "secret.json"), "w", encoding="utf-8") as f:
        json.dump(secret, f, indent=2)

    print(f"wrote challenge.json ({N_TRANSCRIPTS} transcripts) + secret.json (KEEP PRIVATE)")
    print(f"commit_tag = {challenge['commit_tag']}")
    print(f"commit_k   = {challenge['commit_k']}")
    # sanity: verifier logic
    assert sha256_hex(secret["tag_star"]) == challenge["commit_tag"]
    print("self-check OK: SHA-256(tag*) == commit_tag")


if __name__ == "__main__":
    main()
