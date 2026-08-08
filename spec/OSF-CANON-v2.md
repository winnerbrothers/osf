# OSF-CANON v2 — Recommended Tag Construction

**Status:** recommended for new deployments · **v1 remains frozen** for byte-compatibility
with already-deployed systems (see [`OSF-CANON-v1.md`](./OSF-CANON-v1.md)).

---

## 1. What changed and why

v1 computes the tag as a raw hash keyed by placing the secret in the hash input:

```
v1:  tag = SHA-256( canonical(s_K(t)) ‖ nonce )
```

This works, but it has three practical weaknesses:

1. **Security argument leans on the random-oracle model.** The forgery bound is a ROM
   statement — an idealisation, not a standard-model assumption.
2. **No domain separation.** A tag minted for a login is byte-identical to one minted for
   a payment or a weapon command at the same instant, so a tag captured in one context
   could be presented in another.
3. **Custom use of a raw hash.** Reviewers and certification programmes push back on
   bespoke hash constructions; approved *constructions* (not just approved hashes) are
   what get validated.

v2 keeps the same secret — the OSF state `s_K(t)` — but routes it through a standard MAC:

```
v2:  key = canonical(s_K(t))                             # the secret, high entropy
     msg = "OSF-CANON-v2|<domain>|<t>|<nonce>|<aad>"     # public, domain-separated
     tag = HMAC-SHA-256(key, msg)                        # 64 lowercase hex chars
```

| | v1 | v2 |
|---|---|---|
| Security argument | ROM heuristic | **Standard-model PRF** — HMAC is a PRF whenever the compression function is (Bellare, CRYPTO 2006) |
| Length-extension class | avoided but pattern-risky | structurally impossible |
| Domain separation | none | built in (`auth` / `tx` / `cmd` / `chan`) |
| Approved construction | custom hash use | **HMAC-SHA-256 is approved under FIPS 140-3 and appears on Korea's KCMVP approved-algorithm list** |

That last row matters beyond aesthetics: cryptographic-module certification validates
**approved algorithms only**. A product presented as containing a *novel algorithm* is
disqualified on sight. OSF introduces no new primitive — it is a protocol over SHA-256,
HMAC-SHA-256 and ECDH — and v2 makes that structurally obvious to an evaluator.

## 2. Normative definition

```
V2_LABEL = "OSF-CANON-v2"

message(t, nonce, domain, aad) = V2_LABEL ‖ "|" ‖ domain ‖ "|" ‖ dec(t) ‖ "|" ‖ nonce ‖ "|" ‖ aad
tag(K, t, nonce, domain, aad)  = HMAC-SHA-256(
                                    key = canonical_preimage(s_K(t)),   # v1 §3, WITHOUT nonce
                                    msg = message(t, nonce, domain, aad)
                                 )
```

- `canonical_preimage(s_K(t))` is the **v1 canonical string with no nonce field** — the
  frozen encoding from `OSF-CANON-v1.md` §3. It is used here as HMAC key material.
- `dec(t)` is the timestamp in milliseconds, bare decimal integer.
- `domain` is a short ASCII string and **MUST NOT contain `|`**. Reserved: `auth`
  (entity authentication), `tx` (transaction signing), `cmd` (defense command),
  `chan` (channel/handshake binding).
- `aad` is optional additional authenticated data (e.g. a transaction or command hash);
  empty string when unused.
- Output: 64 lowercase hex characters. Verification MUST be constant-time.

## 3. Security statement

Forgery resistance is `min(λ, w)` where λ is the min-entropy of the serialized state
(≈159 bits conservatively; grid capacity 235.6 bits) and `w` is the tag width (256).
For a single OSF, λ = 159 < 256, so the tag width is not binding.

**Composition.** For `m` parallel OSFs the joint min-entropy is `mλ`, but an adversary may
also guess the tag directly, so the achievable security is `min(mλ, w)`. Reaching 318 bits
at `m = 2` therefore **requires widening the tag** — instantiate with HMAC-SHA-512
(`w = 512`), or emit `m` separate 256-bit tags that must all verify. HMAC-SHA-256 alone
caps any composition at 256 bits.

**Post-quantum.** Grover halves the exponent: ≈79 bits at `m = 1`, which is **below NIST
post-quantum Category 1** — a margin, not a guarantee. This concerns authentication only;
confidentiality via ECDH P-256 is classical and needs an ML-KEM hybrid.

## 4. Migration

v1 and v2 tags are unrelated byte-strings for the same inputs, by design. Peers must agree
on the version out of band or negotiate it. Systems already speaking v1 to a deployed
`/api/v1` server keep using v1; new deployments use v2.

```python
import osf, time
K = osf.keygen(int(time.time() * 1000))
t = int(time.time() * 1000)

osf.state_hash(K, t, nonce="n")            # v1 — compatibility
osf.tag(K, t, "n")                          # v2 — recommended, domain "auth"
osf.tag(K, t, "n", "tx", aad=tx_hash)       # v2 — transaction, bound to tx_hash
osf.verify_tag(K, t, "n", candidate)        # constant-time
```

## 5. Conformance

An implementation conforms to v2 iff, for the vectors in `kat/test-vectors.json`, the v1
canonical string it derives matches, and its HMAC-SHA-256 over the v2 message layout
matches a reference implementation. `python/tests/test_tag_v2.py` pins the message layout
(`OSF-CANON-v2|auth|123|NN|AAD`) and asserts domain separation.

---

Winner Brothers Group · inventor/applicant 이정훈 (LEE JUNGHOON) · PCT WO 2025/127469 A1 ·
PolyForm Noncommercial 1.0.0 (commercial license available).
