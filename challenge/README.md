# OSF Public Forgery Challenge

**Break OSF: forge one authentication tag without the key.**

OSF authenticates with a secret key `K = (p₀, â, ω, t₀)`. At time `t` it emits
a tag `H(s_K(t) ‖ nonce)`. The algorithm is fully open — security rests only on
`K` being secret (Kerckhoffs's principle). This challenge tests the core claim:
**observing past tags must not let you forge the next one** (transcript
unforgeability / indistinguishability).

Live page: **https://winnerbrothers.github.io/osf/**

## What is published (`challenge.json`)

| field | meaning |
|---|---|
| `transcripts[]` | 128 genuine `{t, n, tag}` triples — `tag = osf.state_hash(K, t, n)` for one fixed secret `K`. This is exactly what a network eavesdropper sees. |
| `challenge.{t,n}` | the fresh target `(t*, nonce*)` you must forge a tag for |
| `commit_tag` | `SHA-256(tag*)` — the win condition. `tag*` itself is secret. |
| `commit_k` | `SHA-256(canonical K)` — published up front so the key cannot be swapped later |

## How to win

Produce `tag*` = the OSF tag for `(challenge.t, challenge.n)` using **only** the
published transcripts (i.e. without `K`). Then either:

- paste it into the live page — your browser verifies `SHA-256(tag*) == commit_tag`, or
- verify locally:
  ```bash
  python -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" <your_tag>
  # equals commit_tag  ->  you forged it
  ```

A brute-force guess of a 256-bit value is infeasible, so a match means you
predicted `s_K(t*)` from the transcripts — i.e. you broke OSF.

## Claiming

Open a GitHub issue titled **`SOLVED`** containing:

1. your `tag*`,
2. a short write-up of the method (so others can reproduce),
3. optionally, the recovered `K` if you found it.

We verify against `commit_tag` and add you to
[`HALL_OF_FAME.md`](./HALL_OF_FAME.md) with public credit.

## Reward

**v1 = the wall** (Hall of Fame + public credit). Cash bounty tiers may follow.

## Honesty guarantees

- `commit_k` fixes the key before anyone plays. When the challenge ends (or is
  solved) we publish `K`; anyone can then recompute **every** transcript and
  `tag*` and confirm the challenge was generated honestly from one real key.
- The generator is open: [`generate_challenge.py`](./generate_challenge.py).
- No server, no telemetry — verification is 100% client-side math.

## Scope

This tests the OSF primitive as published in `planet-osf`. It does **not**
authorize attacks against any live system or service.

---

Winner Brothers Group · inventor/applicant LEE JUNGHOON (이정훈) · PCT WO 2025/127469 A1.
Code dual-licensed (PolyForm Noncommercial + commercial) — see repo `LICENSE`.
