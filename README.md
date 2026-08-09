# OSF — Orbital State Function, callable in one line

A **time-synchronized mutual authentication protocol** you can call like `md5()`.
One shared Rust core drives byte-identical bindings for **Python**, **PHP**, and
**C/embedded** (UAV · satellite · weapon firmware).

```bash
pip install planet-osf     # Python (PyPI serves 0.1.0 — see the note below)
```

> ⚠️ The published PyPI build is **0.1.0**, which predates the session layer and
> the v2 tag. To use everything shown here, run from this checkout:
> `pip install -e ./python` (or set `PYTHONPATH=$PWD/python/src`).
> See [Quickstart](./docs/QUICKSTART.md).

```python
import osf, time
K   = osf.keygen(int(time.time() * 1000))              # generate a key
tag = osf.tag(K, int(time.time() * 1000), "challenge") # authenticate. one line.
```

Passwordless login with a real session — the whole flow:

```python
from osf.auth import Authenticator
auth = Authenticator()

client_key, record = auth.enroll("alice")               # sign-up
challenge = auth.challenge()                            # server
proof     = Authenticator.prove(client_key, challenge)  # client (holds the key)
token     = auth.login("alice", challenge, proof)       # server -> session token

auth.whoami(token)                # 'alice'
auth.logout(token)                # session ends
auth.logout_everywhere("alice")   # every session ends
```

Same thing in PHP — **pure PHP, no extension, no Composer**:

```php
require 'osf.php';
[$key, $record] = $auth->enroll('alice');
$token = $auth->login('alice', $ch, OSF\Auth::prove($key, $ch));
$auth->whoami($token);   // 'alice'
$auth->logout($token);
```

Run a working login site right now:

```bash
python examples/python/quickstart.py                # the full tour
python examples/python/web_login.py                 # http://localhost:8421
php    examples/php/quickstart.php                  # same tour, PHP
php -S localhost:8422 examples/php/web_login.php    # login site, PHP
```

📖 **[Quickstart](./docs/QUICKSTART.md)** · **[Full API reference](./docs/API.md)** ·
[Installation](./docs/INSTALL.md) · [Spec](./spec/OSF-CANON-v2.md) ·
[Security model](./SECURITY.md) · [Break-it challenge](https://winnerbrothers.github.io/osf/)

| Target | Status |
|---|---|
| Python — `pip install planet-osf` | 🟡 PyPI at 0.1.0; session/v2 need this checkout |
| Rust — `osf-core` crate | ✅ source |
| C / C++ / embedded — `osf.h` | ✅ source |
| PHP extension — `extension=osf.so` | 🟡 builds in CI, build from source |
| `pecl install osf` · `apt install php-osf` | ⬜ planned |

> Rights: **Winner Brothers Group** · inventor/applicant **이정훈 (LEE JUNGHOON)** ·
> **PCT WO 2025/127469 A1** · **PolyForm Noncommercial 1.0.0** — free for
> noncommercial use; **commercial/production use needs a separate license**
> ([LICENSE-COMMERCIAL.md](./LICENSE-COMMERCIAL.md), [PATENTS.md](./PATENTS.md)).
> `osf-core` is the single source of truth;
> the registration record is a **secret** (OSF v1 is a symmetric primitive — see
> the trust-model notes, not a public-key scheme).

---

## One-liners

**Python**
```python
import osf, time
K = osf.keygen(int(time.time()*1000))
tag = osf.state_hash(K, int(time.time()*1000), nonce="challenge-abc")   # like md5()
ok  = osf.login.login_verify(K, ch, proof, now)                          # passwordless
```

**PHP** (global functions, like `md5()`)
```php
$tag = osf_state_hash([1.0,2.0,3.0], [0.0,0.0,1.0], 90.0,
                      1700000000000, 1700000005000, "challenge-abc");
if (osf_login_verify($coords,$axis,$w,$t0,$nonce,$clientTs,$now,500.0,$tag)) { /* in */ }
```

**C / firmware**
```c
#include "osf.h"
char out[OSF_OUT_LEN];
osf_state_hash(coords, axis, 90.0, 1700000000000, 1700000005000, "abc", out);
```

## Five use-cases, each a one-line wrapper

| use-case | Python | what it does |
|---|---|---|
| **tag (recommended)** | `osf.tag(K,t,nonce,domain)` | **OSF-CANON v2** — HMAC-SHA-256, domain-separated |
| raw tag (v1, compat) | `osf.state_hash(K,t,nonce)` | the `md5()`-equivalent; byte-compatible with deployed v1 |
| login | `osf.login.*` | passwordless challenge/response |
| messaging | `osf.messaging.*` | forward-secret sealed channel (ECDH P-256 + AES-256-GCM) |
| coin / tx | `osf.coin.sign_tx / verify_tx` | transaction signing |
| defense / weapons | `osf.defense.*` | on-device command auth: env-adaptive Δ (100µs–500ms), replay + clock-spoof rejection, HSM attest — **no server needed** |

## What OSF is (and is not)

OSF is a **time-synchronized mutual authentication protocol** built on standard
primitives — SHA-256, HMAC-SHA-256, ECDH. It is **not** a cipher, **not** encryption, and
**not** a new cryptographic primitive: it introduces no new hardness assumption, and we
say so in the paper (we even prove the quaternion map is invertible from raw states, which
is exactly why raw states are never transmitted). Security reduces jointly to the
one-wayness of the hash and the entropy of the key.

Its contribution is at the protocol layer, in the same sense that TLS 1.3 and Signal
contribute architecture rather than primitives:

- **mutual** authentication (TOTP is one-way)
- **no secret is ever transmitted** — neither the key nor its function value
- **authentication parameters are not written to server persistent storage**, so a disk /
  DB / backup breach does not enable impersonation (a live-memory compromise is a
  different matter — see [SECURITY.md](./SECURITY.md); HSM isolation recommended)
- **continuous time** with an environment-adaptive window Δ (100 µs – 500 ms)
- **serverless P2P** operation
- forgery resistance ≈**159 bits** (conditional bound; grid capacity 235.6 bits)

Two constructions ship: **v1** (`SHA-256(state ‖ nonce)`, frozen for compatibility) and
**v2** (`HMAC-SHA-256`, domain-separated — [spec](./spec/OSF-CANON-v2.md)). v2 is
recommended: its PRF security is a standard-model assumption rather than a random-oracle
heuristic, and HMAC-SHA-256 is an *approved construction* under FIPS 140-3 and Korea's
KCMVP — which matters, because certification programmes validate approved algorithms only.

## "Prove nobody can break it" — two honest halves

Absolute unbreakability is not provable for *any* cipher (AES/SHA-256 included);
claiming it destroys credibility. OSF ships the two forms that *are* defensible:

1. **Reduction proofs (analytic).** Breaking OSF ⇒ breaking SHA-256/ECDH under
   stated assumptions. Forgery advantage ≤ q_H·2⁻¹⁵⁹ (ROM). Caveat, stated
   plainly: the forward-secrecy layer uses ECDH P-256 (classical DDH) and is
   **not** post-quantum — pair with ML-KEM for that. Peer review via IACR ePrint.
2. **Public attack survival (empirical).** `osf.attack` bundles the break-it
   harness — forgery, replay, MITM, state-recovery, brute-force cost — so anyone
   who installs OSF can *try*. Every attack is asserted to fail in CI. A standing
   public challenge + bounty turns "trust me" into "here, reproduce it."

```python
for r in osf.attack.run_all():
    print(r["attack"], "broke_osf =", r["broke_osf"])   # all False
```

## Verification status

All bindings are gated on one shared KAT (`kat/test-vectors.json`) and pass in
CI ([GitHub Actions](.github/workflows/ci.yml) — run green across the matrix):

| component | status |
|---|---|
| `kat/` ground-truth vectors from planet-core (120 state + 8 HMAC) | ✅ generated, self-checked |
| Python `planet-osf` — core, login, **session/auth**, messaging, coin, defense, attack | ✅ **53/53 tests pass** (Python 3.9 / 3.11 / 3.13 in CI), incl. session/auth |
| OSF-CANON v1 determinism (Python == TS reference) | ✅ **120/120 hash-identical** |
| Rust `osf-core` (+ C ABI `osf.h`, `tests/kat.rs`) | ✅ **`cargo test` KAT-gate green in CI** — 120/120 byte-identical, C ABI cdylib/staticlib build |
| PyO3 native wheel | ✅ **built + KAT smoke green in CI** (byte-identical to the reference) |
| PHP `ext-php-rs` extension (`osf.so`) | ✅ **builds, loads, KAT smoke green in CI** — `osf_state_hash()` global fn matches |
| PECL / apt (PPA) / offline signed release | ⬜ packaging step (roadmap M4) |

Cross-implementation byte-identity (TS ↔ Rust ↔ Python ↔ PyO3 ↔ PHP) is
therefore CI-verified on Linux. Remaining work is packaging/distribution
(PyPI/PECL/apt) and the public challenge server — not correctness.

## Layout
```
spec/OSF-CANON-v1.md     canonical encoding (frozen) + determinism findings
kat/                     generate_kat.mjs + test-vectors.json (single arbiter)
python/                  planet-osf (pure-Python reference + PyPI fallback)
rust/                    osf-core crate — source of truth + C ABI (osf.h)
pyo3/                    native-accelerated Python wheel (maturin)
php/                     ext-php-rs extension (osf.so → pecl/apt)
.github/workflows/ci.yml every binding gated on the shared KAT
```

## Build / test locally
```bash
# Python (works now, no network):
cd python && python -m unittest discover -s tests -v

# Regenerate KAT from the TS reference:
node kat/generate_kat.mjs > kat/test-vectors.json

# Rust core (needs a Rust toolchain):
cd rust && cargo test --all-features
```

## License

Dual-licensed:

- **Noncommercial** — free under **PolyForm Noncommercial 1.0.0**
  ([LICENSE](./LICENSE)). Individuals, hobbyists, researchers, education,
  government/nonprofit. Includes a patent license for noncommercial use.
- **Commercial / production** — requires a **separate commercial license**
  that bundles the patent grant for **PCT WO 2025/127469 A1**. See
  [LICENSE-COMMERCIAL.md](./LICENSE-COMMERCIAL.md) and [PATENTS.md](./PATENTS.md).
  Request one via the
  [commercial license issue form](https://github.com/winnerbrothers/osf/issues/new?template=commercial-license.yml)
  or official@winnerbrothers.org.

**Security:** OSF's security rests on the secret key. Default key storage is
plaintext process memory (not an HSM) and the forward-secrecy layer is
classical, not post-quantum — read [SECURITY.md](./SECURITY.md) before
deploying. Vulnerability reports: see SECURITY.md.

Copyright and patent are separate rights: a permissive copyright license would
not by itself grant the right to practice the patent commercially — hence the
explicit split above.
