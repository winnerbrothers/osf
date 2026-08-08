# OSF — Orbital State Function, callable in one line

Use OSF like `md5()`: install a native module, call a function, done. One
shared Rust core drives byte-identical bindings for **Python**, **PHP**, and
**C/embedded (weapons · UAV · satellite firmware)**.

```
pip install planet-osf              # Python  (PyPI)
pecl install osf                    # PHP     (native extension)
sudo add-apt-repository ppa:winnerbrothers/osf && sudo apt install php-osf
```

> Rights: **Winner Brothers Group** · inventor/applicant **이정훈 (LEE JUNGHOON)** ·
> **PCT WO 2025/127469 A1** · CC BY 4.0. `osf-core` is the single source of truth;
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
| raw primitive | `osf.state_hash(K,t,nonce)` | the `md5()`-equivalent |
| login | `osf.login.*` | passwordless challenge/response |
| messaging | `osf.messaging.*` | forward-secret sealed channel (ECDH P-256 + AES-256-GCM) |
| coin / tx | `osf.coin.sign_tx / verify_tx` | transaction signing |
| defense / weapons | `osf.defense.*` | on-device command auth: env-adaptive Δ (100µs–500ms), replay + clock-spoof rejection, HSM attest — **no server needed** |

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

## What is verified today vs. source-complete

| component | status |
|---|---|
| `kat/` ground-truth vectors from planet-core (120 state + 8 HMAC) | ✅ generated, self-checked |
| Python `planet-osf` — core, login, messaging, coin, defense, attack | ✅ **20/20 tests pass** (`python -m unittest`), `pip install` verified in a clean venv |
| OSF-CANON v1 determinism (Python == TS reference) | ✅ **120/120 hash-identical** |
| Rust `osf-core` (+ C ABI `osf.h`, `tests/kat.rs`) | 🟡 source complete — compiles + KAT-gates in CI (no Rust toolchain on the authoring box) |
| PyO3 wheel · PHP ext-php-rs extension | 🟡 source complete — built in CI (`.github/workflows/ci.yml`) |
| PECL / apt (PPA) / offline signed release | ⬜ packaging step (roadmap M4) |

Honest note: the Rust/PHP artifacts are written to compile and pass the same KAT
in CI; they were **not** compiled on the authoring machine (no Rust/PHP
toolchain there). The determinism proof and the full attack harness **do** run
today, in Python, against the deployed TS core's own output.

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
