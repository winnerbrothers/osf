# planet-osf

**OSF (Orbital State Function)** — a time-synchronized mutual-authentication
primitive you can call in one line, like `md5()`.

```bash
pip install planet-osf
```

```python
import osf, time

K = osf.keygen(int(time.time() * 1000))
tag = osf.state_hash(K, int(time.time() * 1000), nonce="challenge-abc")   # md5()-style
```

## Use-cases (one-line wrappers)

```python
from osf import login, messaging, coin, defense

# passwordless login (challenge/response)
ch    = login.login_challenge(now)
proof = login.login_prove(K, ch, now)
ok    = login.login_verify(K, ch, proof, now)

# transaction signing
sig = coin.sign_tx(K, {"from": "a", "to": "b", "amount": 42}, now)
coin.verify_tx(K, tx, sig, now)

# on-device weapon/UAV command auth (env-adaptive Δ, replay + clock-spoof reject)
defense.command_sign(session_key, "RTL", sender_state_hash, nonce, ts, cmd_id)

# forward-secret sealed channel (needs `pip install planet-osf[messaging]`)
token = messaging.seal(session_key, b"secret")
```

## "Try to break it"

```python
import osf
for r in osf.attack.run_all():
    print(r["attack"], "broke_osf =", r["broke_osf"])   # all False
```

Forgery, replay, MITM, state-recovery, and brute-force are all mounted and all
fail. This is the empirical half of the security argument; the analytic half is
a reduction to SHA-256/ECDH hardness (forgery advantage ≤ q_H·2⁻¹⁵⁹, ROM).
The forward-secrecy layer (ECDH P-256) is classical, not post-quantum — pair
with ML-KEM for that.

`planet-osf` is the pure-Python reference implementation of **OSF-CANON v1**,
byte-identical to the Rust core (`osf-core`), the PHP extension, and the
PyO3-accelerated wheel — all gated on one shared KAT.

## License — dual

- **Noncommercial** free under **PolyForm Noncommercial 1.0.0**.
- **Commercial / production** requires a separate license bundling the patent
  grant for **PCT WO 2025/127469 A1**. Contact: official@winnerbrothers.org

> Winner Brothers Group · inventor/applicant LEE JUNGHOON (이정훈).
