# OSF API Reference

Complete reference for every public function in every binding.
Installation: [`INSTALL.md`](./INSTALL.md) · Canonical encoding: [`../spec/`](../spec/)

**Conventions**

- All timestamps are **milliseconds** since the Unix epoch (integers).
- All tags, hashes and keys crossing an API boundary are **lowercase hex strings**.
- A tag is **64 hex characters** (SHA-256 / HMAC-SHA-256 output).
- Verification is **constant-time** everywhere it compares a secret.
- `K` is a long-term secret. It is never transmitted. Isolate it (HSM / enclave) in
  production — see [`../SECURITY.md`](../SECURITY.md).

---

# Python

```python
import osf
```

## Quick reference

| Call | Purpose |
|---|---|
| `osf.keygen(t0)` | generate a key |
| `osf.tag(K, t, nonce)` | **v2 tag (recommended)** |
| `osf.verify_tag(K, t, nonce, cand)` | verify a v2 tag |
| `osf.state_hash(K, t, nonce)` | v1 tag (compatibility) |
| `osf.state(K, t)` | raw state (debugging) |
| `osf.login.*` | passwordless challenge/response |
| `osf.coin.*` | transaction signing |
| `osf.defense.*` | on-device command auth |
| `osf.messaging.*` | forward-secret sealed channel |
| `osf.attack.*` | public break-it harness |

---

## 1. Keys

### `osf.keygen(initial_timestamp_ms, shell_inner=1.0, shell_outer=1000.0) -> Key`

Generate a fresh key with CSPRNG parameters (`os.urandom`).

```python
import osf, time
K = osf.keygen(int(time.time() * 1000))
```

`p₀` is sampled from a **3-dimensional shell**, not a fixed-radius sphere — the
third degree of freedom is required for the stated output min-entropy. Do not
narrow `shell_inner`/`shell_outer` without recomputing the entropy budget.

### `class osf.Key`

Frozen dataclass. **Every field is secret.**

| Field | Type | Meaning |
|---|---|---|
| `coordinates` | `(float, float, float)` | `p₀` — initial position |
| `rotation_axis` | `(float, float, float)` | `â` — unit rotation axis |
| `angular_speed` | `float` | `ω` — degrees/second |
| `initial_timestamp` | `int` | `t₀` — epoch ms |

**Methods**

| Method | Returns | Notes |
|---|---|---|
| `K.state_at(t)` | `State` | raw state `s_K(t)` |
| `K.state_hash(t, nonce=None)` | `str` | v1 tag |
| `K.registration_record()` | `dict` | serialized `K` for the verifier — **SECRET** |
| `Key.from_record(rec)` | `Key` | restore from a record |

> **Trust model.** OSF v1/v2 are **symmetric**. The verifier stores the
> registration record and can therefore impersonate the prover. This is the same
> model as TOTP seeds — *not* public-key. Never call the record a "public key".
> Public verifiability is a roadmap item.

```python
record = K.registration_record()      # store server-side, protect like a TOTP seed
K2 = osf.Key.from_record(record)      # restore
```

---

## 2. Tags

### `osf.tag(key, timestamp_ms, nonce, domain="auth", aad="") -> str`  ⭐ recommended

**OSF-CANON v2.** `HMAC-SHA-256(key = canonical(s_K(t)), msg = "OSF-CANON-v2|domain|t|nonce|aad")`

```python
t = int(time.time() * 1000)
osf.tag(K, t, "challenge-abc")                       # domain "auth"
osf.tag(K, t, nonce, "tx", aad=tx_hash)              # bound to a transaction
```

`domain` separates contexts so a login tag can never be replayed as a payment or
a command. Reserved: `auth`, `tx`, `cmd`, `chan`. It must not contain `|`.
`aad` is optional additional authenticated data.

### `osf.verify_tag(key, timestamp_ms, nonce, candidate, domain="auth", aad="") -> bool`

Constant-time verification. **This does not check freshness** — compare
timestamps against your Δ yourself, or use `osf.login` / `osf.defense`, which do.

### `osf.state_hash(key, timestamp_ms, nonce=None) -> str`

**OSF-CANON v1.** `SHA-256(canonical(s_K(t)) ‖ nonce)`. Frozen for
byte-compatibility with already-deployed v1 systems. Prefer `osf.tag` for
anything new.

### `osf.state(key, timestamp_ms) -> State`

Raw state. `State` has `.position` (3-tuple), `.rotation` (4-tuple `w,x,y,z`),
`.timestamp`.

> ⚠️ **Never transmit raw states.** Three of them recover `K` in closed form.
> This function exists for debugging and test vectors.

### Module `osf.v2`

Lower-level access to the v2 construction.

| Function | Purpose |
|---|---|
| `v2.tag(key, t, nonce, domain, aad)` | same as `osf.tag` |
| `v2.verify(key, t, nonce, candidate, domain, aad)` | same as `osf.verify_tag` |
| `v2.tag_from_state(state, nonce, domain, aad)` | tag from a precomputed `State` |
| `v2.v2_message(t, nonce, domain, aad)` | the exact MAC'd message string |
| `v2.V2_LABEL` | `"OSF-CANON-v2"` |
| `v2.DOMAIN_AUTH / DOMAIN_TX / DOMAIN_CMD / DOMAIN_CHAN` | reserved domains |

---

## 3. Login — passwordless challenge/response

```python
from osf import login
from osf.key import Key

now = lambda: int(time.time() * 1000)

# --- enrollment (once) ---
K = osf.keygen(now())
record = K.registration_record()          # server stores this (secret)

# --- login ---
ch    = login.login_challenge(now())               # server → client
proof = login.login_prove(K, ch, now())            # client, holds K
ok    = login.login_verify(Key.from_record(record), ch, proof, now(), delta_ms=500)
```

| Function | Signature | Returns |
|---|---|---|
| `login_challenge` | `(now_ms)` | `Challenge(nonce, issued_at)` |
| `login_prove` | `(key, challenge, now_ms)` | `Proof(client_ts, tag, nonce)` |
| `login_verify` | `(registered, challenge, proof, now_ms, delta_ms=500.0)` | `bool` |

`Challenge` and `Proof` are frozen dataclasses with `.to_dict()` for transport.

`login_verify` checks, in order: the proof answers *this* challenge; the client
timestamp is within Δ of the challenge; the client timestamp is within Δ of
server-now; the tag matches (constant-time).

> **Not yet provided:** session issuance and revocation. `login_verify` returning
> `True` authenticates the request — minting a session cookie/token, its expiry,
> and logout are your application's responsibility. A session layer is a roadmap
> item.

---

## 4. Transactions

```python
from osf import coin

tx  = {"from": "alice", "to": "bob", "amount": 42, "asset": "PLNT"}
sig = coin.sign_tx(K, tx, now())
coin.verify_tx(Key.from_record(record), tx, sig, now(), delta_ms=500)   # True
```

| Function | Signature | Returns |
|---|---|---|
| `canonical_tx` | `(tx: dict)` | deterministic JSON (sorted keys, no spaces) |
| `sign_tx` | `(key, tx, now_ms)` | `TxSignature(ts, nonce, tx_hash, sig)` |
| `verify_tx` | `(registered, tx, signature, now_ms, delta_ms=500.0)` | `bool` |

`verify_tx` rejects if the transaction body changed, if it is outside Δ, or if
the tag does not match. Same symmetric trust model as §1 — the verifier is an
issuer/clearing node that holds the record, **not** a permissionless ledger.

---

## 5. Defense — on-device command authentication

Runs entirely on the device. No server round-trip.

```python
from osf import defense

dev = defense.Device("uav-01", "uav", "field", callsign="HAWK-1", hsm_attested=True)
sk  = defense.derive_session_key(init_sh, resp_sh, init_eph, resp_eph, "hs-1")

sig = defense.command_sign(sk, "RTL", sender_state_hash, nonce, ts, "cmd-1")
r   = defense.verify_command(dev, sk, "RTL", sender_state_hash, nonce, ts,
                             "cmd-1", sig, server_now_ms)
if not r.ok:
    print(r.reason, r.skew_ms, r.delta_ms)
```

### Δ by environment — `defense.DELTA_MS_BY_ENV`

| Environment | Δ | Typical use |
|---|---|---|
| `gps_disciplined` | 100 µs | PTP-synced satellite payload, GNSS |
| `datacenter` | 1 ms | single rack, MEC, GCS datacenter |
| `lan` | 10 ms | military LAN, KJCCS, tactical LAN |
| `field` | 50 ms | tactical field, drone GCS, EW |
| `satellite` | 100 ms | LEO/MEO/GEO to ground |
| `space` | 500 ms | deep space, GPS-denied |

> ⚠️ **Δ is a freshness window, not a distance bound.** Relay latency is usually
> under 10 ms, so relaying succeeds against `field`/`satellite`/`space`. Only the
> `gps_disciplined` setting meaningfully constrains a relay, and even then it is a
> clock check, not proof of proximity. Round-trip-time distance bounding is a
> roadmap item.

### Functions

| Function | Signature | Returns |
|---|---|---|
| `delta_ms` | `(environment)` | `float` — raises `ValueError` if unknown |
| `derive_session_key` | `(init_sh, resp_sh, init_eph, resp_eph, handshake_id)` | `str` — transcript binding |
| `command_sign` | `(session_key_hex, command, sender_state_hash, nonce, ts, cmd_id)` | `str` |
| `command_verify` | `(… , signature_hex)` | `bool` — MAC only |
| `verify_command` | `(device, session_key_hex, command, sender_state_hash, nonce, ts, cmd_id, signature_hex, server_now_ms)` | `VerifyResult` — **full pipeline** |
| `heartbeat` | `(device, device_ts_ms, server_now_ms)` | `HeartbeatResult(alive, drift_ms, within_delta)` |

`verify_command` runs four stages and stops at the first failure:

| Order | Check | `reason` on failure |
|---|---|---|
| 1 | device revoked | `device_revoked` |
| 2 | command id already seen | `replay_detected` |
| 3 | `|now − ts| ≤ Δ` | `clock_skew_exceeds_delta` |
| 4 | HMAC matches | `signature_invalid` |

The command id is recorded **only after full success**, so a failed attempt does
not burn the id.

### `class defense.Device`

| Field | Default | Meaning |
|---|---|---|
| `device_id` | — | identifier |
| `classification` | — | `gcs`/`uav`/`ugv`/`usv`/`satellite`/`weapon`/`sensor`/`soldier`/`vehicle` |
| `environment` | — | selects Δ |
| `callsign` | `""` | display name |
| `hsm_attested` | `False` | **a recorded claim, not enforcement** — it does not move `K` into hardware |
| `revoked` | `False` | rejects all commands when `True` |

Property `dev.delta_ms` returns Δ for its environment.

Wire-format compatible with the deployed `/api/v1/defense` server.

---

## 6. Messaging — forward-secret sealed channel

Requires `pip install "planet-osf[messaging]"`.

```python
from osf import messaging

init_msg, ctx        = messaging.handshake_init(alice, now())
resp, sk_bob, hs     = messaging.handshake_respond(bob, alice_record, init_msg, now())
sk_alice             = messaging.handshake_finalize(ctx, bob_record, resp)
assert sk_alice == sk_bob

token = messaging.seal(sk_alice, b"payload")
messaging.open(sk_bob, token)          # b"payload"
```

| Function | Signature | Returns |
|---|---|---|
| `handshake_init` | `(key, now_ms)` | `(msg: dict, ctx: InitContext)` |
| `handshake_respond` | `(my_key, peer_record, init_msg, now_ms, delta_ms=500.0)` | `(msg, session_key: bytes, Handshake)` |
| `handshake_finalize` | `(ctx, peer_record, resp_msg, delta_ms=500.0)` | `session_key: bytes` |
| `seal` | `(session_key, plaintext: bytes, aad=b"")` | `{"iv": hex, "ct": hex}` |
| `open` | `(session_key, token, aad=b"")` | `bytes` |

`handshake_respond` / `handshake_finalize` raise `ValueError` if the peer's state
prediction does not match — that is the authentication step. The session key is
`SHA-256(ecdh_shared ‖ "|OSFv1|" ‖ transcript)`, so it binds both the ECDH secret
and the full handshake.

> **Post-quantum scope.** Forward secrecy here uses **ECDH P-256** — classical,
> Shor-breakable. The authentication core is hash-based and unaffected, but
> harvested ciphertext is *not* safe against a future quantum adversary. Pair
> with ML-KEM where that matters.

---

## 7. Attack harness — "try to break it"

```python
for r in osf.attack.run_all():
    print(r["attack"], r["broke_osf"], r["detail"])
```

| Function | Signature | Attack |
|---|---|---|
| `attempt_forgery` | `(victim, trials=200_000)` | produce a valid tag without `K` |
| `attempt_replay` | `(victim)` | reuse a captured proof against a fresh challenge |
| `attempt_mitm` | `(session_key_hex)` | tamper with a signed command in flight |
| `attempt_state_recovery` | `(victim, observations=512)` | recover `K` from observed tags |
| `brute_force_cost` | `(hash_rate_per_sec=1e12)` | expected work to guess a 159-bit output |
| `run_all` | `(seed_ts=…)` | all of the above → `list[dict]` |

Each returns `AttackResult(attack, broke_osf, attempts, detail)`; `.as_dict()`
for JSON. **`broke_osf` must always be `False`** — the test suite asserts it, so
a regression that weakens OSF fails CI.

See the live challenge: <https://winnerbrothers.github.io/osf/>

---

## 8. Primitives and canonical encoding

| Function | Purpose |
|---|---|
| `osf.sha256_hex(s)` | SHA-256 of a string → hex |
| `osf.hmac_sign(key: bytes, data: str)` | HMAC-SHA-256 → hex |
| `osf.hmac_verify(key, data, sig_hex)` | constant-time verify |
| `osf.random_nonce(byte_length=32)` | CSPRNG nonce → hex |
| `osf.get_state_at(coords, axis, speed, t0, t)` | `s_K(t)` from raw parameters |
| `osf.canonical_preimage(state, nonce=None)` | the exact string that gets hashed |
| `osf.js_to_fixed_10(x)` | JavaScript `toFixed(10)`, byte-exact |

`canonical_preimage` and `js_to_fixed_10` exist so other implementations can be
checked against this one. See [`../spec/OSF-CANON-v1.md`](../spec/OSF-CANON-v1.md).

---

# Rust — `osf-core`

```rust
use osf_core::{state_hash, get_state_at, canonical_preimage, crypto, defense};

let tag = state_hash(
    [312.61, 618.95, -634.53],   // p₀
    [-0.716, 0.083, 0.693],      // â
    23667.67,                    // ω
    1_700_000_000_000,           // t₀
    1_700_000_005_000,           // t
    Some("nonce"),
);
```

| Item | Signature |
|---|---|
| `state_hash` | `(coords: Vec3, axis: Vec3, ω: f64, t0: i64, t: i64, nonce: Option<&str>) -> String` |
| `get_state_at` | `(coords, axis, ω, t0, t) -> State` |
| `canonical_preimage` | `(&State, Option<&str>) -> String` |
| `state::to_fixed_10` | `(f64) -> String` |
| `state::compute_rotation` | `(axis, ω, elapsed_s) -> Quat` |
| `crypto::sha256_hex` | `(&str) -> String` |
| `crypto::hmac_sha256_hex` | `(&[u8], &str) -> String` |
| `crypto::hmac_sha256_verify` | `(&[u8], &str, &str) -> bool` |
| `defense::delta_ms` | `(&str) -> Option<f64>` |
| `defense::derive_session_key` | `(&str, &str, &str, &str, &str) -> String` |
| `defense::command_sign` | `(&str, &str, &str, &str, i64, &str) -> String` |
| `defense::command_verify` | `(…, &str) -> bool` |
| `quaternion::{multiply, from_axis_angle, rotate_point}` | quaternion math |

Types: `Vec3 = [f64; 3]`, `Quat = [f64; 4]` (`w, x, y, z`), `State { position, rotation, timestamp }`.

---

# C ABI — `osf.h`

Link `libosf_core`. Every hash output is 64 hex chars + NUL; pass a buffer of at
least `OSF_OUT_LEN` (65) bytes.

```c
int  osf_state_hash(const double *coords, const double *axis,
                    double angular_speed, int64_t t0_ms, int64_t t_ms,
                    const char *nonce /* nullable */, char *out);

int  osf_command_sign(const char *session_key_hex, const char *command,
                      const char *sender_state_hash, const char *nonce,
                      int64_t ts_ms, const char *cmd_id, char *out);

int  osf_command_verify(const char *session_key_hex, const char *command,
                        const char *sender_state_hash, const char *nonce,
                        int64_t ts_ms, const char *cmd_id,
                        const char *signature_hex);   /* 1 valid, 0 invalid */

int  osf_delta_ms(const char *environment, double *out);
const char *osf_version(void);
```

| Constant | Value | Meaning |
|---|---|---|
| `OSF_OK` | 0 | success |
| `OSF_ERR_NULL` | −1 | null pointer or bad output length |
| `OSF_ERR_UTF8` | −2 | argument was not valid UTF-8 |
| `OSF_ERR_ENV` | −3 | unknown environment string |
| `OSF_HEX_LEN` | 64 | hex chars, excluding NUL |
| `OSF_OUT_LEN` | 65 | minimum `out` buffer size |

---

# PHP

Global functions, callable like `md5()`.

```php
$tag = osf_state_hash([1.0, 2.0, 3.0], [0.0, 0.0, 1.0], 90.0,
                      1700000000000, 1700000005000, "nonce");

if (osf_login_verify($coords, $axis, $omega, $t0,
                     $challengeNonce, $clientTs, $now, 500.0, $tag)) { /* ok */ }
```

| Function | Returns |
|---|---|
| `osf_state_hash(array $coords, array $axis, float $omega, int $t0, int $t, ?string $nonce)` | `string` |
| `osf_login_verify(array $coords, array $axis, float $omega, int $t0, string $nonce, int $clientTs, int $now, float $deltaMs, string $tag)` | `bool` |
| `osf_command_sign(string $sessionKeyHex, string $command, string $senderStateHash, string $nonce, int $ts, string $cmdId)` | `string` |
| `osf_command_verify(…, string $signatureHex)` | `bool` |
| `osf_delta_ms(string $environment)` | `float` — `0.0` if unknown |
| `osf_version()` | `string` |

> ⚠️ Float parameters do **not** accept PHP integers. Cast explicitly:
> `osf_state_hash($c, $a, floatval($omega), (int)$t0, (int)$t, $n)`.

---

# Error handling summary

| Binding | Convention |
|---|---|
| Python | raises `ValueError` (bad domain, failed handshake, unknown environment), `RuntimeError` (messaging without `cryptography`); verification returns `False` |
| Rust | `Option`/`bool`; `delta_ms` returns `None` for unknown environments |
| C | negative return codes (see table above) |
| PHP | `bool` for verification; `0.0` from `osf_delta_ms` for unknown environments |

---

Winner Brothers Group · inventor/applicant LEE JUNGHOON (이정훈) ·
PCT WO 2025/127469 A1 · PolyForm Noncommercial 1.0.0 (commercial license available).
