# Quickstart — login, logout, and everything else in 5 minutes

Copy-paste runnable. Every snippet below was executed exactly as written.

Full reference: [`API.md`](./API.md) · Install details: [`INSTALL.md`](./INSTALL.md)

---

## Python

### Install and run the tour

```bash
pip install planet-osf
python examples/python/quickstart.py
```

That prints working demonstrations of all six areas: the one-liner, login +
session, the failure cases, transaction signing, defense command auth, and the
break-it harness.

### Login and logout — the whole thing

```python
import osf
from osf.auth import Authenticator

auth = Authenticator()                       # server, once at startup

# --- sign-up ---------------------------------------------------------------
client_key, record = auth.enroll("alice")    # client keeps the key, server the record

# --- login (3 steps) -------------------------------------------------------
challenge = auth.challenge()                            # 1. server issues a challenge
proof     = Authenticator.prove(client_key, challenge)  # 2. client proves (holds K)
token     = auth.login("alice", challenge, proof)       # 3. server verifies -> session

# --- use the session -------------------------------------------------------
auth.whoami(token)          # 'alice'
auth.session(token)         # Session(sid=..., subject='alice', issued_ms=..., expires_ms=...)
auth.refresh(token)         # new token, old one dies (sliding expiry)

# --- logout ----------------------------------------------------------------
auth.logout(token)          # this session
auth.whoami(token)          # None
auth.logout_everywhere("alice")   # every session for alice
```

That is the complete flow. No password is typed, stored, or transmitted; the
key never leaves the client.

### Run a real login site

```bash
python examples/python/web_login.py          # http://localhost:8421
```

Standard library only — no Flask, no Django. Sign up, log in, check the
session, log out, all in the browser. Port is configurable:
`python web_login.py 9000`.

### Wire it into your own app

```python
# on every protected request
def current_user(request):
    token = request.cookies.get("osf_session")
    return auth.whoami(token) if token else None

# after a successful login
response.set_cookie(
    "osf_session", token,
    httponly=True, secure=True, samesite="Strict",
    max_age=auth.session(token).remaining_ms(now) // 1000,
)
```

Point the `Authenticator` at your own storage instead of memory:

```python
from osf import session

auth = Authenticator(
    server_secret=os.environ["OSF_SECRET"],   # persist this — rotating logs everyone out
    records=MyRecordTable(),                  # dict-like: __getitem__/__setitem__/__contains__/pop
    store=MyRedisSessionStore(),              # implements osf.session.SessionStore
    session_ttl_ms=15 * 60 * 1000,
)
```

---

## PHP

**No extension and no Composer required.** `php/osf.php` is a complete pure-PHP
implementation, verified byte-identical to Python/Rust/TypeScript against the
shared test vectors (120/120 state, 8/8 HMAC).

```bash
php examples/php/quickstart.php              # the tour, same as Python
php -S localhost:8422 examples/php/web_login.php   # a real login site
```

### Login and logout

```php
<?php
require 'osf.php';

use OSF\Auth;
use OSF\MemorySessionStore;
use OSF\Session;

$records = [];                                     // subject => record (SECRET)
$auth = new Auth(Session::newSecret(), $records, new MemorySessionStore());

// sign-up
[$clientKey, $record] = $auth->enroll('alice');

// login
$challenge = $auth->challenge();                   // 1. server
$proof     = Auth::prove($clientKey, $challenge);  // 2. client
$token     = $auth->login('alice', $challenge, $proof);   // 3. server

// use
$auth->whoami($token);       // 'alice'
$auth->session($token);      // ['sid'=>..., 'subject'=>'alice', 'issued'=>..., 'expires'=>...]
$auth->refresh($token);      // rotate

// logout
$auth->logout($token);
$auth->logoutEverywhere('alice');
```

Swap `MemorySessionStore` for `FileSessionStore` (ships with the library) or
implement the `OSF\SessionStore` interface against Redis/MySQL.

### Cookie

```php
setcookie('osf_session', $token, [
    'expires'  => (int) (($now + 900000) / 1000),
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'Strict',
    'secure'   => true,      // behind HTTPS
]);
```

---

## The same key works in every language

Session tokens and OSF tags are byte-identical across implementations, so a
Python service and a PHP service can share both. Verified:

```
v1 tag  (Python == PHP): MATCH
v2 tag  (Python == PHP): MATCH
session token issued by Python, verified by PHP: OK  subject='이정훈'
```

Everything crossing a boundary is a plain string: the record is JSON, the tag
is hex, the token is ASCII.

---

## The other calls

| Task | Python | PHP |
|---|---|---|
| Generate a key | `osf.keygen(t0)` | `OSF\Key::generate()` |
| Tag (v2, recommended) | `osf.tag(K, t, nonce, domain)` | `Core::tag($k, $t, $n, $domain)` |
| Verify a tag | `osf.verify_tag(K, t, nonce, cand)` | `Core::verifyTag(...)` |
| Tag (v1, compatibility) | `osf.state_hash(K, t, nonce)` | `Core::stateHash($k, $t, $n)` |
| Sign a transaction | `osf.coin.sign_tx(K, tx, now)` | — (use `Core::tag` with domain `tx`) |
| Verify a transaction | `osf.coin.verify_tx(rec, tx, sig, now)` | — |
| Δ for an environment | `osf.defense.delta_ms("field")` | `Core::deltaMs('field')` |
| Sign a command | `osf.defense.command_sign(...)` | `Core::commandSign(...)` |
| Verify a command | `osf.defense.verify_command(...)` | `Core::commandVerify(...)` |
| Sealed channel (forward secrecy) | `osf.messaging.*` | — |
| Break-it harness | `osf.attack.run_all()` | — |

Domain separation matters: a tag minted with domain `auth` will not verify as
`tx` or `cmd`, so a captured login tag cannot be replayed as a payment or a
weapon command.

---

## Things to get right in production

**Persist the session secret.** `Authenticator()` generates one at startup, so
restarting logs everyone out. Set it from the environment. Rotating it is the
intended "log everyone out now" lever.

**The registration record is the key.** OSF is symmetric — whoever holds the
record can impersonate the user, exactly like a TOTP seed. It is *not* a public
key. Protect the record store; use an HSM or enclave where it matters. See
[`SECURITY.md`](../SECURITY.md).

**Cookies:** `HttpOnly`, `SameSite=Strict`, and `Secure` behind HTTPS. Tokens
are bearer credentials — never log them.

**Clock skew.** Login compares timestamps within Δ (default 500 ms). If clients
and servers drift more than that, widen `delta_ms` or fix time sync (NTP). The
demos use 500 ms; the defense path exposes per-environment values from 100 µs
to 500 ms.

**Δ is a freshness window, not a distance bound.** Relay latency is typically
under 10 ms, so relaying is not prevented at `field`/`satellite`/`space`
settings. Distance bounding is a roadmap item.

**Post-quantum scope.** Authentication is hash-based and unaffected by Shor
(Grover gives ≈79 bits, which is below NIST Category 1). The forward-secrecy
layer in `osf.messaging` uses ECDH P-256 and is *not* post-quantum — pair with
ML-KEM where that matters.

---

Winner Brothers Group · inventor/applicant LEE JUNGHOON (이정훈) ·
PCT WO 2025/127469 A1 · PolyForm Noncommercial 1.0.0 (commercial license available).
