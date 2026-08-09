# OSF (Orbital State Function)
# Copyright (c) 2026 Winner Brothers Group. All rights reserved.
# Inventor / applicant: LEE JUNGHOON (이정훈).  Patent: PCT WO 2025/127469 A1.
# Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
# requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
# https://github.com/winnerbrothers/osf

"""
Everything OSF does, in one runnable file.

    pip install planet-osf
    python quickstart.py

No server, no network, no configuration. Each section prints what it proved.
"""
import time

import osf
from osf.auth import Authenticator

now = lambda: int(time.time() * 1000)


def section(n, title):
    print(f"\n{'=' * 68}\n{n}. {title}\n{'=' * 68}")


# ---------------------------------------------------------------- 1. one-liner
section(1, "The one-liner — authenticate like md5()")

K = osf.keygen(now())
t = now()
print("  key generated (7 CSPRNG params, never transmitted)")
print("  osf.tag(K, t, 'hello') =", osf.tag(K, t, "hello"))
print("  deterministic?         ", osf.tag(K, t, "hello") == osf.tag(K, t, "hello"))
print("  different nonce differs?", osf.tag(K, t, "hello") != osf.tag(K, t, "world"))
print("  domain-separated?      ",
      osf.tag(K, t, "n", "auth") != osf.tag(K, t, "n", "tx"),
      "(a login tag can't be replayed as a payment)")


# --------------------------------------------------------- 2. login + session
section(2, "Login and logout — with a real session")

auth = Authenticator()                       # server, once at startup

client_key, _record = auth.enroll("alice")   # sign-up. client keeps the key.
print("  enrolled 'alice'")

challenge = auth.challenge()                              # server → client
proof     = Authenticator.prove(client_key, challenge)    # client (holds K)
token     = auth.login("alice", challenge, proof)         # server verifies
print("  login  ->", "OK" if token else "FAILED")
print("  token  ->", token[:44] + "...")
print("  whoami ->", auth.whoami(token))

s = auth.session(token)
print(f"  session: sid={s.sid[:12]}... expires in {s.remaining_ms(now()) // 1000}s")

auth.logout(token)
print("  logout ->", "session ended")
print("  whoami after logout ->", auth.whoami(token), "(token is now dead)")


# --------------------------------------------------------------- 3. it's safe
section(3, "The failure cases actually fail")

ch2 = auth.challenge()
wrong = osf.keygen(now())                                  # attacker's own key
bad = Authenticator.prove(wrong, ch2)
print("  wrong key         ->", auth.login("alice", ch2, bad))

ch3 = auth.challenge()
good = Authenticator.prove(client_key, ch3)
tok3 = auth.login("alice", ch3, good)
print("  replay same proof ->", auth.login("alice", ch3, good), "(challenge is one-time)")

forged = "osf1." + "a" * 32 + ".YWxpY2U.1.9999999999999." + "b" * 64
print("  forged token      ->", auth.whoami(forged))

auth.logout_everywhere("alice")
print("  logout everywhere ->", auth.whoami(tok3), "(all sessions killed)")


# ------------------------------------------------------------ 4. transactions
section(4, "Signing a transaction")

from osf import coin
from osf.key import Key

tx = {"from": "alice", "to": "bob", "amount": 42, "asset": "PLNT"}
sig = coin.sign_tx(client_key, tx, now())
record_key = Key.from_record(_record)
print("  signed          ->", sig.sig[:32] + "...")
print("  verify          ->", coin.verify_tx(record_key, tx, sig, now()))
print("  tampered amount ->", coin.verify_tx(record_key, dict(tx, amount=4_200_000), sig, now()))


# ----------------------------------------------------------------- 5. defense
section(5, "On-device command auth (UAV / satellite / weapon)")

from osf import defense

dev = defense.Device("uav-01", "uav", "field", callsign="HAWK-1")
sk = defense.derive_session_key("a" * 64, "b" * 64, "cc", "dd", "hs-1")
ssh, nonce, ts = osf.sha256_hex("sender-state"), osf.random_nonce(16), now()

sig2 = defense.command_sign(sk, "RTL", ssh, nonce, ts, "cmd-1")
r1 = defense.verify_command(dev, sk, "RTL", ssh, nonce, ts, "cmd-1", sig2, ts)
r2 = defense.verify_command(dev, sk, "RTL", ssh, nonce, ts, "cmd-1", sig2, ts)      # replay
r3 = defense.verify_command(dev, sk, "RTL", ssh, nonce, ts, "cmd-2", sig2, ts + 10_000)  # skew
r4 = defense.verify_command(dev, sk, "LAUNCH", ssh, nonce, ts, "cmd-3", sig2, ts)   # tamper

print(f"  Δ for 'field'   -> {dev.delta_ms} ms")
print(f"  valid command   -> {r1.ok}")
print(f"  replayed        -> {r2.ok}  ({r2.reason})")
print(f"  clock spoofed   -> {r3.ok}  ({r3.reason})")
print(f"  tampered body   -> {r4.ok}  ({r4.reason})")


# ---------------------------------------------------------------- 6. break it
section(6, "Try to break it")

for r in osf.attack.run_all():
    print(f"  {r['attack']:<18} broke_osf = {r['broke_osf']}")
print("\n  Public challenge: https://winnerbrothers.github.io/osf/")

print("\nDone.\n")
