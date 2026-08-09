# OSF (Orbital State Function)
# Copyright (c) 2026 Winner Brothers Group. All rights reserved.
# Inventor / applicant: LEE JUNGHOON (이정훈).  Patent: PCT WO 2025/127469 A1.
# Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
# requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
# https://github.com/winnerbrothers/osf

"""Functional tests for the five one-line use-case wrappers."""
import unittest

import _bootstrap  # noqa: F401
import osf
from osf import login, coin, defense, messaging
from osf.key import keygen

T0 = 1_700_000_000_000


class TestLogin(unittest.TestCase):
    def test_success(self):
        K = keygen(T0)
        ch = login.login_challenge(T0)
        proof = login.login_prove(K, ch, T0)
        self.assertTrue(login.login_verify(K, ch, proof, T0, delta_ms=500.0))

    def test_wrong_key_fails(self):
        K, other = keygen(T0), keygen(T0 + 1)
        ch = login.login_challenge(T0)
        proof = login.login_prove(other, ch, T0)  # attacker uses a different key
        self.assertFalse(login.login_verify(K, ch, proof, T0, delta_ms=500.0))

    def test_stale_proof_rejected(self):
        K = keygen(T0)
        ch = login.login_challenge(T0)
        proof = login.login_prove(K, ch, T0)
        # server clock advanced far beyond Δ
        self.assertFalse(login.login_verify(K, ch, proof, T0 + 10_000, delta_ms=500.0))


class TestCoin(unittest.TestCase):
    def test_sign_verify(self):
        K = keygen(T0)
        tx = {"from": "alice", "to": "bob", "amount": 42, "asset": "PLNT"}
        sig = coin.sign_tx(K, tx, T0)
        self.assertTrue(coin.verify_tx(K, tx, sig, T0, delta_ms=500.0))

    def test_tamper_amount_fails(self):
        K = keygen(T0)
        tx = {"from": "alice", "to": "bob", "amount": 42, "asset": "PLNT"}
        sig = coin.sign_tx(K, tx, T0)
        tampered = dict(tx, amount=4_200_000)          # attacker inflates amount
        self.assertFalse(coin.verify_tx(K, tampered, sig, T0, delta_ms=500.0))


class TestDefense(unittest.TestCase):
    def _session(self):
        return defense.derive_session_key("a" * 64, "b" * 64, "cc", "dd", "hs-1")

    def test_command_roundtrip(self):
        sk = self._session()
        dev = defense.Device("d1", "uav", "field", callsign="HAWK-1", hsm_attested=True)
        ssh = osf.sha256_hex("sender-state")
        sig = defense.command_sign(sk, "RTL", ssh, "nonce1", T0, "cmd-1")
        r = defense.verify_command(dev, sk, "RTL", ssh, "nonce1", T0, "cmd-1", sig, T0)
        self.assertTrue(r.ok, r.reason)

    def test_replay_blocked(self):
        sk = self._session()
        dev = defense.Device("d1", "uav", "field")
        ssh = osf.sha256_hex("s")
        sig = defense.command_sign(sk, "RTL", ssh, "n", T0, "cmd-1")
        first = defense.verify_command(dev, sk, "RTL", ssh, "n", T0, "cmd-1", sig, T0)
        second = defense.verify_command(dev, sk, "RTL", ssh, "n", T0, "cmd-1", sig, T0)
        self.assertTrue(first.ok)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "replay_detected")

    def test_clock_spoof_blocked(self):
        sk = self._session()
        dev = defense.Device("d1", "uav", "field")  # Δ = 50ms
        ssh = osf.sha256_hex("s")
        sig = defense.command_sign(sk, "RTL", ssh, "n", T0, "cmd-2")
        r = defense.verify_command(dev, sk, "RTL", ssh, "n", T0, "cmd-2", sig, T0 + 10_000)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "clock_skew_exceeds_delta")

    def test_delta_table(self):
        self.assertEqual(defense.delta_ms("gps_disciplined"), 0.1)
        self.assertEqual(defense.delta_ms("space"), 500.0)
        with self.assertRaises(ValueError):
            defense.delta_ms("bogus")


class TestMessaging(unittest.TestCase):
    def setUp(self):
        try:
            import cryptography  # noqa: F401
        except Exception:
            self.skipTest("cryptography not installed; messaging FS unavailable")

    def test_handshake_and_sealed_channel(self):
        alice, bob = keygen(T0), keygen(T0 + 5)
        init_msg, ctx = messaging.handshake_init(alice, T0)
        resp, sk_bob, _ = messaging.handshake_respond(bob, alice, init_msg, T0 + 1)
        sk_alice = messaging.handshake_finalize(ctx, bob, resp)
        self.assertEqual(sk_alice, sk_bob)                  # shared session key
        token = messaging.seal(sk_alice, b"launch codes: 0000")
        self.assertEqual(messaging.open(sk_bob, token), b"launch codes: 0000")

    def test_impostor_peer_rejected(self):
        alice, mallory = keygen(T0), keygen(T0 + 9)
        init_msg, _ = messaging.handshake_init(alice, T0)
        # Bob expects Alice, but Mallory's record is used to verify -> mismatch
        with self.assertRaises(ValueError):
            messaging.handshake_respond(keygen(T0 + 1), mallory, init_msg, T0 + 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
