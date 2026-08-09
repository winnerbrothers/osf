# OSF (Orbital State Function)
# Copyright (c) 2026 Winner Brothers Group. All rights reserved.
# Inventor / applicant: LEE JUNGHOON (이정훈).  Patent: PCT WO 2025/127469 A1.
# Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
# requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
# https://github.com/winnerbrothers/osf

"""Session tokens and the Authenticator facade: login, logout, expiry, revocation."""
import unittest

import _bootstrap  # noqa: F401
import osf
from osf import session
from osf.auth import Authenticator

T0 = 1_700_000_000_000
HOUR = 3_600_000


class TestSessionToken(unittest.TestCase):
    def setUp(self):
        self.secret = session.new_secret()
        self.store = session.MemorySessionStore()

    def test_issue_and_verify(self):
        tok = session.issue("alice", T0, self.secret, self.store)
        s = session.verify(tok, T0 + 1000, self.secret, self.store)
        self.assertIsNotNone(s)
        self.assertEqual(s.subject, "alice")
        self.assertEqual(s.expires_ms, T0 + HOUR)

    def test_subject_survives_unicode(self):
        tok = session.issue("이정훈@winnerbrothers", T0, self.secret, self.store)
        self.assertEqual(
            session.verify(tok, T0, self.secret, self.store).subject,
            "이정훈@winnerbrothers",
        )

    def test_expired_rejected(self):
        tok = session.issue("alice", T0, self.secret, self.store, ttl_ms=1000)
        self.assertIsNotNone(session.verify(tok, T0 + 999, self.secret, self.store))
        self.assertIsNone(session.verify(tok, T0 + 1000, self.secret, self.store))
        self.assertEqual(session.inspect(tok, T0 + 5000, self.secret, self.store)[1], "expired")

    def test_wrong_secret_rejected(self):
        tok = session.issue("alice", T0, self.secret, self.store)
        self.assertIsNone(session.verify(tok, T0, session.new_secret(), self.store))

    def test_tampered_token_rejected(self):
        tok = session.issue("alice", T0, self.secret, self.store)
        parts = tok.split(".")

        # swap the subject, keep the original signature
        import base64
        parts[2] = base64.urlsafe_b64encode(b"root").decode().rstrip("=")
        self.assertIsNone(session.verify(".".join(parts), T0, self.secret, self.store))

        # extend the expiry
        parts = tok.split(".")
        parts[4] = str(int(parts[4]) + 10 * HOUR)
        self.assertIsNone(session.verify(".".join(parts), T0, self.secret, self.store))

    def test_malformed_rejected(self):
        for bad in ("", "garbage", "osf1.a.b.c", "xxx1.a.b.1.2.3", "osf1.a.b.x.y.z"):
            self.assertIsNone(session.verify(bad, T0, self.secret, self.store))

    def test_revoke(self):
        tok = session.issue("alice", T0, self.secret, self.store)
        self.assertTrue(session.revoke(tok, self.secret, self.store))
        self.assertIsNone(session.verify(tok, T0, self.secret, self.store))
        self.assertFalse(session.revoke(tok, self.secret, self.store))  # already gone

    def test_revoke_requires_valid_signature(self):
        """An attacker must not be able to revoke a session id they guessed."""
        tok = session.issue("alice", T0, self.secret, self.store)
        forged = tok[:-1] + ("0" if tok[-1] != "0" else "1")
        self.assertFalse(session.revoke(forged, self.secret, self.store))
        self.assertIsNotNone(session.verify(tok, T0, self.secret, self.store))

    def test_revoke_all(self):
        toks = [session.issue("alice", T0, self.secret, self.store) for _ in range(3)]
        other = session.issue("bob", T0, self.secret, self.store)
        self.assertEqual(session.revoke_all("alice", self.store), 3)
        for t in toks:
            self.assertIsNone(session.verify(t, T0, self.secret, self.store))
        self.assertIsNotNone(session.verify(other, T0, self.secret, self.store))

    def test_refresh_rotates_and_kills_old(self):
        old = session.issue("alice", T0, self.secret, self.store, ttl_ms=HOUR)
        new = session.refresh(old, T0 + 60_000, self.secret, self.store, ttl_ms=HOUR)
        self.assertIsNotNone(new)
        self.assertNotEqual(old, new)
        self.assertIsNone(session.verify(old, T0 + 60_000, self.secret, self.store))
        self.assertIsNotNone(session.verify(new, T0 + 60_000, self.secret, self.store))

    def test_refresh_of_dead_token_fails(self):
        tok = session.issue("alice", T0, self.secret, self.store, ttl_ms=1000)
        self.assertIsNone(session.refresh(tok, T0 + 2000, self.secret, self.store))

    def test_purge_expired(self):
        session.issue("a", T0, self.secret, self.store, ttl_ms=1000)
        session.issue("b", T0, self.secret, self.store, ttl_ms=HOUR)
        self.assertEqual(self.store.purge_expired(T0 + 5000), 1)
        self.assertEqual(len(self.store), 1)

    def test_ttl_must_be_positive(self):
        with self.assertRaises(ValueError):
            session.issue("alice", T0, self.secret, self.store, ttl_ms=0)


class TestAuthenticator(unittest.TestCase):
    def setUp(self):
        self.auth = Authenticator()
        self.key, self.record = self.auth.enroll("alice", now_ms=T0)

    def _login(self, key=None, subject="alice", now=T0):
        ch = self.auth.challenge(now_ms=now)
        proof = Authenticator.prove(key or self.key, ch, now_ms=now)
        return self.auth.login(subject, ch, proof, now_ms=now)

    def test_happy_path(self):
        tok = self._login()
        self.assertIsNotNone(tok)
        self.assertEqual(self.auth.whoami(tok, now_ms=T0), "alice")

    def test_logout(self):
        tok = self._login()
        self.assertTrue(self.auth.logout(tok))
        self.assertIsNone(self.auth.whoami(tok, now_ms=T0))

    def test_wrong_key_rejected(self):
        self.assertIsNone(self._login(key=osf.keygen(T0 + 7)))

    def test_unknown_subject_rejected(self):
        self.assertIsNone(self._login(subject="mallory"))

    def test_challenge_is_single_use(self):
        ch = self.auth.challenge(now_ms=T0)
        proof = Authenticator.prove(self.key, ch, now_ms=T0)
        self.assertIsNotNone(self.auth.login("alice", ch, proof, now_ms=T0))
        self.assertIsNone(self.auth.login("alice", ch, proof, now_ms=T0))

    def test_unknown_challenge_rejected(self):
        from osf.login import Challenge, login_prove
        rogue = Challenge(nonce="deadbeef" * 8, issued_at=T0)
        proof = login_prove(self.key, rogue, T0)
        self.assertIsNone(self.auth.login("alice", rogue, proof, now_ms=T0))

    def test_stale_proof_rejected(self):
        ch = self.auth.challenge(now_ms=T0)
        proof = Authenticator.prove(self.key, ch, now_ms=T0)
        self.assertIsNone(self.auth.login("alice", ch, proof, now_ms=T0 + 10_000))

    def test_logout_everywhere(self):
        toks = [self._login() for _ in range(3)]
        self.assertEqual(self.auth.logout_everywhere("alice"), 3)
        for t in toks:
            self.assertIsNone(self.auth.whoami(t, now_ms=T0))

    def test_refresh(self):
        tok = self._login()
        new = self.auth.refresh(tok, now_ms=T0 + 1000)
        self.assertIsNotNone(new)
        self.assertIsNone(self.auth.whoami(tok, now_ms=T0 + 1000))
        self.assertEqual(self.auth.whoami(new, now_ms=T0 + 1000), "alice")

    def test_register_client_generated_record(self):
        k = osf.keygen(T0)
        self.auth.register_record("bob", k.registration_record())
        self.assertTrue(self.auth.is_enrolled("bob"))
        self.assertIsNotNone(self._login(key=k, subject="bob"))

    def test_purge_clears_stale_challenges(self):
        self.auth.challenge(now_ms=T0)
        self.auth.challenge(now_ms=T0)
        self.assertGreaterEqual(self.auth.purge(now_ms=T0 + 600_000), 2)

    def test_secret_rotation_invalidates_everything(self):
        tok = self._login()
        self.auth.server_secret = session.new_secret()
        self.assertIsNone(self.auth.whoami(tok, now_ms=T0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
