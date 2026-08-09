# OSF (Orbital State Function)
# Copyright (c) 2026 Winner Brothers Group. All rights reserved.
# Inventor / applicant: LEE JUNGHOON (이정훈).  Patent: PCT WO 2025/127469 A1.
# Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
# requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
# https://github.com/winnerbrothers/osf

"""
OSF-CANON v2 (HMAC-SHA-256) tag construction.

v2 exists because v1's raw-hash keying leans on the random-oracle model and
carries no domain separation. v2 is an HMAC, so its PRF security follows from
a standard-model assumption, and it is an approved construction under FIPS
140-3 / KCMVP — which matters for certification, since those programmes
validate approved algorithms only.
"""
import unittest

import _bootstrap  # noqa: F401
import osf
from osf import v2 as tagmod
from osf.key import keygen

T0 = 1_700_000_000_000


class TestTagV2(unittest.TestCase):
    def setUp(self):
        self.K = keygen(T0)
        self.t = T0 + 5_000
        self.n = "nonce-abc"

    def test_deterministic_and_well_formed(self):
        a = tagmod.tag(self.K, self.t, self.n)
        b = tagmod.tag(self.K, self.t, self.n)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)
        int(a, 16)  # valid hex

    def test_differs_from_v1(self):
        """v2 must not collide with the v1 construction on the same inputs."""
        self.assertNotEqual(tagmod.tag(self.K, self.t, self.n),
                            osf.state_hash(self.K, self.t, self.n))

    def test_domain_separation(self):
        """A login tag must not be reusable as a transaction or command tag."""
        auth = tagmod.tag(self.K, self.t, self.n, tagmod.DOMAIN_AUTH)
        tx = tagmod.tag(self.K, self.t, self.n, tagmod.DOMAIN_TX)
        cmd = tagmod.tag(self.K, self.t, self.n, tagmod.DOMAIN_CMD)
        self.assertEqual(len({auth, tx, cmd}), 3)

    def test_sensitive_to_time_nonce_and_key(self):
        base = tagmod.tag(self.K, self.t, self.n)
        self.assertNotEqual(base, tagmod.tag(self.K, self.t + 1, self.n))
        self.assertNotEqual(base, tagmod.tag(self.K, self.t, self.n + "x"))
        self.assertNotEqual(base, tagmod.tag(keygen(T0 + 1), self.t, self.n))

    def test_aad_is_bound(self):
        a = tagmod.tag(self.K, self.t, self.n, tagmod.DOMAIN_TX, aad="tx-hash-1")
        b = tagmod.tag(self.K, self.t, self.n, tagmod.DOMAIN_TX, aad="tx-hash-2")
        self.assertNotEqual(a, b)

    def test_verify_roundtrip_and_rejection(self):
        t = tagmod.tag(self.K, self.t, self.n)
        self.assertTrue(tagmod.verify(self.K, self.t, self.n, t))
        self.assertFalse(tagmod.verify(self.K, self.t, self.n, t, tagmod.DOMAIN_TX))
        self.assertFalse(tagmod.verify(self.K, self.t, self.n, "0" * 64))
        self.assertFalse(tagmod.verify(keygen(T0 + 7), self.t, self.n, t))

    def test_message_layout_is_frozen(self):
        self.assertEqual(
            tagmod.v2_message(123, "NN", "auth", "AAD"),
            "OSF-CANON-v2|auth|123|NN|AAD",
        )
        with self.assertRaises(ValueError):
            tagmod.v2_message(1, "n", "bad|domain")

    def test_matches_manual_hmac(self):
        """The tag really is HMAC-SHA-256 keyed by the canonical state."""
        import hmac, hashlib
        from osf._canon import canonical_preimage
        key = canonical_preimage(self.K.state_at(self.t), None).encode()
        msg = tagmod.v2_message(self.t, self.n, tagmod.DOMAIN_AUTH, "").encode()
        self.assertEqual(hmac.new(key, msg, hashlib.sha256).hexdigest(),
                         tagmod.tag(self.K, self.t, self.n))


if __name__ == "__main__":
    unittest.main(verbosity=2)
