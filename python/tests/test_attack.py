"""
The public attack harness must show OSF defeats every attack.
If any of these ever flip to broke_osf=True, OSF is broken — fail loudly.
"""
import unittest

import _bootstrap  # noqa: F401
from osf import attack
from osf.key import keygen
from osf._crypto import sha256_hex

T0 = 1_700_000_000_000


class TestAttackHarness(unittest.TestCase):
    def test_forgery_fails(self):
        r = attack.attempt_forgery(keygen(T0), trials=100_000)
        self.assertFalse(r.broke_osf, r.detail)

    def test_replay_fails(self):
        r = attack.attempt_replay(keygen(T0))
        self.assertFalse(r.broke_osf, r.detail)

    def test_mitm_fails(self):
        r = attack.attempt_mitm(sha256_hex("session"))
        self.assertFalse(r.broke_osf, r.detail)

    def test_state_recovery_fails(self):
        r = attack.attempt_state_recovery(keygen(T0), observations=512)
        self.assertFalse(r.broke_osf, r.detail)

    def test_brute_force_is_infeasible(self):
        r = attack.brute_force_cost(hash_rate_per_sec=1e12)
        self.assertFalse(r.broke_osf)
        self.assertIn("years", r.detail)

    def test_run_all_clean(self):
        results = attack.run_all(T0)
        broke = [r for r in results if r["broke_osf"]]
        self.assertEqual(broke, [], f"OSF was defeated by: {broke}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
