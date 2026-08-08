"""
KAT determinism: the pure-Python OSF reference must reproduce the deployed
TypeScript core (planet-core) byte-for-byte on every known-answer vector.
This is the machine-checkable half of "OSF is implemented correctly".
"""
import json
import unittest

import _bootstrap  # noqa: F401  (path + KAT setup)
from _bootstrap import KAT_PATH

import osf
from osf._canon import get_state_at, canonical_preimage
from osf._crypto import sha256_hex, hmac_sign


def _load():
    with open(KAT_PATH, encoding="utf-8") as f:
        return json.load(f)


class TestKAT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = _load()

    def test_state_hash_matches_reference(self):
        vs = self.data["stateVectors"]
        self.assertGreaterEqual(len(vs), 100, "expected a substantial KAT set")
        pos_bit = 0
        for v in vs:
            k = v["k"]; ex = v["expected"]
            coords = (k["coordinates"]["x"], k["coordinates"]["y"], k["coordinates"]["z"])
            axis = (k["rotationAxis"]["x"], k["rotationAxis"]["y"], k["rotationAxis"]["z"])
            st = get_state_at(coords, axis, k["angularSpeed"], k["initialTimestamp"], v["t"])

            self.assertEqual(canonical_preimage(st, None), ex["canonicalNoNonce"],
                             f"canonical mismatch at idx {v['idx']}")
            self.assertEqual(sha256_hex(canonical_preimage(st, None)), ex["stateHash"],
                             f"stateHash mismatch at idx {v['idx']}")
            self.assertEqual(sha256_hex(canonical_preimage(st, v["nonce"])), ex["stateHashNonce"],
                             f"stateHashNonce mismatch at idx {v['idx']}")
            if (st.position[0], st.position[1], st.position[2]) == (
                ex["position"]["x"], ex["position"]["y"], ex["position"]["z"]):
                pos_bit += 1
        # Informational: raw-f64 bit-identity is NOT required (toFixed(10)
        # absorbs sub-ULP libm drift); the hash identity above is what matters.
        print(f"\n[KAT] raw position bit-identical: {pos_bit}/{len(vs)} "
              f"(hash-identity is 100% regardless)")

    def test_hmac_matches_reference(self):
        for hv in self.data["hmacVectors"]:
            key = bytes.fromhex(hv["keyHex"])
            self.assertEqual(hmac_sign(key, hv["msg"]), hv["sig"])

    def test_public_api_oneliner(self):
        # the md5()-style call surface exists and is stable
        K = osf.keygen(1_700_000_000_000)
        h1 = osf.state_hash(K, 1_700_000_005_000, nonce="abc")
        h2 = osf.state_hash(K, 1_700_000_005_000, nonce="abc")
        self.assertEqual(h1, h2)                 # deterministic
        self.assertEqual(len(h1), 64)            # sha-256 hex
        self.assertNotEqual(h1, osf.state_hash(K, 1_700_000_005_000, nonce="abd"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
