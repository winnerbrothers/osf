"""
OSF key K = (p0, â, ω, t0) — the 7-parameter orbital secret.

  p0 (coordinates)   : 3 reals, sampled in a bounded shell   [entropy]
  â  (rotation axis)  : 3 reals on the unit sphere (2 DOF)    [entropy]
  ω  (angular speed)  : 1 real in [1, 36000] deg/s            [entropy]
  t0 (initial epoch)  : reference timestamp (ms)              [public-ish]

Trust model (be explicit — this is a SYMMETRIC primitive, not public-key):
K, or its serialized `registration record`, is a secret shared between the
prover and the party that will verify it (a login server, a coin issuer, a
command authority). Verification requires knowledge of K. Public
verifiability is NOT provided by v1 and is tracked as a roadmap item; do not
represent the registration record as a "public key".
"""
from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Dict

from ._canon import Vec3, State, get_state_at, canonical_preimage
from ._crypto import sha256_hex, random_nonce


def _secure_float() -> float:
    """Uniform float in [0,1) from CSPRNG (53-bit)."""
    return int.from_bytes(os.urandom(7), "big") / float(1 << 56)


def _secure_range(lo: float, hi: float) -> float:
    return lo + (hi - lo) * _secure_float()


def _random_unit_vector() -> Vec3:
    # Marsaglia: uniform on S^2 via CSPRNG
    while True:
        x1 = _secure_range(-1.0, 1.0)
        x2 = _secure_range(-1.0, 1.0)
        s = x1 * x1 + x2 * x2
        if s < 1.0 and s > 0.0:
            f = 2.0 * math.sqrt(1.0 - s)
            return (x1 * f, x2 * f, 1.0 - 2.0 * s)


def _random_point_in_shell(inner: float, outer: float) -> Vec3:
    u = _random_unit_vector()
    r = _secure_range(inner, outer)
    return (u[0] * r, u[1] * r, u[2] * r)


@dataclass(frozen=True)
class Key:
    """An OSF key. Treat every field as secret."""
    coordinates: Vec3
    rotation_axis: Vec3
    angular_speed: float
    initial_timestamp: int

    def state_at(self, timestamp_ms: int) -> State:
        return get_state_at(
            self.coordinates, self.rotation_axis, self.angular_speed,
            self.initial_timestamp, timestamp_ms,
        )

    def state_hash(self, timestamp_ms: int, nonce: str | None = None) -> str:
        """H(s_K(t) || nonce) — the OSF authentication tag."""
        return sha256_hex(canonical_preimage(self.state_at(timestamp_ms), nonce))

    def registration_record(self) -> Dict:
        """Serialized K for the verifier to store (SECRET — see module docstring)."""
        return {
            "coordinates": {"x": self.coordinates[0], "y": self.coordinates[1], "z": self.coordinates[2]},
            "rotationAxis": {"x": self.rotation_axis[0], "y": self.rotation_axis[1], "z": self.rotation_axis[2]},
            "angularSpeed": self.angular_speed,
            "initialTimestamp": self.initial_timestamp,
        }

    @staticmethod
    def from_record(rec: Dict) -> "Key":
        c, a = rec["coordinates"], rec["rotationAxis"]
        return Key(
            coordinates=(c["x"], c["y"], c["z"]),
            rotation_axis=(a["x"], a["y"], a["z"]),
            angular_speed=rec["angularSpeed"],
            initial_timestamp=rec["initialTimestamp"],
        )


def keygen(initial_timestamp_ms: int, shell_inner: float = 1.0, shell_outer: float = 1000.0) -> Key:
    """Generate a fresh OSF key with CSPRNG parameters.

    ``initial_timestamp_ms`` is caller-supplied (usually the current epoch in
    ms) so that key generation is fully deterministic given its RNG source and
    is easy to test; production callers pass ``int(time.time()*1000)``.
    """
    return Key(
        coordinates=_random_point_in_shell(shell_inner, shell_outer),
        rotation_axis=_random_unit_vector(),
        angular_speed=_secure_range(1.0, 36000.0),
        initial_timestamp=int(initial_timestamp_ms),
    )
