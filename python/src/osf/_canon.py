# OSF (Orbital State Function)
# Copyright (c) 2026 Winner Brothers Group. All rights reserved.
# Inventor / applicant: LEE JUNGHOON (이정훈).  Patent: PCT WO 2025/127469 A1.
# Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
# requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
# https://github.com/winnerbrothers/osf

"""
OSF-CANON v1 — canonical state computation and encoding.

This is the byte-exact reference for the Orbital State Function primitive,
validated against the deployed TypeScript core (`planet-core`) by the KAT
suite (see tests/test_kat.py). Every OSF binding — Rust, PHP, Node — MUST
produce identical `state_hash` output for identical inputs.

Determinism note (empirically established, 2026): transcendental drift
between platform libm implementations can differ by ~1 ULP in the raw f64
state, but toFixed(10) rounding absorbs that margin for coordinate
magnitudes up to ~1000. The authoritative canonical math is nonetheless
pinned to the shared core's libm; this pure-Python module is the reference
oracle. See spec/OSF-CANON-v1.md.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional, Tuple

Vec3 = Tuple[float, float, float]
Quat = Tuple[float, float, float, float]  # (w, x, y, z)


@dataclass(frozen=True)
class State:
    """OSF state s_K(t): a position (rotated point) and rotation quaternion."""
    position: Vec3
    rotation: Quat
    timestamp: int  # milliseconds


def js_to_fixed_10(x: float) -> str:
    """Reproduce JavaScript ``Number.prototype.toFixed(10)`` byte-for-byte.

    Collapses negative zero (JS prints ``0.0000000000``) then formats with
    round-half-to-even, which agrees with V8 on every non-tie value.
    """
    if x == 0:  # -0.0 == 0.0 -> assign +0.0 so no leading '-'
        x = 0.0
    return format(x, ".10f")


def _q_mul(a: Quat, b: Quat) -> Quat:
    aw, ax, ay, az = a
    bw, bx, by, bz = b
    return (
        aw * bw - ax * bx - ay * by - az * bz,
        aw * bx + ax * bw + ay * bz - az * by,
        aw * by - ax * bz + ay * bw + az * bx,
        aw * bz + ax * by - ay * bx + az * bw,
    )


def _from_axis_angle(axis: Vec3, angle_rad: float) -> Quat:
    half = angle_rad / 2.0
    s = math.sin(half)
    return (math.cos(half), axis[0] * s, axis[1] * s, axis[2] * s)


def compute_rotation(axis: Vec3, angular_speed: float, elapsed_seconds: float) -> Quat:
    # JS `%` is truncated remainder == math.fmod (NOT Python's floored `%`).
    angle_deg = math.fmod(angular_speed * elapsed_seconds, 360.0)
    angle_rad = angle_deg * math.pi / 180.0
    return _from_axis_angle(axis, angle_rad)


def compute_position(
    coords: Vec3, axis: Vec3, angular_speed: float, elapsed_seconds: float
) -> Vec3:
    q = compute_rotation(axis, angular_speed, elapsed_seconds)
    p: Quat = (0.0, coords[0], coords[1], coords[2])
    q_inv: Quat = (q[0], -q[1], -q[2], -q[3])
    r = _q_mul(_q_mul(q, p), q_inv)
    return (r[1], r[2], r[3])


def get_state_at(
    coords: Vec3,
    axis: Vec3,
    angular_speed: float,
    initial_timestamp: int,
    timestamp: int,
) -> State:
    """s_K(t): full OSF state at wall-clock ``timestamp`` (ms)."""
    elapsed = (timestamp - initial_timestamp) / 1000.0
    return State(
        position=compute_position(coords, axis, angular_speed, elapsed),
        rotation=compute_rotation(axis, angular_speed, elapsed),
        timestamp=timestamp,
    )


def canonical_preimage(state: State, nonce: Optional[str] = None) -> str:
    """OSF-CANON v1 pre-image string: exactly what gets SHA-256'd.

    Key order and formatting are frozen: position{x,y,z} -> rotation{w,x,y,z}
    -> timestamp -> nonce?, each real via ``toFixed(10)``, JSON with no spaces.
    """
    px, py, pz = state.position
    rw, rx, ry, rz = state.rotation
    parts = [
        '{"position":{"x":"', js_to_fixed_10(px),
        '","y":"', js_to_fixed_10(py),
        '","z":"', js_to_fixed_10(pz),
        '"},"rotation":{"w":"', js_to_fixed_10(rw),
        '","x":"', js_to_fixed_10(rx),
        '","y":"', js_to_fixed_10(ry),
        '","z":"', js_to_fixed_10(rz),
        '"},"timestamp":', str(int(state.timestamp)),
    ]
    if nonce is not None:
        parts.append(',"nonce":"')
        parts.append(nonce)
        parts.append('"')
    parts.append("}")
    return "".join(parts)
