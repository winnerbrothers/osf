// OSF (Orbital State Function)
// Copyright (c) 2026 Winner Brothers Group. All rights reserved.
// Inventor / applicant: LEE JUNGHOON.  Patent: PCT WO 2025/127469 A1.
// Licensed under PolyForm Noncommercial 1.0.0 - commercial or production use
// requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
// https://github.com/winnerbrothers/osf

//! Deterministic quaternion math. Uses the `libm` crate (fixed fdlibm port)
//! so sin/cos are identical on every target — the basis of OSF-CANON v1
//! cross-platform byte-identity.

pub type Vec3 = [f64; 3];
/// (w, x, y, z)
pub type Quat = [f64; 4];

#[inline]
pub fn multiply(a: Quat, b: Quat) -> Quat {
    let [aw, ax, ay, az] = a;
    let [bw, bx, by, bz] = b;
    [
        aw * bw - ax * bx - ay * by - az * bz,
        aw * bx + ax * bw + ay * bz - az * by,
        aw * by - ax * bz + ay * bw + az * bx,
        aw * bz + ax * by - ay * bx + az * bw,
    ]
}

#[inline]
pub fn from_axis_angle(axis: Vec3, angle_rad: f64) -> Quat {
    let half = angle_rad / 2.0;
    let s = libm::sin(half);
    [libm::cos(half), axis[0] * s, axis[1] * s, axis[2] * s]
}

#[inline]
pub fn rotate_point(q: Quat, p: Vec3) -> Vec3 {
    let pq: Quat = [0.0, p[0], p[1], p[2]];
    let q_inv: Quat = [q[0], -q[1], -q[2], -q[3]];
    let r = multiply(multiply(q, pq), q_inv);
    [r[1], r[2], r[3]]
}
