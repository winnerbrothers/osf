// OSF (Orbital State Function)
// Copyright (c) 2026 Winner Brothers Group. All rights reserved.
// Inventor / applicant: LEE JUNGHOON.  Patent: PCT WO 2025/127469 A1.
// Licensed under PolyForm Noncommercial 1.0.0 - commercial or production use
// requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
// https://github.com/winnerbrothers/osf

//! OSF state function s_K(t) and OSF-CANON v1 encoding.

use crate::quaternion::{from_axis_angle, rotate_point, Quat, Vec3};

pub struct State {
    pub position: Vec3,
    pub rotation: Quat,
    pub timestamp: i64,
}

#[inline]
pub fn compute_rotation(axis: Vec3, angular_speed: f64, elapsed_seconds: f64) -> Quat {
    // JS `%` == truncated remainder == libm::fmod (NOT floored modulo).
    let angle_deg = libm::fmod(angular_speed * elapsed_seconds, 360.0);
    let angle_rad = angle_deg * core::f64::consts::PI / 180.0;
    from_axis_angle(axis, angle_rad)
}

pub fn get_state_at(
    coords: Vec3,
    axis: Vec3,
    angular_speed: f64,
    initial_timestamp: i64,
    timestamp: i64,
) -> State {
    let elapsed = (timestamp - initial_timestamp) as f64 / 1000.0;
    let rotation = compute_rotation(axis, angular_speed, elapsed);
    let position = rotate_point(rotation, coords);
    State { position, rotation, timestamp }
}

/// Reproduce JavaScript `Number.prototype.toFixed(10)` byte-for-byte.
/// Collapse -0.0 -> 0.0 (JS prints "0.0000000000"), then round-half-to-even
/// via Rust's float formatter (agrees with V8 on every non-tie value).
#[inline]
pub fn to_fixed_10(x: f64) -> String {
    let x = if x == 0.0 { 0.0 } else { x }; // canonicalize -0.0
    format!("{:.10}", x)
}

/// OSF-CANON v1 pre-image string (exactly what is SHA-256'd).
/// Key order: position{x,y,z} -> rotation{w,x,y,z} -> timestamp -> nonce?,
/// each real via to_fixed_10, JSON with no spaces.
pub fn canonical_preimage(state: &State, nonce: Option<&str>) -> String {
    let mut s = String::with_capacity(320);
    s.push_str("{\"position\":{\"x\":\"");
    s.push_str(&to_fixed_10(state.position[0]));
    s.push_str("\",\"y\":\"");
    s.push_str(&to_fixed_10(state.position[1]));
    s.push_str("\",\"z\":\"");
    s.push_str(&to_fixed_10(state.position[2]));
    s.push_str("\"},\"rotation\":{\"w\":\"");
    s.push_str(&to_fixed_10(state.rotation[0]));
    s.push_str("\",\"x\":\"");
    s.push_str(&to_fixed_10(state.rotation[1]));
    s.push_str("\",\"y\":\"");
    s.push_str(&to_fixed_10(state.rotation[2]));
    s.push_str("\",\"z\":\"");
    s.push_str(&to_fixed_10(state.rotation[3]));
    s.push_str("\"},\"timestamp\":");
    s.push_str(&state.timestamp.to_string());
    if let Some(n) = nonce {
        s.push_str(",\"nonce\":\"");
        s.push_str(n);
        s.push('"');
    }
    s.push('}');
    s
}
