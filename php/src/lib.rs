// OSF (Orbital State Function)
// Copyright (c) 2026 Winner Brothers Group. All rights reserved.
// Inventor / applicant: LEE JUNGHOON.  Patent: PCT WO 2025/127469 A1.
// Licensed under PolyForm Noncommercial 1.0.0 - commercial or production use
// requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
// https://github.com/winnerbrothers/osf

//! OSF native PHP extension.
//!
//! Exposes OSF as GLOBAL PHP functions — call `osf_state_hash(...)` the same
//! way you call `md5(...)`. Every function delegates to the shared `osf-core`
//! Rust crate, so results are byte-identical to the Python wheel, the embedded
//! C library, and the planet-core TypeScript reference.
//!
//! Build:   cargo build --release   ->  rename cdylib to `osf.so`
//! Load:    add `extension=osf.so` to php.ini   (or `pecl install osf`)
//!
//! ```php
//! <?php
//! $tag = osf_state_hash([1.0, 2.0, 3.0], [0.0, 0.0, 1.0], 90.0,
//!                       1700000000000, 1700000005000, "nonce-abc");
//! if (osf_login_verify(...)) { /* authenticated */ }
//! ```

use ext_php_rs::prelude::*;

/// H(s_K(t) || nonce). `coords` and `axis` are PHP arrays of 3 floats;
/// pass `null` for `nonce` to omit it. Returns a 64-char hex string.
#[php_function]
pub fn osf_state_hash(
    coords: Vec<f64>,
    axis: Vec<f64>,
    angular_speed: f64,
    initial_timestamp: i64,
    timestamp: i64,
    nonce: Option<String>,
) -> String {
    let c = [coords[0], coords[1], coords[2]];
    let a = [axis[0], axis[1], axis[2]];
    osf_core::state_hash(c, a, angular_speed, initial_timestamp, timestamp, nonce.as_deref())
}

/// HMAC-SHA-256 command signature (defense / weapon command path).
#[php_function]
pub fn osf_command_sign(
    session_key_hex: String,
    command: String,
    sender_state_hash: String,
    nonce: String,
    ts: i64,
    cmd_id: String,
) -> String {
    osf_core::defense::command_sign(&session_key_hex, &command, &sender_state_hash, &nonce, ts, &cmd_id)
}

/// Verify a command signature (constant-time). Returns bool.
#[php_function]
pub fn osf_command_verify(
    session_key_hex: String,
    command: String,
    sender_state_hash: String,
    nonce: String,
    ts: i64,
    cmd_id: String,
    signature_hex: String,
) -> bool {
    osf_core::defense::command_verify(
        &session_key_hex, &command, &sender_state_hash, &nonce, ts, &cmd_id, &signature_hex,
    )
}

/// Δ (ms) for an operating environment; 0.0 if unknown.
#[php_function]
pub fn osf_delta_ms(environment: String) -> f64 {
    osf_core::defense::delta_ms(&environment).unwrap_or(0.0)
}

/// Passwordless login verification: recompute the tag from the registered key
/// and compare, within Δ. `coords`/`axis` are the verifier's stored record.
#[php_function]
#[allow(clippy::too_many_arguments)]
pub fn osf_login_verify(
    coords: Vec<f64>,
    axis: Vec<f64>,
    angular_speed: f64,
    initial_timestamp: i64,
    challenge_nonce: String,
    client_ts: i64,
    server_now: i64,
    delta_ms: f64,
    tag: String,
) -> bool {
    if (server_now - client_ts).abs() as f64 > delta_ms {
        return false;
    }
    let c = [coords[0], coords[1], coords[2]];
    let a = [axis[0], axis[1], axis[2]];
    let expected = osf_core::state_hash(c, a, angular_speed, initial_timestamp, client_ts, Some(&challenge_nonce));
    // constant-time-ish compare
    if expected.len() != tag.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in expected.bytes().zip(tag.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extension version.
#[php_function]
pub fn osf_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[php_module]
pub fn get_module(module: ModuleBuilder) -> ModuleBuilder {
    // Functions annotated with #[php_function] are auto-registered in
    // ext-php-rs 0.12+ (the old `.function(wrap_function!(..))` API was removed).
    module
}
