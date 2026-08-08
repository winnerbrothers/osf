//! # osf-core
//!
//! The single source of truth for the Orbital State Function (OSF) and
//! OSF-CANON v1. Every language binding — Python (PyO3), PHP (ext-php-rs),
//! C/C++ and embedded firmware (this crate's C ABI) — links this crate, which
//! is why they are byte-identical.
//!
//! Rights: Winner Brothers Group · inventor/applicant 이정훈 (LEE JUNGHOON) ·
//! PCT WO 2025/127469 A1. CC BY 4.0.

pub mod crypto;
pub mod defense;
pub mod quaternion;
pub mod state;

pub use quaternion::{Quat, Vec3};
pub use state::{canonical_preimage, get_state_at, State};

/// Raw OSF state hash: H(s_K(t) || nonce). The one primitive every binding
/// wraps. Pure Rust, no allocation beyond the pre-image string.
pub fn state_hash(
    coords: Vec3,
    axis: Vec3,
    angular_speed: f64,
    initial_timestamp: i64,
    timestamp: i64,
    nonce: Option<&str>,
) -> String {
    let st = get_state_at(coords, axis, angular_speed, initial_timestamp, timestamp);
    crypto::sha256_hex(&canonical_preimage(&st, nonce))
}

// ===========================================================================
// C ABI — consumed by the PHP extension, C/C++, and weapon/UAV firmware.
// All hash outputs are written as 64 lowercase hex chars + NUL into `out`
// (caller provides >= 65 bytes). Returns 0 on success, negative on error.
// ===========================================================================
use core::ffi::{c_char, c_double, c_int};
use std::ffi::CStr;

const OSF_OK: c_int = 0;
const OSF_ERR_NULL: c_int = -1;
const OSF_ERR_UTF8: c_int = -2;
const OSF_ERR_ENV: c_int = -3;

/// # Safety
/// `coords`/`axis` must point to 3 f64 each. `nonce` may be null. `out` must
/// have room for 65 bytes.
#[no_mangle]
pub unsafe extern "C" fn osf_state_hash(
    coords: *const c_double,
    axis: *const c_double,
    angular_speed: c_double,
    initial_timestamp: i64,
    timestamp: i64,
    nonce: *const c_char,
    out: *mut c_char,
) -> c_int {
    if coords.is_null() || axis.is_null() || out.is_null() {
        return OSF_ERR_NULL;
    }
    let c = core::slice::from_raw_parts(coords, 3);
    let a = core::slice::from_raw_parts(axis, 3);
    let nonce_str: Option<&str> = if nonce.is_null() {
        None
    } else {
        match CStr::from_ptr(nonce).to_str() {
            Ok(s) => Some(s),
            Err(_) => return OSF_ERR_UTF8,
        }
    };
    let hex = state_hash([c[0], c[1], c[2]], [a[0], a[1], a[2]], angular_speed, initial_timestamp, timestamp, nonce_str);
    write_hex(out, &hex)
}

/// # Safety: see `osf_state_hash`. All string args must be valid C strings.
#[no_mangle]
pub unsafe extern "C" fn osf_command_sign(
    session_key_hex: *const c_char,
    command: *const c_char,
    sender_state_hash: *const c_char,
    nonce: *const c_char,
    ts: i64,
    cmd_id: *const c_char,
    out: *mut c_char,
) -> c_int {
    let (sk, cmd, ssh, n, id) = match (
        cstr(session_key_hex), cstr(command), cstr(sender_state_hash), cstr(nonce), cstr(cmd_id),
    ) {
        (Some(a), Some(b), Some(c), Some(d), Some(e)) => (a, b, c, d, e),
        _ => return OSF_ERR_NULL,
    };
    let hex = defense::command_sign(sk, cmd, ssh, n, ts, id);
    write_hex(out, &hex)
}

/// Returns 1 if valid, 0 if invalid, negative on error.
/// # Safety: all string args must be valid C strings.
#[no_mangle]
pub unsafe extern "C" fn osf_command_verify(
    session_key_hex: *const c_char,
    command: *const c_char,
    sender_state_hash: *const c_char,
    nonce: *const c_char,
    ts: i64,
    cmd_id: *const c_char,
    signature_hex: *const c_char,
) -> c_int {
    let (sk, cmd, ssh, n, id, sig) = match (
        cstr(session_key_hex), cstr(command), cstr(sender_state_hash), cstr(nonce), cstr(cmd_id), cstr(signature_hex),
    ) {
        (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)) => (a, b, c, d, e, f),
        _ => return OSF_ERR_NULL,
    };
    if defense::command_verify(sk, cmd, ssh, n, ts, id, sig) { 1 } else { 0 }
}

/// Writes Δ (ms) for an environment into `*out`. Returns 0 or OSF_ERR_ENV.
/// # Safety: `environment` valid C string, `out` non-null.
#[no_mangle]
pub unsafe extern "C" fn osf_delta_ms(environment: *const c_char, out: *mut c_double) -> c_int {
    let env = match cstr(environment) {
        Some(s) => s,
        None => return OSF_ERR_NULL,
    };
    match defense::delta_ms(env) {
        Some(d) => { *out = d; OSF_OK }
        None => OSF_ERR_ENV,
    }
}

/// Version string, static NUL-terminated.
#[no_mangle]
pub extern "C" fn osf_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

// --- ffi helpers ---
unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() { return None; }
    CStr::from_ptr(p).to_str().ok()
}

unsafe fn write_hex(out: *mut c_char, hex: &str) -> c_int {
    if out.is_null() || hex.len() != 64 {
        return OSF_ERR_NULL;
    }
    core::ptr::copy_nonoverlapping(hex.as_ptr(), out as *mut u8, 64);
    *out.add(64) = 0; // NUL
    OSF_OK
}
