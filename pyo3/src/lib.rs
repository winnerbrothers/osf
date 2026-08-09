// OSF (Orbital State Function)
// Copyright (c) 2026 Winner Brothers Group. All rights reserved.
// Inventor / applicant: LEE JUNGHOON.  Patent: PCT WO 2025/127469 A1.
// Licensed under PolyForm Noncommercial 1.0.0 - commercial or production use
// requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
// https://github.com/winnerbrothers/osf

//! PyO3 native-accelerated OSF module (`osf_native`).
//!
//! Exposes the shared Rust core to Python. `planet-osf` prefers this module
//! when the compiled wheel is installed and transparently falls back to the
//! pure-Python reference otherwise — both produce identical output (enforced
//! by the shared KAT suite).

use pyo3::prelude::*;

#[pyfunction]
#[pyo3(signature = (coords, axis, angular_speed, initial_timestamp, timestamp, nonce=None))]
fn state_hash(
    coords: [f64; 3],
    axis: [f64; 3],
    angular_speed: f64,
    initial_timestamp: i64,
    timestamp: i64,
    nonce: Option<String>,
) -> String {
    osf_core::state_hash(coords, axis, angular_speed, initial_timestamp, timestamp, nonce.as_deref())
}

#[pyfunction]
fn command_sign(
    session_key_hex: String,
    command: String,
    sender_state_hash: String,
    nonce: String,
    ts: i64,
    cmd_id: String,
) -> String {
    osf_core::defense::command_sign(&session_key_hex, &command, &sender_state_hash, &nonce, ts, &cmd_id)
}

#[pyfunction]
fn command_verify(
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

#[pyfunction]
fn delta_ms(environment: String) -> Option<f64> {
    osf_core::defense::delta_ms(&environment)
}

#[pymodule]
fn osf_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(state_hash, m)?)?;
    m.add_function(wrap_pyfunction!(command_sign, m)?)?;
    m.add_function(wrap_pyfunction!(command_verify, m)?)?;
    m.add_function(wrap_pyfunction!(delta_ms, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
