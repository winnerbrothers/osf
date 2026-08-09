// OSF (Orbital State Function)
// Copyright (c) 2026 Winner Brothers Group. All rights reserved.
// Inventor / applicant: LEE JUNGHOON.  Patent: PCT WO 2025/127469 A1.
// Licensed under PolyForm Noncommercial 1.0.0 - commercial or production use
// requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
// https://github.com/winnerbrothers/osf

//! On-device command authentication (weapon / UAV / UGV / satellite).
//! Δ table and sign/verify string layout mirror the deployed planet-core
//! Defense API exactly, so an osf-core device interoperates with /api/v1/defense.

use crate::crypto::{hmac_sha256_hex, hmac_sha256_verify, sha256_hex};

/// Δ in milliseconds per operating environment (planet-store DELTA_MS_BY_ENV).
pub fn delta_ms(environment: &str) -> Option<f64> {
    Some(match environment {
        "gps_disciplined" => 0.1, // 100 µs
        "datacenter" => 1.0,
        "lan" => 10.0,
        "field" => 50.0,
        "satellite" => 100.0,
        "space" => 500.0,
        _ => return None,
    })
}

/// Transcript-binding session key. Matches defense-helpers deriveSessionKey.
pub fn derive_session_key(
    init_state_hash: &str,
    respond_state_hash: &str,
    init_ephemeral_pub: &str,
    respond_ephemeral_pub: &str,
    handshake_id: &str,
) -> String {
    sha256_hex(&format!(
        "{init_state_hash}|{respond_state_hash}|{init_ephemeral_pub}|{respond_ephemeral_pub}|{handshake_id}"
    ))
}

fn command_message(command: &str, sender_state_hash: &str, nonce: &str, ts: i64, cmd_id: &str) -> String {
    format!("{command}|{sender_state_hash}|{nonce}|{ts}|{cmd_id}")
}

pub fn command_sign(
    session_key_hex: &str, command: &str, sender_state_hash: &str, nonce: &str, ts: i64, cmd_id: &str,
) -> String {
    let key = hex::decode(session_key_hex).unwrap_or_default();
    hmac_sha256_hex(&key, &command_message(command, sender_state_hash, nonce, ts, cmd_id))
}

pub fn command_verify(
    session_key_hex: &str, command: &str, sender_state_hash: &str, nonce: &str, ts: i64, cmd_id: &str,
    signature_hex: &str,
) -> bool {
    let key = match hex::decode(session_key_hex) {
        Ok(k) => k,
        Err(_) => return false,
    };
    hmac_sha256_verify(&key, &command_message(command, sender_state_hash, nonce, ts, cmd_id), signature_hex)
}
