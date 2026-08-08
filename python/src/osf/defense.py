"""
OSF defense — on-device command authentication for weapons / UAV / UGV /
satellites, byte-compatible with the deployed planet-core Defense API.

Runs entirely on the device (no server round-trip): environment-adaptive
time window Δ, replay rejection, clock-skew (spoof) rejection, HMAC command
signing bound to sender state, and heartbeat drift detection.

Δ table and the sign/verify string layout mirror
`src/lib/defense-helpers.ts` and `src/lib/planet-store.ts` exactly, so an
osf-native device interoperates with the existing /api/v1/defense server.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

from ._crypto import sha256_hex, hmac_sign, hmac_verify, hex_to_bytes, random_nonce

# Δ in milliseconds per operating environment (planet-store.ts DELTA_MS_BY_ENV)
DELTA_MS_BY_ENV: Dict[str, float] = {
    "gps_disciplined": 0.1,   # 100 µs  — PTP-synced satellite payload / GNSS
    "datacenter": 1.0,        # 1 ms    — single rack / MEC / GCS datacenter
    "lan": 10.0,              # 10 ms   — military LAN / KJCCS / tactical LAN
    "field": 50.0,            # 50 ms   — tactical field / drone GCS / EW
    "satellite": 100.0,       # 100 ms  — LEO/MEO/GEO sat-ground
    "space": 500.0,           # 500 ms  — deep space / GPS-denied (heavy jamming)
}


def delta_ms(environment: str) -> float:
    try:
        return DELTA_MS_BY_ENV[environment]
    except KeyError:
        raise ValueError(f"unknown environment: {environment!r}")


def derive_session_key(
    init_state_hash: str,
    respond_state_hash: str,
    init_ephemeral_pub: str,
    respond_ephemeral_pub: str,
    handshake_id: str,
) -> str:
    """Transcript-binding session key. Matches defense-helpers deriveSessionKey.

    (Note: this binds the 3-round transcript; channel *confidentiality* comes
    from the ECDH-derived transport key — see osf.messaging. Kept identical to
    the deployed server for command-MAC interop.)
    """
    return sha256_hex(
        f"{init_state_hash}|{respond_state_hash}|{init_ephemeral_pub}|{respond_ephemeral_pub}|{handshake_id}"
    )


def _command_message(command: str, sender_state_hash: str, nonce: str, ts: int, cmd_id: str) -> str:
    return f"{command}|{sender_state_hash}|{nonce}|{ts}|{cmd_id}"


def command_sign(
    session_key_hex: str, command: str, sender_state_hash: str, nonce: str, ts: int, cmd_id: str
) -> str:
    """HMAC-SHA-256 sign a command. Matches defense-helpers signCommand."""
    key = hex_to_bytes(session_key_hex)
    return hmac_sign(key, _command_message(command, sender_state_hash, nonce, ts, cmd_id))


def command_verify(
    session_key_hex: str,
    command: str,
    sender_state_hash: str,
    nonce: str,
    ts: int,
    cmd_id: str,
    signature_hex: str,
) -> bool:
    key = hex_to_bytes(session_key_hex)
    return hmac_verify(key, _command_message(command, sender_state_hash, nonce, ts, cmd_id), signature_hex)


@dataclass
class Device:
    """A registered defense device (weapon, UAV, UGV, satellite, ...)."""
    device_id: str
    classification: str
    environment: str
    callsign: str = ""
    hsm_attested: bool = False
    revoked: bool = False
    _seen: Set[str] = field(default_factory=set)  # replay tracking (command ids)

    @property
    def delta_ms(self) -> float:
        return delta_ms(self.environment)


@dataclass
class VerifyResult:
    ok: bool
    reason: Optional[str] = None
    delta_ms: float = 0.0
    skew_ms: float = 0.0


def verify_command(
    device: Device,
    session_key_hex: str,
    command: str,
    sender_state_hash: str,
    nonce: str,
    ts: int,
    cmd_id: str,
    signature_hex: str,
    server_now_ms: int,
) -> VerifyResult:
    """Full 4-stage command verification: revoked / replay / clock-skew / HMAC.

    Mirrors the deployed /api/v1/defense/command/verify pipeline.
    """
    d = device.delta_ms
    if device.revoked:
        return VerifyResult(False, "device_revoked", d, 0.0)
    if cmd_id in device._seen:
        return VerifyResult(False, "replay_detected", d, 0.0)
    skew = abs(server_now_ms - ts)
    if skew > d:
        return VerifyResult(False, "clock_skew_exceeds_delta", d, skew)
    if not command_verify(session_key_hex, command, sender_state_hash, nonce, ts, cmd_id, signature_hex):
        return VerifyResult(False, "signature_invalid", d, skew)
    device._seen.add(cmd_id)  # commit only after full success
    return VerifyResult(True, None, d, skew)


@dataclass
class HeartbeatResult:
    alive: bool
    drift_ms: float
    within_delta: bool


def heartbeat(device: Device, device_ts_ms: int, server_now_ms: int) -> HeartbeatResult:
    """Device liveness + clock-drift detection."""
    drift = abs(server_now_ms - device_ts_ms)
    return HeartbeatResult(alive=True, drift_ms=drift, within_delta=drift <= device.delta_ms)
