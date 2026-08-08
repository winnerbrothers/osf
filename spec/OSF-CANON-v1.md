# OSF-CANON v1 — Canonical Encoding Specification

**Status:** frozen · **Arbiter:** `kat/test-vectors.json` · **Reference source:** `planet-core@1.0.0`

Every OSF binding (Rust core, Python, PHP, C/embedded, TypeScript) MUST produce
identical `stateHash` output for identical inputs. This document defines the
byte-exact computation. Conformance = passing the KAT suite.

> Rights: Winner Brothers Group · inventor/applicant 이정훈 (LEE JUNGHOON) ·
> PCT WO 2025/127469 A1 · PolyForm Noncommercial 1.0.0 (commercial license available).

---

## 1. Key

`K = (p₀, â, ω, t₀)`

| symbol | field | type | domain |
|---|---|---|---|
| p₀ | `coordinates` | 3×f64 | bounded shell, ‖p₀‖ ∈ [1, 1000] |
| â | `rotationAxis` | 3×f64 | unit vector on S² |
| ω | `angularSpeed` | f64 | [1, 36000] deg/s |
| t₀ | `initialTimestamp` | i64 | epoch milliseconds |

## 2. State function s_K(t)

Given wall-clock `t` (epoch ms):

```
elapsed   = (t − t₀) / 1000                      # seconds, f64
angleDeg  = fmod(ω · elapsed, 360)               # TRUNCATED remainder (JS %), not floored
angleRad  = angleDeg · π / 180
q         = ( cos(angleRad/2),                    # rotation quaternion (w,x,y,z)
              âx·sin(angleRad/2),
              ây·sin(angleRad/2),
              âz·sin(angleRad/2) )
position  = q · (0, p₀) · q⁻¹                     # quaternion sandwich; take (x,y,z)
rotation  = q
```

`q⁻¹` = conjugate `(w, −x, −y, −z)` (unit quaternion). Quaternion product is the
Hamilton product (see `quaternion.rs::multiply`).

**Canonical math is pinned to a fixed `sin`/`cos`/`fmod`.** The Rust core uses the
`libm` crate (a fixed fdlibm/MUSL port) so these are bit-identical on every target.
Platform libm (used by CPython/V8/glibc) is NOT canonical — see §5.

## 3. Canonical pre-image

The string that is SHA-256'd. **Frozen** — key order and formatting are normative:

```json
{"position":{"x":"<f10>","y":"<f10>","z":"<f10>"},"rotation":{"w":"<f10>","x":"<f10>","y":"<f10>","z":"<f10>"},"timestamp":<int>[,"nonce":"<hex>"]}
```

- No whitespace. Keys in the exact order shown.
- `<f10>` = the real formatted as **`toFixed(10)`** — a decimal string with exactly
  10 fractional digits, round-half-to-even, with negative zero collapsed to
  `"0.0000000000"` (no leading `-`).
- `timestamp` is a bare integer (not quoted).
- `nonce`, when present, is appended last as a quoted string.

## 4. Tag

```
stateHash = SHA-256( canonical_preimage )   # lowercase hex, 64 chars
```

HMAC path (defense command MAC): `HMAC-SHA-256(key, "cmd|senderStateHash|nonce|ts|cmdId")`,
key = raw bytes of the hex session key.

## 5. Determinism boundary (empirically established, 2026-08)

Measured against 120 KAT vectors spanning coordinate shells {1, 10, 100, 1000},
speeds {1 … 36000} deg/s, and elapsed times {0 … ~1 year}:

| metric | result |
|---|---|
| Python (CPython libm) raw f64 position bit-identical to V8 | **116 / 120** |
| Python canonical string identical to V8 | **120 / 120** |
| Python final `stateHash` identical to V8 | **120 / 120** |
| HMAC-SHA-256 identical | **8 / 8** |

**Interpretation.** Different platform libm implementations (V8's fdlibm vs
CPython's MSVCRT libm) disagree by ≤ 1 ULP in the raw f64 state for 4 of 120
vectors. `toFixed(10)` absorbs that drift in **all** cases at these magnitudes,
so the hash is identical. **But the margin is finite** — at larger magnitudes or
on other libm implementations a 1-ULP difference could land on a rounding
boundary and flip the 10th digit.

**Consequence (normative).** Cross-platform, cross-language byte-identity is
guaranteed by all production bindings linking ONE math implementation — the
`osf-core` Rust crate's `libm`. This is the reason the architecture is
"one Rust core, thin bindings" rather than independent per-language ports. The
pure-Python `planet-osf` package is a **reference oracle** that matches the TS
source on this platform; where absolute cross-platform identity is required
(e.g. a device verifying another vendor's device), both link `osf-core`.

## 6. Conformance

An implementation conforms to OSF-CANON v1 iff, for every vector in
`kat/test-vectors.json`, it reproduces `stateHash`, `stateHashNonce`, and the
`hmacVectors[].sig`. CI runs this gate for Rust (`tests/kat.rs`), Python
(`tests/test_kat.py`), and re-derives the vectors from the TS source
(`kat-freshness`).

## 7. Versioning

This is v1. A future change to the encoding (e.g. a different fractional
precision or a bit-exact float encoding) increments to `v2`; producers stamp the
version so verifiers stay backward-compatible. v1 is frozen to match the
already-deployed `/api/v1` server and existing planet-core clients.
