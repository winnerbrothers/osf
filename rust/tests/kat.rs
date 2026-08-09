// OSF (Orbital State Function)
// Copyright (c) 2026 Winner Brothers Group. All rights reserved.
// Inventor / applicant: LEE JUNGHOON.  Patent: PCT WO 2025/127469 A1.
// Licensed under PolyForm Noncommercial 1.0.0 - commercial or production use
// requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
// https://github.com/winnerbrothers/osf

//! KAT determinism: the Rust core must reproduce the deployed TypeScript core
//! (planet-core) byte-for-byte on every known-answer vector. This is the CI
//! gate that guarantees the native extension is byte-identical to the
//! reference. Run with:  cargo test
//!
//! Vectors live in the shared file ../kat/test-vectors.json (one file, all
//! bindings validate against it).

use osf_core::{crypto, state_hash};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn load() -> Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("kat");
    p.push("test-vectors.json");
    let raw = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e));
    serde_json::from_str(&raw).expect("valid KAT json")
}

fn v3(o: &Value) -> [f64; 3] {
    [o["x"].as_f64().unwrap(), o["y"].as_f64().unwrap(), o["z"].as_f64().unwrap()]
}

#[test]
fn state_hash_matches_reference() {
    let data = load();
    let vs = data["stateVectors"].as_array().unwrap();
    assert!(vs.len() >= 100, "expected a substantial KAT set");
    let mut pos_bit = 0usize;
    for v in vs {
        let k = &v["k"];
        let coords = v3(&k["coordinates"]);
        let axis = v3(&k["rotationAxis"]);
        let speed = k["angularSpeed"].as_f64().unwrap();
        let t0 = k["initialTimestamp"].as_i64().unwrap();
        let t = v["t"].as_i64().unwrap();
        let ex = &v["expected"];
        let nonce = v["nonce"].as_str().unwrap();

        let h = state_hash(coords, axis, speed, t0, t, None);
        let hn = state_hash(coords, axis, speed, t0, t, Some(nonce));
        assert_eq!(h, ex["stateHash"].as_str().unwrap(), "stateHash idx {}", v["idx"]);
        assert_eq!(hn, ex["stateHashNonce"].as_str().unwrap(), "stateHashNonce idx {}", v["idx"]);

        // informational raw-f64 bit-identity (not required; toFixed(10) absorbs drift)
        let st = osf_core::get_state_at(coords, axis, speed, t0, t);
        if st.position == v3(&ex["position"]) {
            pos_bit += 1;
        }
    }
    println!("[KAT] raw position bit-identical: {}/{} (hash-identity is 100%)", pos_bit, vs.len());
}

#[test]
fn hmac_matches_reference() {
    let data = load();
    for hv in data["hmacVectors"].as_array().unwrap() {
        let key = hex::decode(hv["keyHex"].as_str().unwrap()).unwrap();
        let sig = crypto::hmac_sha256_hex(&key, hv["msg"].as_str().unwrap());
        assert_eq!(sig, hv["sig"].as_str().unwrap());
    }
}
