//! Hash / HMAC primitives (RustCrypto; no OpenSSL). Byte-compatible with the
//! TS core and the Python reference — verified by the KAT suite.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub fn sha256_hex(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    hex::encode(h.finalize())
}

pub fn hmac_sha256_hex(key: &[u8], data: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time HMAC verification.
pub fn hmac_sha256_verify(key: &[u8], data: &str, signature_hex: &str) -> bool {
    let sig = match hex::decode(signature_hex) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data.as_bytes());
    mac.verify_slice(&sig).is_ok()
}
