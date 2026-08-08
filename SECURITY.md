# Security Policy

## Reporting a vulnerability

Email **official@winnerbrothers.org** (or jason@winnerbrothers.org) with details
and a proof of concept. We aim to acknowledge within 5 business days and
coordinate a fix + disclosure timeline. Please do not open a public issue for an
unpatched vulnerability.

For the **specific claim** that OSF tags are unforgeable, there is a public,
self-verifying challenge — see [`challenge/`](./challenge/) and
<https://winnerbrothers.github.io/osf/>.

## Honest security model — read this before deploying

OSF's security rests on the **secret key `K`** staying secret. The algorithm is
fully open by design (Kerckhoffs's principle). Two things you must understand:

### 1. Key storage — default is plaintext process memory (NOT an HSM)

- `osf.keygen()` produces `K` with a CSPRNG (`os.urandom`) and holds it in
  **ordinary process memory**. It is **not** in an HSM, TPM, or secure enclave.
- The `hsm_attested` field on a defense `Device` is a **metadata flag** (a claim
  you record); it does **not** move the key into hardware or enforce anything.
- Python cannot reliably wipe secrets from memory (immutable `bytes`/`str` are
  copied; the GC relocates them), so `K` can linger. Plaintext-memory keys are
  exposed to memory dumps, swap/hibernation files, core dumps, a debugger/root,
  cold-boot attacks, and memory-scraping malware.
- **Important:** the formal OSF theorems assume `K` is **isolated** (HSM /
  enclave). Plaintext memory does **not** meet that assumption, so real-world
  security is weaker than the analytic bounds until you isolate the key.

**Mitigations today:** never log `K`; disable core dumps; encrypt swap; use
short-lived keys; run inside a hardened enclave where possible.

**Roadmap (priority):** a pluggable key backend — software (default) →
PKCS#11 / cloud KMS / TPM / Secure Enclave — so production and defense
deployments keep `K` in hardware. Until shipped, treat key isolation as
**bring-your-own**.

### 2. Post-quantum scope

The authentication core reduces to SHA-256 (hash-based; Grover-only, ~79-bit PQ).
The **forward-secrecy** layer uses ECDH P-256 — **classical DDH, not
post-quantum** (breakable by Shor). For post-quantum forward secrecy, pair with
ML-KEM. Do not represent the ECDH layer as quantum-safe.

## Scope

This policy covers the `planet-osf` package and the `osf-core` crate in this
repository. It does not authorize testing against any live third-party system.

---

Winner Brothers Group · inventor/applicant LEE JUNGHOON (이정훈) · PCT WO 2025/127469 A1.
