# Installation

OSF ships as one Rust core with thin bindings, so every language produces
byte-identical output. Pick your language below.

| Target | Status | Command |
|---|---|---|
| **Python** | ✅ published | `pip install planet-osf` |
| **Rust** | ✅ source | `osf-core = { git = "https://github.com/winnerbrothers/osf" }` |
| **C / C++ / embedded** | ✅ source | build `osf-core` as a static/shared lib, include `osf.h` |
| **PHP** | 🟡 builds in CI, not yet packaged | build from `php/`, then `extension=osf.so` |
| **PECL / apt** | ⬜ planned | `pecl install osf` · `apt install php-osf` |

---

## Python

```bash
pip install planet-osf
```

Core, login, transactions and defense command auth need **no third-party
dependencies** (standard library only). The forward-secret messaging channel
needs one extra package:

```bash
pip install "planet-osf[messaging]"     # adds `cryptography` for ECDH + AES-GCM
```

Verify:

```bash
python -c "import osf, time; K = osf.keygen(int(time.time()*1000)); \
print(osf.tag(K, int(time.time()*1000), 'hello'))"
```

Requires Python 3.9+. The distribution is named `planet-osf`; the import name
is `osf` (like `beautifulsoup4` → `bs4`).

### Optional native acceleration

A PyO3 wheel (`osf_native`) exposes the same functions backed by the Rust core.
Output is identical — the shared known-answer tests enforce it.

```bash
cd pyo3 && maturin build --release && pip install target/wheels/*.whl
```

---

## Rust

```toml
[dependencies]
osf-core = { git = "https://github.com/winnerbrothers/osf", branch = "main" }
```

Feature flags:

| Feature | Default | Pulls in |
|---|---|---|
| `rng` | ✅ | `getrandom` — key generation |
| `messaging` | — | `p256`, `aes-gcm` — ECDH + AEAD |

No OpenSSL: hashing and MAC come from RustCrypto, and the transcendental
functions come from the `libm` crate, which is what makes results bit-identical
across targets.

```bash
cargo test --all-features     # runs the KAT suite
```

---

## C / C++ / embedded

Build the core, then link against it and include the header.

```bash
cd rust
cargo build --release
#   target/release/libosf_core.so      (cdylib — Linux/macOS)
#   target/release/libosf_core.a       (staticlib — firmware)
#   target/release/osf_core.dll        (Windows)
```

```c
#include "osf.h"            /* rust/include/osf.h */

double coords[3] = {312.61, 618.95, -634.53};
double axis[3]   = {-0.716, 0.083, 0.693};
char   tag[OSF_OUT_LEN];

if (osf_state_hash(coords, axis, 23667.67,
                   1700000000000LL, 1700000005000LL, "nonce", tag) == OSF_OK) {
    printf("%s\n", tag);
}
```

Cross-compiling for a microcontroller:

```bash
rustup target add thumbv7em-none-eabihf
cargo build --release --target thumbv7em-none-eabihf --no-default-features
```

`--no-default-features` drops `getrandom` (no OS entropy source on bare metal) —
provision keys externally and pass them in.

---

## PHP

The extension builds in CI today but is not yet on PECL. To build it yourself:

```bash
cd php
cargo build --release
cp target/release/libphp_osf.so /usr/lib/php/$(php -i | grep -oP 'api\d+')/osf.so
echo "extension=osf.so" | sudo tee /etc/php/conf.d/osf.ini
php -r 'echo osf_version(), "\n";'
```

Requires a Rust toolchain and PHP 8.1+ development headers (`php-dev`).

Planned once packaging lands:

```bash
pecl install osf
# or
sudo add-apt-repository ppa:winnerbrothers/osf && sudo apt install php-osf
```

---

## Verifying an installation

Every binding is gated on one shared file, `kat/test-vectors.json`. To confirm
your build agrees with the reference:

```bash
# Python
cd python && python -m unittest discover -s tests -v

# Rust
cd rust && cargo test --all-features

# Regenerate the vectors from the TypeScript reference (needs Node 20+)
node kat/generate_kat.mjs --check
```

---

## License

Free for noncommercial use under PolyForm Noncommercial 1.0.0. Commercial or
production use requires a separate license that includes a patent grant for
PCT WO 2025/127469 A1 — see [`LICENSE-COMMERCIAL.md`](../LICENSE-COMMERCIAL.md).

Winner Brothers Group · inventor/applicant LEE JUNGHOON (이정훈).
