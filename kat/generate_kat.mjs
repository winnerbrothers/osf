// OSF (Orbital State Function)
// Copyright (c) 2026 Winner Brothers Group. All rights reserved.
// Inventor / applicant: LEE JUNGHOON.  Patent: PCT WO 2025/127469 A1.
// Licensed under PolyForm Noncommercial 1.0.0 - commercial or production use
// requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
// https://github.com/winnerbrothers/osf

/**
 * OSF-CANON v1 — Known-Answer-Test (KAT) generator.
 *
 * Ground truth is the deployed TypeScript reference implementation
 * (`packages/planet-core`). This script drives its REAL functions
 * (getStateAt / hashState / sha256 / hmacSign) and emits deterministic
 * vectors that every other binding (Python, Rust, PHP) must reproduce
 * byte-for-byte.
 *
 * It also RE-DERIVES the canonical pre-image string independently and
 * asserts sha256(canonical) === hashState(state, nonce). If that self-check
 * ever fails, our understanding of OSF-CANON v1 is wrong — fail loudly.
 *
 * Usage:  node kat/generate_kat.mjs  > kat/test-vectors.json
 *         node kat/generate_kat.mjs --check   (self-check only, no output file noise)
 */
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import path from 'path';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const core = require(path.join(here, '..', '..', 'planet-core', 'dist', 'index.js'));
const { getStateAt, hashState, sha256, hmacSign } = core;

/* ---- deterministic PRNG (mulberry32) so vectors are reproducible ---- */
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(0x0_5F_0F_01); // fixed seed
const rid = mulberry32(0xC0FFEE);     // separate stream for nonces

function unitVec(r) {
  // uniform-ish point on S^2
  const u = r() * 2 - 1;
  const th = r() * 2 * Math.PI;
  const s = Math.sqrt(1 - u * u);
  return { x: s * Math.cos(th), y: s * Math.sin(th), z: u };
}
function hexNonce(r, bytes = 32) {
  let s = '';
  for (let i = 0; i < bytes; i++) s += Math.floor(r() * 256).toString(16).padStart(2, '0');
  return s;
}

/**
 * Re-derivation of OSF-CANON v1 pre-image, INDEPENDENT of planet-core's
 * hashState, so we validate the spec text against the real code.
 * Mirrors planet-state.ts::hashState exactly.
 */
function canonicalPreimage(state, nonce) {
  const obj = {
    position: {
      x: state.position.x.toFixed(10),
      y: state.position.y.toFixed(10),
      z: state.position.z.toFixed(10),
    },
    rotation: {
      w: state.rotation.w.toFixed(10),
      x: state.rotation.x.toFixed(10),
      y: state.rotation.y.toFixed(10),
      z: state.rotation.z.toFixed(10),
    },
    timestamp: state.timestamp,
    ...(nonce !== undefined && { nonce }),
  };
  return JSON.stringify(obj);
}

async function main() {
  const checkOnly = process.argv.includes('--check');
  const vectors = [];

  // Coordinate magnitude buckets: probe the determinism boundary.
  // Small coords are forgiving; ~1000 coords push toFixed(10) to the
  // double-precision edge where libm sin/cos ULP drift can flip digits.
  const shells = [1, 10, 100, 1000];
  const speeds = [1, 90, 360.5, 3600, 36000]; // deg/s incl. non-integer
  const elapsedMs = [0, 1, 37, 1000, 86_400_000, 31_557_600_000]; // 0s .. ~1yr

  let idx = 0;
  for (const shell of shells) {
    for (const speed of speeds) {
      for (const dt of elapsedMs) {
        const axis = unitVec(rnd);
        const dir = unitVec(rnd);
        const coordinates = { x: dir.x * shell, y: dir.y * shell, z: dir.z * shell };
        const rotationConditions = { angularSpeed: speed };
        const initialTimestamp = 1_700_000_000_000 + Math.floor(rnd() * 1_000_000);
        const timestamp = initialTimestamp + dt;
        const nonce = hexNonce(rid);

        const state = getStateAt(coordinates, axis, rotationConditions, initialTimestamp, timestamp);

        // Ground-truth hashes from the REAL reference implementation:
        const stateHash = await hashState(state);            // no nonce
        const stateHashNonce = await hashState(state, nonce); // with nonce

        // Independent re-derivation + self-check:
        const canonicalNoNonce = canonicalPreimage(state, undefined);
        const canonical = canonicalPreimage(state, nonce);
        const reHash = await sha256(canonicalNoNonce);
        const reHashNonce = await sha256(canonical);
        if (reHash !== stateHash || reHashNonce !== stateHashNonce) {
          throw new Error(`SELF-CHECK FAILED at idx ${idx}: canonical re-derivation != hashState`);
        }

        vectors.push({
          idx,
          k: {
            coordinates,
            rotationAxis: axis,
            angularSpeed: speed,
            initialTimestamp,
          },
          t: timestamp,
          nonce,
          expected: {
            // raw doubles as shortest round-trip decimal (lets a port isolate
            // math divergence from formatting divergence)
            position: state.position,
            rotation: state.rotation,
            canonicalNoNonce,
            canonical,
            stateHash,
            stateHashNonce,
          },
        });
        idx++;
      }
    }
  }

  // HMAC-SHA-256 vectors (command/tx signing path)
  const hmacVectors = [];
  for (let i = 0; i < 8; i++) {
    const keyHex = hexNonce(rnd, 32);
    const msg = `cmd|payload-${i}|state${hexNonce(rid, 4)}|nonce${hexNonce(rid, 8)}|ts${1_700_000_000_000 + i}|id${i}`;
    const keyBuf = Buffer.from(keyHex, 'hex');
    const sig = await hmacSign(keyBuf.buffer.slice(keyBuf.byteOffset, keyBuf.byteOffset + keyBuf.byteLength), msg);
    hmacVectors.push({ keyHex, msg, sig });
  }

  const out = {
    spec: 'OSF-CANON v1',
    source: 'planet-core@1.0.0 (dist/index.js)',
    generatedBy: 'kat/generate_kat.mjs',
    note: 'Ground-truth vectors. Every OSF binding MUST reproduce stateHash / stateHashNonce / sig byte-for-byte.',
    stateVectors: vectors,
    hmacVectors,
  };

  if (checkOnly) {
    console.error(`self-check OK: ${vectors.length} state vectors, ${hmacVectors.length} hmac vectors`);
    return;
  }
  process.stdout.write(JSON.stringify(out, null, 2));
  console.error(`generated ${vectors.length} state vectors + ${hmacVectors.length} hmac vectors (self-check passed)`);
}

main().catch((e) => { console.error(e); process.exit(1); });
