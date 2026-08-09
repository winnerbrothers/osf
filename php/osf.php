<?php
/**
 * OSF (Orbital State Function) — pure PHP implementation.
 *
 * Copyright (c) 2026 Winner Brothers Group. All rights reserved.
 * Inventor / applicant: LEE JUNGHOON.  Patent: PCT WO 2025/127469 A1.
 * Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
 * requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
 * https://github.com/winnerbrothers/osf
 *
 * No extension, no Composer, no dependencies — `require 'osf.php';` and go.
 * Verified byte-identical to the Python, Rust and TypeScript implementations
 * against the shared known-answer tests (kat/test-vectors.json): 120/120 state
 * vectors and 8/8 HMAC vectors.
 *
 * A compiled extension exists in this directory for hot paths, but it is not
 * required — this file is a complete implementation on its own.
 */

declare(strict_types=1);

namespace OSF;

// ---------------------------------------------------------------------------
// Core — OSF-CANON v1 / v2
// ---------------------------------------------------------------------------

final class Core
{
    public const V2_LABEL = 'OSF-CANON-v2';

    public const DOMAIN_AUTH = 'auth';
    public const DOMAIN_TX   = 'tx';
    public const DOMAIN_CMD  = 'cmd';
    public const DOMAIN_CHAN = 'chan';

    /** Δ (ms) by operating environment. */
    public const DELTA_MS = [
        'gps_disciplined' => 0.1,
        'datacenter'      => 1.0,
        'lan'             => 10.0,
        'field'           => 50.0,
        'satellite'       => 100.0,
        'space'           => 500.0,
    ];

    /** Current epoch milliseconds. */
    public static function now(): int
    {
        return (int) round(microtime(true) * 1000);
    }

    /** CSPRNG nonce as hex. */
    public static function nonce(int $bytes = 32): string
    {
        return bin2hex(random_bytes($bytes));
    }

    /** Reproduce JavaScript Number.prototype.toFixed(10) byte-for-byte. */
    public static function toFixed10(float $x): string
    {
        if ($x == 0.0) {
            $x = 0.0; // collapse -0.0, which JS prints as "0.0000000000"
        }
        return sprintf('%.10f', $x);
    }

    /** Hamilton product of two quaternions [w, x, y, z]. */
    private static function qmul(array $a, array $b): array
    {
        return [
            $a[0] * $b[0] - $a[1] * $b[1] - $a[2] * $b[2] - $a[3] * $b[3],
            $a[0] * $b[1] + $a[1] * $b[0] + $a[2] * $b[3] - $a[3] * $b[2],
            $a[0] * $b[2] - $a[1] * $b[3] + $a[2] * $b[0] + $a[3] * $b[1],
            $a[0] * $b[3] + $a[1] * $b[2] - $a[2] * $b[1] + $a[3] * $b[0],
        ];
    }

    /**
     * The OSF state s_K(t): rotated position plus the rotation quaternion.
     *
     * @return array{position: array<float>, rotation: array<float>, timestamp: int}
     */
    public static function stateAt(Key $k, int $timestampMs): array
    {
        $elapsed = ($timestampMs - $k->initialTimestamp) / 1000.0;
        $deg = fmod($k->angularSpeed * $elapsed, 360.0);  // JS % is truncated remainder
        $rad = $deg * M_PI / 180.0;
        $s = sin($rad / 2.0);
        $q = [cos($rad / 2.0), $k->axis[0] * $s, $k->axis[1] * $s, $k->axis[2] * $s];

        $p  = [0.0, $k->coords[0], $k->coords[1], $k->coords[2]];
        $qi = [$q[0], -$q[1], -$q[2], -$q[3]];
        $r  = self::qmul(self::qmul($q, $p), $qi);

        return ['position' => [$r[1], $r[2], $r[3]], 'rotation' => $q, 'timestamp' => $timestampMs];
    }

    /** OSF-CANON v1 pre-image: exactly the string that gets hashed. */
    public static function canonical(array $state, ?string $nonce = null): string
    {
        $p = $state['position'];
        $q = $state['rotation'];
        $s = '{"position":{"x":"' . self::toFixed10($p[0])
           . '","y":"' . self::toFixed10($p[1])
           . '","z":"' . self::toFixed10($p[2])
           . '"},"rotation":{"w":"' . self::toFixed10($q[0])
           . '","x":"' . self::toFixed10($q[1])
           . '","y":"' . self::toFixed10($q[2])
           . '","z":"' . self::toFixed10($q[3])
           . '"},"timestamp":' . $state['timestamp'];
        if ($nonce !== null) {
            $s .= ',"nonce":"' . $nonce . '"';
        }
        return $s . '}';
    }

    /** OSF-CANON v1 tag: SHA-256(canonical(s_K(t)) ‖ nonce). Compatibility. */
    public static function stateHash(Key $k, int $timestampMs, ?string $nonce = null): string
    {
        return hash('sha256', self::canonical(self::stateAt($k, $timestampMs), $nonce));
    }

    /** The public, domain-separated message a v2 tag authenticates. */
    public static function v2Message(int $timestampMs, string $nonce, string $domain, string $aad = ''): string
    {
        if (str_contains($domain, '|')) {
            throw new \InvalidArgumentException("domain must not contain '|'");
        }
        return self::V2_LABEL . "|{$domain}|{$timestampMs}|{$nonce}|{$aad}";
    }

    /** OSF-CANON v2 tag (recommended): HMAC-SHA-256 keyed by the state. */
    public static function tag(
        Key $k, int $timestampMs, string $nonce,
        string $domain = self::DOMAIN_AUTH, string $aad = ''
    ): string {
        $key = self::canonical(self::stateAt($k, $timestampMs), null);
        return hash_hmac('sha256', self::v2Message($timestampMs, $nonce, $domain, $aad), $key);
    }

    /** Constant-time verification of a v2 tag. */
    public static function verifyTag(
        Key $k, int $timestampMs, string $nonce, string $candidate,
        string $domain = self::DOMAIN_AUTH, string $aad = ''
    ): bool {
        return hash_equals(self::tag($k, $timestampMs, $nonce, $domain, $aad), $candidate);
    }

    /** Δ (ms) for an environment. */
    public static function deltaMs(string $environment): float
    {
        if (!isset(self::DELTA_MS[$environment])) {
            throw new \InvalidArgumentException("unknown environment: {$environment}");
        }
        return self::DELTA_MS[$environment];
    }

    /** HMAC-SHA-256 command signature (defense path). */
    public static function commandSign(
        string $sessionKeyHex, string $command, string $senderStateHash,
        string $nonce, int $ts, string $cmdId
    ): string {
        $msg = "{$command}|{$senderStateHash}|{$nonce}|{$ts}|{$cmdId}";
        return hash_hmac('sha256', $msg, hex2bin($sessionKeyHex));
    }

    /** Verify a command signature (constant-time). */
    public static function commandVerify(
        string $sessionKeyHex, string $command, string $senderStateHash,
        string $nonce, int $ts, string $cmdId, string $signatureHex
    ): bool {
        return hash_equals(
            self::commandSign($sessionKeyHex, $command, $senderStateHash, $nonce, $ts, $cmdId),
            $signatureHex
        );
    }
}

// ---------------------------------------------------------------------------
// Key
// ---------------------------------------------------------------------------

/**
 * An OSF key K = (p₀, â, ω, t₀). Every field is secret.
 *
 * The registration record IS the key: whoever holds it can impersonate the
 * owner. OSF is symmetric, like a TOTP seed — not public-key. Protect the
 * record store accordingly.
 */
final class Key
{
    /** @param array<float> $coords @param array<float> $axis */
    public function __construct(
        public readonly array $coords,
        public readonly array $axis,
        public readonly float $angularSpeed,
        public readonly int $initialTimestamp,
    ) {}

    /** Generate a key. p₀ is drawn from a 3-D shell — the third DOF matters. */
    public static function generate(?int $initialTimestampMs = null): self
    {
        $t0 = $initialTimestampMs ?? Core::now();
        $u = self::unitVector();
        $r = self::range(1.0, 1000.0);
        return new self(
            [$u[0] * $r, $u[1] * $r, $u[2] * $r],
            self::unitVector(),
            self::range(1.0, 36000.0),
            $t0
        );
    }

    /** @return array<string, mixed> the record a verifier stores. SECRET. */
    public function toRecord(): array
    {
        return [
            'coordinates'  => ['x' => $this->coords[0], 'y' => $this->coords[1], 'z' => $this->coords[2]],
            'rotationAxis' => ['x' => $this->axis[0],   'y' => $this->axis[1],   'z' => $this->axis[2]],
            'angularSpeed' => $this->angularSpeed,
            'initialTimestamp' => $this->initialTimestamp,
        ];
    }

    public static function fromRecord(array $rec): self
    {
        return new self(
            array_values($rec['coordinates']),
            array_values($rec['rotationAxis']),
            (float) $rec['angularSpeed'],
            (int) $rec['initialTimestamp']
        );
    }

    private static function range(float $lo, float $hi): float
    {
        $u = unpack('J', "\0" . random_bytes(7))[1] / (float) (1 << 56);
        return $lo + ($hi - $lo) * $u;
    }

    /** Uniform point on the unit sphere (Marsaglia), CSPRNG-driven. */
    private static function unitVector(): array
    {
        while (true) {
            $x1 = self::range(-1.0, 1.0);
            $x2 = self::range(-1.0, 1.0);
            $s = $x1 * $x1 + $x2 * $x2;
            if ($s > 0.0 && $s < 1.0) {
                $f = 2.0 * sqrt(1.0 - $s);
                return [$x1 * $f, $x2 * $f, 1.0 - 2.0 * $s];
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/** Where live session ids are tracked, so logout can be exact. */
interface SessionStore
{
    public function add(string $sid, string $subject, int $expiresMs): void;
    public function isLive(string $sid): bool;
    public function drop(string $sid): void;
    public function dropSubject(string $subject): int;
    public function purgeExpired(int $nowMs): int;
}

/** Single-process store. Fine for CLI and tests. */
final class MemorySessionStore implements SessionStore
{
    private array $live = [];

    public function add(string $sid, string $subject, int $expiresMs): void { $this->live[$sid] = [$subject, $expiresMs]; }
    public function isLive(string $sid): bool { return isset($this->live[$sid]); }
    public function drop(string $sid): void { unset($this->live[$sid]); }

    public function dropSubject(string $subject): int
    {
        $n = 0;
        foreach ($this->live as $sid => [$subj, $_]) {
            if ($subj === $subject) { unset($this->live[$sid]); $n++; }
        }
        return $n;
    }

    public function purgeExpired(int $nowMs): int
    {
        $n = 0;
        foreach ($this->live as $sid => [$_, $exp]) {
            if ($exp <= $nowMs) { unset($this->live[$sid]); $n++; }
        }
        return $n;
    }
}

/** JSON-file store — survives across PHP requests without a database. */
final class FileSessionStore implements SessionStore
{
    public function __construct(private readonly string $path) {}

    private function read(): array
    {
        if (!is_file($this->path)) return [];
        $raw = file_get_contents($this->path);
        return $raw === false ? [] : (json_decode($raw, true) ?: []);
    }

    private function write(array $d): void
    {
        $dir = dirname($this->path);
        if (!is_dir($dir)) mkdir($dir, 0700, true);
        file_put_contents($this->path, json_encode($d), LOCK_EX);
        @chmod($this->path, 0600);
    }

    public function add(string $sid, string $subject, int $expiresMs): void
    {
        $d = $this->read(); $d[$sid] = [$subject, $expiresMs]; $this->write($d);
    }

    public function isLive(string $sid): bool { return isset($this->read()[$sid]); }

    public function drop(string $sid): void { $d = $this->read(); unset($d[$sid]); $this->write($d); }

    public function dropSubject(string $subject): int
    {
        $d = $this->read(); $n = 0;
        foreach ($d as $sid => [$subj, $_]) { if ($subj === $subject) { unset($d[$sid]); $n++; } }
        $this->write($d);
        return $n;
    }

    public function purgeExpired(int $nowMs): int
    {
        $d = $this->read(); $n = 0;
        foreach ($d as $sid => [$_, $exp]) { if ($exp <= $nowMs) { unset($d[$sid]); $n++; } }
        $this->write($d);
        return $n;
    }
}

/**
 * Bearer session tokens, signed by a server secret (not by any user key).
 *
 *   token = "osf1.<sid>.<subject_b64>.<issued>.<expires>.<mac>"
 *
 * Expiry lives inside the signed payload, so an expired token is rejected with
 * no I/O. Revocation consults the store, so logout is exact.
 */
final class Session
{
    public const VERSION = 'osf1';
    public const DEFAULT_TTL_MS = 3600000; // 1 hour

    /** Generate a server signing secret (hex). Persist it outside source control. */
    public static function newSecret(int $bytes = 32): string { return bin2hex(random_bytes($bytes)); }

    private static function b64(string $raw): string { return rtrim(strtr(base64_encode($raw), '+/', '-_'), '='); }

    private static function unb64(string $s): string
    {
        return base64_decode(str_pad(strtr($s, '-_', '+/'), (int) (ceil(strlen($s) / 4) * 4), '=')) ?: '';
    }

    private static function payload(string $sid, string $sub, int $iss, int $exp): string
    {
        return self::VERSION . "|{$sid}|{$sub}|{$iss}|{$exp}";
    }

    private static function mac(string $secretHex, string $payload): string
    {
        return hash_hmac('sha256', $payload, hex2bin($secretHex));
    }

    /** Mint a token. Call after a successful login. */
    public static function issue(
        string $subject, int $nowMs, string $secretHex,
        ?SessionStore $store = null, int $ttlMs = self::DEFAULT_TTL_MS
    ): string {
        if ($ttlMs <= 0) throw new \InvalidArgumentException('ttlMs must be positive');
        $sid = bin2hex(random_bytes(16));
        $sub = self::b64($subject);
        $exp = $nowMs + $ttlMs;
        $payload = self::payload($sid, $sub, $nowMs, $exp);
        $store?->add($sid, $subject, $exp);
        return str_replace('|', '.', $payload) . '.' . self::mac($secretHex, $payload);
    }

    /**
     * Verify a token.
     *
     * @return array{sid:string,subject:string,issued:int,expires:int}|null
     */
    public static function verify(
        string $token, int $nowMs, string $secretHex, ?SessionStore $store = null
    ): ?array {
        [$s, $reason] = self::inspect($token, $nowMs, $secretHex, $store);
        return $s;
    }

    /**
     * Verify and also report why it failed — for server-side logs only.
     *
     * @return array{0: ?array, 1: ?string}
     */
    public static function inspect(
        string $token, int $nowMs, string $secretHex, ?SessionStore $store = null
    ): array {
        $p = explode('.', $token);
        if (count($p) !== 6 || $p[0] !== self::VERSION) return [null, 'malformed'];
        [, $sid, $sub, $iss, $exp, $mac] = $p;
        if (!ctype_digit($iss) || !ctype_digit($exp)) return [null, 'malformed'];

        if (!hash_equals(self::mac($secretHex, self::payload($sid, $sub, (int) $iss, (int) $exp)), $mac)) {
            return [null, 'bad_signature'];
        }
        if ($nowMs >= (int) $exp) return [null, 'expired'];
        if ($store !== null && !$store->isLive($sid)) return [null, 'revoked'];

        return [[
            'sid' => $sid, 'subject' => self::unb64($sub),
            'issued' => (int) $iss, 'expires' => (int) $exp,
        ], null];
    }

    /** Slide the expiry: issues a fresh token and kills the old session id. */
    public static function refresh(
        string $token, int $nowMs, string $secretHex,
        ?SessionStore $store = null, int $ttlMs = self::DEFAULT_TTL_MS
    ): ?string {
        $s = self::verify($token, $nowMs, $secretHex, $store);
        if ($s === null) return null;
        $store?->drop($s['sid']);
        return self::issue($s['subject'], $nowMs, $secretHex, $store, $ttlMs);
    }

    /** Log out. True if a live session was ended. */
    public static function revoke(string $token, string $secretHex, SessionStore $store): bool
    {
        $p = explode('.', $token);
        if (count($p) !== 6 || $p[0] !== self::VERSION) return false;
        [, $sid, $sub, $iss, $exp, $mac] = $p;
        // check the signature so nobody can revoke arbitrary session ids
        if (!hash_equals(self::mac($secretHex, self::payload($sid, $sub, (int) $iss, (int) $exp)), $mac)) {
            return false;
        }
        $live = $store->isLive($sid);
        $store->drop($sid);
        return $live;
    }

    /** Log a subject out everywhere. Returns how many sessions ended. */
    public static function revokeAll(string $subject, SessionStore $store): int
    {
        return $store->dropSubject($subject);
    }
}

// ---------------------------------------------------------------------------
// Auth — login + session, wired together
// ---------------------------------------------------------------------------

/**
 * Server-side OSF login and session manager.
 *
 * The client holds the key and never transmits it; `prove()` is the only call
 * that touches it and belongs on the client side. The server holds the
 * registration records and the session secret.
 */
final class Auth
{
    private array $challenges = [];

    public function __construct(
        private string $serverSecret,
        /** @var array<string, array> subject => record. SECRET. */
        private array &$records,
        private SessionStore $store = new MemorySessionStore(),
        private float $deltaMs = 500.0,
        private int $sessionTtlMs = Session::DEFAULT_TTL_MS,
    ) {}

    // -- enrollment ---------------------------------------------------------

    /** @return array{0: Key, 1: array} the client's key and the server's record */
    public function enroll(string $subject): array
    {
        $key = Key::generate();
        $this->records[$subject] = $key->toRecord();
        return [$key, $key->toRecord()];
    }

    public function registerRecord(string $subject, array $record): void
    {
        $this->records[$subject] = $record;
    }

    public function isEnrolled(string $subject): bool { return isset($this->records[$subject]); }

    // -- login --------------------------------------------------------------

    /** Step 1 (server): issue a one-time challenge. */
    public function challenge(?int $nowMs = null): array
    {
        $now = $nowMs ?? Core::now();
        $ch = ['nonce' => Core::nonce(32), 'issued_at' => $now];
        $this->challenges[$ch['nonce']] = $ch;
        return $ch;
    }

    /** Step 2 (client): answer with the key. K never leaves the client. */
    public static function prove(Key $key, array $challenge, ?int $nowMs = null): array
    {
        $now = $nowMs ?? Core::now();
        return [
            'client_ts' => $now,
            'nonce'     => $challenge['nonce'],
            'tag'       => Core::stateHash($key, $now, $challenge['nonce']),
        ];
    }

    /** Step 3 (server): verify, then issue a session token. Null on failure. */
    public function login(string $subject, array $challenge, array $proof, ?int $nowMs = null): ?string
    {
        $now = $nowMs ?? Core::now();
        $issued = $this->challenges[$challenge['nonce']] ?? null;
        unset($this->challenges[$challenge['nonce']]);   // one-time, consumed either way
        if ($issued === null) return null;
        if (!isset($this->records[$subject])) return null;
        if (($proof['nonce'] ?? null) !== $issued['nonce']) return null;
        if (abs($proof['client_ts'] - $issued['issued_at']) > $this->deltaMs) return null;
        if (abs($now - $proof['client_ts']) > $this->deltaMs) return null;

        $key = Key::fromRecord($this->records[$subject]);
        $expected = Core::stateHash($key, (int) $proof['client_ts'], $issued['nonce']);
        if (!hash_equals($expected, (string) $proof['tag'])) return null;

        return Session::issue($subject, $now, $this->serverSecret, $this->store, $this->sessionTtlMs);
    }

    // -- session ------------------------------------------------------------

    /** Subject for a valid token, else null. Call on every protected request. */
    public function whoami(string $token, ?int $nowMs = null): ?string
    {
        $s = Session::verify($token, $nowMs ?? Core::now(), $this->serverSecret, $this->store);
        return $s['subject'] ?? null;
    }

    public function session(string $token, ?int $nowMs = null): ?array
    {
        return Session::verify($token, $nowMs ?? Core::now(), $this->serverSecret, $this->store);
    }

    public function refresh(string $token, ?int $nowMs = null): ?string
    {
        return Session::refresh($token, $nowMs ?? Core::now(), $this->serverSecret, $this->store, $this->sessionTtlMs);
    }

    public function logout(string $token): bool
    {
        return Session::revoke($token, $this->serverSecret, $this->store);
    }

    public function logoutEverywhere(string $subject): int
    {
        return Session::revokeAll($subject, $this->store);
    }

    public function purge(?int $nowMs = null): int
    {
        $now = $nowMs ?? Core::now();
        $n = 0;
        foreach ($this->challenges as $nonce => $c) {
            if ($now - $c['issued_at'] > max($this->deltaMs * 4, 30000)) { unset($this->challenges[$nonce]); $n++; }
        }
        return $this->store->purgeExpired($now) + $n;
    }
}
