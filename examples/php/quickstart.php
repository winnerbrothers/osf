<?php
/**
 * OSF (Orbital State Function) — everything OSF does, in one runnable file.
 *
 * Copyright (c) 2026 Winner Brothers Group. All rights reserved.
 * Inventor / applicant: LEE JUNGHOON.  Patent: PCT WO 2025/127469 A1.
 * Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
 * requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
 *
 *     php quickstart.php
 *
 * No extension, no Composer, no network. Pure PHP.
 */

declare(strict_types=1);

require __DIR__ . '/../../php/osf.php';

use OSF\Auth;
use OSF\Core;
use OSF\Key;
use OSF\MemorySessionStore;
use OSF\Session;

function section(int $n, string $title): void
{
    echo "\n" . str_repeat('=', 68) . "\n{$n}. {$title}\n" . str_repeat('=', 68) . "\n";
}

function yn(bool $b): string { return $b ? 'true' : 'false'; }

$now = Core::now();

// ------------------------------------------------------------- 1. one-liner
section(1, 'The one-liner — authenticate like md5()');

$K = Key::generate();
$t = Core::now();
echo "  key generated (7 CSPRNG params, never transmitted)\n";
echo '  Core::tag($K, $t, "hello") = ' . Core::tag($K, $t, 'hello') . "\n";
echo '  deterministic?           ' . yn(Core::tag($K, $t, 'hello') === Core::tag($K, $t, 'hello')) . "\n";
echo '  different nonce differs? ' . yn(Core::tag($K, $t, 'hello') !== Core::tag($K, $t, 'world')) . "\n";
echo '  domain-separated?        '
   . yn(Core::tag($K, $t, 'n', Core::DOMAIN_AUTH) !== Core::tag($K, $t, 'n', Core::DOMAIN_TX))
   . "  (a login tag can't be replayed as a payment)\n";

// -------------------------------------------------------- 2. login + session
section(2, 'Login and logout — with a real session');

$records = [];                                     // subject => record (SECRET)
$auth = new Auth(Session::newSecret(), $records, new MemorySessionStore());

[$clientKey, $record] = $auth->enroll('alice');    // sign-up. client keeps the key.
echo "  enrolled 'alice'\n";

$challenge = $auth->challenge();                   // server -> client
$proof     = Auth::prove($clientKey, $challenge);  // client (holds K)
$token     = $auth->login('alice', $challenge, $proof);
echo '  login  -> ' . ($token !== null ? 'OK' : 'FAILED') . "\n";
echo '  token  -> ' . substr((string) $token, 0, 44) . "...\n";
echo '  whoami -> ' . var_export($auth->whoami((string) $token), true) . "\n";

$s = $auth->session((string) $token);
printf("  session: sid=%s... expires in %ds\n",
    substr($s['sid'], 0, 12), (int) (($s['expires'] - Core::now()) / 1000));

$auth->logout((string) $token);
echo "  logout -> session ended\n";
echo '  whoami after logout -> ' . var_export($auth->whoami((string) $token), true) . "  (token is now dead)\n";

// -------------------------------------------------------------- 3. it's safe
section(3, 'The failure cases actually fail');

$ch2  = $auth->challenge();
$bad  = Auth::prove(Key::generate(), $ch2);         // attacker's own key
echo '  wrong key         -> ' . var_export($auth->login('alice', $ch2, $bad), true) . "\n";

$ch3  = $auth->challenge();
$good = Auth::prove($clientKey, $ch3);
$tok3 = $auth->login('alice', $ch3, $good);
echo '  replay same proof -> ' . var_export($auth->login('alice', $ch3, $good), true)
   . "  (challenge is one-time)\n";

$forged = 'osf1.' . str_repeat('a', 32) . '.YWxpY2U.1.9999999999999.' . str_repeat('b', 64);
echo '  forged token      -> ' . var_export($auth->whoami($forged), true) . "\n";

$auth->logoutEverywhere('alice');
echo '  logout everywhere -> ' . var_export($auth->whoami((string) $tok3), true) . "  (all sessions killed)\n";

// ------------------------------------------------------------- 4. cross-lang
section(4, 'Byte-identical to Python / Rust / TypeScript');

$katPath = __DIR__ . '/../../kat/test-vectors.json';
$kat = json_decode((string) file_get_contents($katPath), true);
$okState = 0; $okHmac = 0;
foreach ($kat['stateVectors'] as $v) {
    $k = Key::fromRecord([
        'coordinates'      => $v['k']['coordinates'],
        'rotationAxis'     => $v['k']['rotationAxis'],
        'angularSpeed'     => $v['k']['angularSpeed'],
        'initialTimestamp' => $v['k']['initialTimestamp'],
    ]);
    if (Core::stateHash($k, $v['t'], $v['nonce']) === $v['expected']['stateHashNonce']) $okState++;
}
foreach ($kat['hmacVectors'] as $hv) {
    if (hash_hmac('sha256', $hv['msg'], (string) hex2bin($hv['keyHex'])) === $hv['sig']) $okHmac++;
}
printf("  state vectors: %d/%d\n", $okState, count($kat['stateVectors']));
printf("  hmac  vectors: %d/%d\n", $okHmac, count($kat['hmacVectors']));
echo "  -> the same key and time produce the same tag in every language.\n";

// --------------------------------------------------------------- 5. defense
section(5, 'On-device command auth (UAV / satellite / weapon)');

$sk    = hash('sha256', 'session');
$ssh   = hash('sha256', 'sender-state');
$nonce = Core::nonce(16);
$ts    = Core::now();
$sig   = Core::commandSign($sk, 'RTL', $ssh, $nonce, $ts, 'cmd-1');

printf("  Δ for 'field'    -> %s ms\n", Core::deltaMs('field'));
printf("  Δ for 'space'    -> %s ms\n", Core::deltaMs('space'));
echo '  valid command    -> ' . yn(Core::commandVerify($sk, 'RTL', $ssh, $nonce, $ts, 'cmd-1', $sig)) . "\n";
echo '  tampered body    -> ' . yn(Core::commandVerify($sk, 'LAUNCH', $ssh, $nonce, $ts, 'cmd-1', $sig)) . "\n";
echo "  (replay + clock-skew rejection: track command ids and compare |now - ts| <= Δ;\n";
echo "   see examples/php/login.php for the pattern, or osf.defense in Python.)\n";

echo "\nDone.\n\n";
