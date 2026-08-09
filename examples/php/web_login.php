<?php
/**
 * OSF (Orbital State Function) — passwordless login site in one PHP file.
 *
 * Copyright (c) 2026 Winner Brothers Group. All rights reserved.
 * Inventor / applicant: LEE JUNGHOON.  Patent: PCT WO 2025/127469 A1.
 * Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
 * requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
 *
 *     php -S localhost:8422 web_login.php      # then open http://localhost:8422
 *
 * No extension, no Composer, no database. Records and sessions are kept in JSON
 * files under ./_osf_demo/ so they survive across requests; delete that folder
 * to reset.
 *
 * Demo simplifications: the key is generated server-side and handed to the
 * browser (a real deployment generates it on the client and never transmits
 * it), there is no TLS, and the file store is not concurrency-hardened. The
 * session cookie is HttpOnly + SameSite=Strict; add Secure behind HTTPS.
 */

declare(strict_types=1);

require __DIR__ . '/../../php/osf.php';

use OSF\Auth;
use OSF\Core;
use OSF\FileSessionStore;
use OSF\Key;
use OSF\Session;

const COOKIE   = 'osf_session';
const DEMO_DIR = __DIR__ . '/_osf_demo';
const TTL_MS   = 900000;   // 15 minutes

// --- tiny JSON-file persistence so state survives between requests ----------

function demoPath(string $name): string
{
    if (!is_dir(DEMO_DIR)) mkdir(DEMO_DIR, 0700, true);
    return DEMO_DIR . '/' . $name;
}

function loadJson(string $path): array
{
    return is_file($path) ? (json_decode((string) file_get_contents($path), true) ?: []) : [];
}

function saveJson(string $path, array $data): void
{
    file_put_contents($path, json_encode($data), LOCK_EX);
    @chmod($path, 0600);
}

/** The server signing secret. Generated once, then reused. */
function serverSecret(): string
{
    $p = demoPath('secret.txt');
    if (!is_file($p)) {
        file_put_contents($p, Session::newSecret(), LOCK_EX);
        @chmod($p, 0600);
    }
    return trim((string) file_get_contents($p));
}

function jsonOut(array $payload): void
{
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

function body(): array
{
    return json_decode((string) file_get_contents('php://input'), true) ?: [];
}

// --- wiring ----------------------------------------------------------------

$recordsPath = demoPath('records.json');
$records     = loadJson($recordsPath);          // subject => record (SECRET)
$auth = new Auth(
    serverSecret(),
    $records,
    new FileSessionStore(demoPath('sessions.json')),
    500.0,
    TTL_MS
);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$in   = body();

// --- API -------------------------------------------------------------------

switch ($path) {
    case '/api/enroll':
        $user = (string) ($in['user'] ?? '');
        if ($user === '') jsonOut(['error' => 'user required']);
        [$key, $record] = $auth->enroll($user);
        $records[$user] = $record;
        saveJson($recordsPath, $records);
        // the client keeps the key; the server keeps only the record
        jsonOut(['key' => $key->toRecord()]);

    case '/api/challenge':
        $ch = $auth->challenge();
        // stash it so the next request can find it (a DB/Redis in production)
        $chPath = demoPath('challenges.json');
        $chs = loadJson($chPath);
        $chs[$ch['nonce']] = $ch;
        saveJson($chPath, $chs);
        jsonOut($ch);

    case '/api/prove':
        // DEMO ONLY: in production this runs in the browser and K never travels.
        $key = Key::fromRecord($in['key']);
        jsonOut(Auth::prove($key, $in['challenge']));

    case '/api/login':
        $user = (string) ($in['user'] ?? '');
        $chPath = demoPath('challenges.json');
        $chs = loadJson($chPath);
        $nonce = (string) ($in['challenge']['nonce'] ?? '');
        $issued = $chs[$nonce] ?? null;
        unset($chs[$nonce]);                       // one-time, consumed either way
        saveJson($chPath, $chs);
        if ($issued === null || !isset($records[$user])) jsonOut(['ok' => false]);

        $proof = $in['proof'];
        $now   = Core::now();
        $ok = ($proof['nonce'] ?? null) === $issued['nonce']
           && abs($proof['client_ts'] - $issued['issued_at']) <= 500
           && abs($now - $proof['client_ts']) <= 500
           && hash_equals(
                Core::stateHash(Key::fromRecord($records[$user]), (int) $proof['client_ts'], $issued['nonce']),
                (string) $proof['tag']
              );
        if (!$ok) jsonOut(['ok' => false]);

        $token = Session::issue($user, $now, serverSecret(),
                                new FileSessionStore(demoPath('sessions.json')), TTL_MS);
        setcookie(COOKIE, $token, [
            'expires'  => (int) (($now + TTL_MS) / 1000),
            'path'     => '/',
            'httponly' => true,
            'samesite' => 'Strict',
            // 'secure' => true,   // enable behind HTTPS
        ]);
        jsonOut(['ok' => true, 'expires_in' => (int) (TTL_MS / 1000)]);

    case '/api/whoami':
        $tok = $_COOKIE[COOKIE] ?? '';
        jsonOut(['user' => $tok !== '' ? $auth->whoami($tok) : null]);

    case '/api/logout':
        $tok = $_COOKIE[COOKIE] ?? '';
        if ($tok !== '') $auth->logout($tok);
        setcookie(COOKIE, '', ['expires' => 1, 'path' => '/']);
        jsonOut(['ok' => true]);
}

// --- page ------------------------------------------------------------------
?>
<!doctype html><html lang="en"><meta charset="utf-8">
<title>OSF passwordless login (PHP)</title>
<style>
 body{background:#0b0f17;color:#e6edf6;font:15px/1.6 system-ui,sans-serif;
      max-width:640px;margin:0 auto;padding:48px 20px}
 h1{font-size:28px;margin:0 0 4px} .sub{color:#8b97a8;margin-bottom:28px}
 button{background:#4fd6b8;color:#04231c;border:0;border-radius:8px;
        padding:10px 18px;font-weight:700;cursor:pointer;margin:4px 6px 4px 0}
 button.ghost{background:#1b2434;color:#e6edf6}
 input{background:#0e1420;color:#e6edf6;border:1px solid #222c3d;border-radius:8px;
       padding:9px 12px;font:14px monospace;width:220px}
 pre{background:#121826;border:1px solid #222c3d;border-radius:10px;padding:14px;
     white-space:pre-wrap;word-break:break-all;font:12.5px monospace;color:#9fb0c6}
 .ok{color:#3ddc84}.bad{color:#ff6b6b}
</style>
<h1>OSF passwordless login <span style="font-size:15px;color:#8b97a8">· PHP</span></h1>
<div class="sub">Pure PHP, no extension. The key stays in this browser; no password is ever sent.</div>

<div>
  <input id="user" value="alice" autocomplete="off">
  <button onclick="enroll()">1. Sign up</button>
  <button onclick="login()">2. Log in</button>
  <button class="ghost" onclick="whoami()">Who am I?</button>
  <button class="ghost" onclick="logout()">Log out</button>
</div>
<pre id="log">ready.</pre>

<script>
const $ = s => document.querySelector(s);
const log = (m, cls) => $('#log').innerHTML =
  `<span class="${cls||''}">${m}</span>\n` + $('#log').innerHTML;
const api = async (p, b) => (await fetch(p, {
  method:'POST', headers:{'Content-Type':'application/json'},
  body: JSON.stringify(b||{}), credentials:'same-origin'
})).json();
const keyName = u => 'osf_key_' + u;

async function enroll(){
  const u = $('#user').value;
  const r = await api('/api/enroll', {user:u});
  localStorage.setItem(keyName(u), JSON.stringify(r.key));
  log(`signed up "${u}". key stored in this browser only.`, 'ok');
}
async function login(){
  const u = $('#user').value;
  const key = localStorage.getItem(keyName(u));
  if(!key) return log('no key in this browser — sign up first.', 'bad');
  const ch = await api('/api/challenge');
  const pr = await api('/api/prove', {key:JSON.parse(key), challenge:ch});
  const r  = await api('/api/login', {user:u, challenge:ch, proof:pr});
  log(r.ok ? `logged in as "${u}" — session cookie set, expires in ${r.expires_in}s`
           : 'login failed.', r.ok ? 'ok' : 'bad');
}
async function whoami(){
  const r = await api('/api/whoami');
  log(r.user ? `session valid: ${r.user}` : 'no valid session.', r.user ? 'ok' : 'bad');
}
async function logout(){
  await api('/api/logout');
  log('logged out — session revoked server-side.', 'ok');
}
</script>
</html>
