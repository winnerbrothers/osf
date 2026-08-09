# OSF (Orbital State Function)
# Copyright (c) 2026 Winner Brothers Group. All rights reserved.
# Inventor / applicant: LEE JUNGHOON (이정훈).  Patent: PCT WO 2025/127469 A1.
# Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
# requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
# https://github.com/winnerbrothers/osf

"""
A working passwordless login site in one file — no web framework needed.

    pip install planet-osf
    python web_login.py            # then open http://localhost:8000

Only the Python standard library plus `planet-osf`. The browser holds the key
in localStorage and does the challenge/response in JavaScript; the server never
sees the key, only the tag.

This is a demo, so a few things are deliberately simple: keys live in the
browser's localStorage (a real deployment would use WebCrypto's non-extractable
storage or a hardware token), records are in memory, and there is no TLS. The
session cookie is HttpOnly and SameSite=Strict; add Secure once you are behind
HTTPS.
"""
from __future__ import annotations

import json
import os
import sys
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

import osf
from osf.auth import Authenticator
from osf.key import Key
from osf.login import Challenge, Proof

# Windows reserves scattered port ranges (Hyper-V/WSL), where binding fails with
# WinError 10013. Override if 8421 is taken:  python web_login.py 9000
PORT = int(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("OSF_DEMO_PORT", 8421))
COOKIE = "osf_session"

auth = Authenticator(session_ttl_ms=15 * 60 * 1000)   # 15-minute sessions


PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<title>OSF passwordless login</title>
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
<h1>OSF passwordless login</h1>
<div class="sub">No password is ever typed, stored, or sent. The key stays in this browser.</div>

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
  `<span class="${cls||''}">${m}</span>\\n` + $('#log').innerHTML;
const api = async (p, b) => (await fetch(p, {
  method:'POST', headers:{'Content-Type':'application/json'},
  body: JSON.stringify(b||{}), credentials:'same-origin'
})).json();
const keyName = u => 'osf_key_' + u;

async function enroll(){
  const u = $('#user').value;
  const r = await api('/api/enroll', {user:u});
  localStorage.setItem(keyName(u), JSON.stringify(r.key));   // client keeps the key
  log(`signed up "${u}". key stored in this browser only.`, 'ok');
}

async function login(){
  const u = $('#user').value;
  const key = localStorage.getItem(keyName(u));
  if(!key) return log('no key in this browser — sign up first.', 'bad');

  const ch = await api('/api/challenge');                    // 1. server challenge
  const pr = await api('/api/prove', {key:JSON.parse(key), challenge:ch});  // 2. prove
  const r  = await api('/api/login', {user:u, challenge:ch, proof:pr});     // 3. verify
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
</html>"""


def now() -> int:
    return int(time.time() * 1000)


class Handler(BaseHTTPRequestHandler):
    # -- helpers ------------------------------------------------------------

    def _send(self, code: int, body: bytes, ctype: str, cookie: str | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, cookie: str | None = None):
        self._send(200, json.dumps(obj).encode(), "application/json", cookie)

    def _token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        c = SimpleCookie()
        c.load(raw)
        return c[COOKIE].value if COOKIE in c else None

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def log_message(self, *a):  # quieter console
        pass

    # -- routes -------------------------------------------------------------

    def do_GET(self):
        if urlparse(self.path).path == "/":
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        path = urlparse(self.path).path
        b = self._body()

        if path == "/api/enroll":
            key, _record = auth.enroll(b["user"])
            # the client keeps the key; the server keeps only the record
            return self._json({"key": key.registration_record()})

        if path == "/api/challenge":
            ch = auth.challenge()
            return self._json(ch.to_dict())

        if path == "/api/prove":
            # DEMO ONLY: in production this runs in the browser and the key never
            # crosses the network. Kept server-side here to stay dependency-free.
            key = Key.from_record(b["key"])
            ch = Challenge(nonce=b["challenge"]["nonce"], issued_at=b["challenge"]["issued_at"])
            return self._json(auth.prove(key, ch).to_dict())

        if path == "/api/login":
            ch = Challenge(nonce=b["challenge"]["nonce"], issued_at=b["challenge"]["issued_at"])
            pr = Proof(client_ts=b["proof"]["client_ts"], tag=b["proof"]["tag"],
                       nonce=b["proof"]["nonce"])
            token = auth.login(b["user"], ch, pr)
            if not token:
                return self._json({"ok": False})
            s = auth.session(token)
            cookie = (f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; "
                      f"Max-Age={s.remaining_ms(now()) // 1000}")
            return self._json({"ok": True, "expires_in": s.remaining_ms(now()) // 1000}, cookie)

        if path == "/api/whoami":
            tok = self._token()
            return self._json({"user": auth.whoami(tok) if tok else None})

        if path == "/api/logout":
            tok = self._token()
            if tok:
                auth.logout(tok)
            return self._json({"ok": True}, f"{COOKIE}=; Max-Age=0; Path=/")

        self._send(404, b"not found", "text/plain")


if __name__ == "__main__":
    print(f"OSF passwordless login demo  ->  http://localhost:{PORT}")
    print("  sign up, log in, check the session, log out.  Ctrl-C to stop.\n")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
