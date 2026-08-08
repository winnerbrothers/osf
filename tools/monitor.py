#!/usr/bin/env python3
"""
OSF usage monitor — collects *leads* on who is using `planet-osf`.

Detection of license compliance is fundamentally limited for any public
package (see SECURITY / licensing notes). This tool does NOT prove commercial
use; it surfaces public signals you can follow up on:

  1. GitHub code search  — public repos referencing `planet-osf` / `import osf`
  2. PyPI download stats  — aggregate volume (no identity)
  3. GitHub dependents    — link (the graph is a web feature, not fully in the API)

GitHub queries use the `gh` CLI so they inherit your login. Set OSF_GH_BIN if
`gh` is not on PATH.

Usage:
    python tools/monitor.py                 # print markdown report
    python tools/monitor.py -o report.md    # also write to a file
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

PACKAGE = "planet-osf"
IMPORT_NAME = "import osf"
REPO = "winnerbrothers/osf"


def gh_bin() -> str | None:
    return os.environ.get("OSF_GH_BIN") or shutil.which("gh")


def gh_search(kind: str, query: str) -> dict:
    """kind = 'code' | 'repositories'. Returns parsed JSON or {'error':...}."""
    gh = gh_bin()
    if not gh:
        return {"error": "gh CLI not found (set OSF_GH_BIN or install gh)"}
    env = dict(os.environ, MSYS2_ARG_CONV_EXCL="*")
    try:
        out = subprocess.run(
            [gh, "api", "-X", "GET", f"search/{kind}", "-f", f"q={query}",
             "--jq", "{total: .total_count, items: [.items[] | (.repository.full_name // .full_name)]}"],
            capture_output=True, text=True, env=env, timeout=60,
        )
        if out.returncode != 0:
            return {"error": out.stderr.strip()[:200] or f"exit {out.returncode}"}
        return json.loads(out.stdout or "{}")
    except Exception as e:  # pragma: no cover
        return {"error": str(e)[:200]}


def pypi_stats() -> dict:
    url = f"https://pypistats.org/api/packages/{PACKAGE}/recent"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)[:200]}


def section(title: str, body: str) -> str:
    return f"## {title}\n\n{body}\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", help="also write the report to this file")
    args = ap.parse_args()

    try:  # ensure UTF-8 output on any console (Windows cp949 etc.)
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts = [f"# OSF usage report — {PACKAGE}\n\n_Generated {now}. Leads, not proof of "
             f"commercial use. Follow up manually + assert patent/license where warranted._\n"]

    # 1. GitHub code search
    code = gh_search("code", f'"{PACKAGE}"')
    imp = gh_search("code", f'"{IMPORT_NAME}" language:python')
    if "error" in code:
        parts.append(section("GitHub code — repos referencing planet-osf", f"_error: {code['error']}_"))
    else:
        items = code.get("items", [])
        uniq = sorted(set(items))
        body = f"**{code.get('total', 0)}** code hits, **{len(uniq)}** distinct public repos:\n\n"
        body += "\n".join(f"- {r}" for r in uniq[:40]) or "_none yet_"
        if "error" not in imp:
            body += f"\n\n`import osf` (python) hits: **{imp.get('total', 0)}**"
        parts.append(section("GitHub code — repos referencing planet-osf", body))

    # 2. PyPI stats
    ps = pypi_stats()
    if "error" in ps or "data" not in ps:
        parts.append(section("PyPI downloads", f"_no data yet (package is new) or error: "
                                               f"{ps.get('error', 'n/a')}_"))
    else:
        d = ps["data"]
        parts.append(section("PyPI downloads (aggregate, no identity)",
                             f"- last day: **{d.get('last_day', 0):,}**\n"
                             f"- last week: **{d.get('last_week', 0):,}**\n"
                             f"- last month: **{d.get('last_month', 0):,}**"))

    # 3. Dependents (web feature)
    parts.append(section("GitHub dependents (manual)",
                         f"Public repos that declare a dependency:\n"
                         f"https://github.com/{REPO}/network/dependents\n\n"
                         f"_Not exposed via API; check periodically. Private/internal corporate "
                         f"use is invisible here — the patent is your enforcement hook there._"))

    report = "\n".join(parts)
    sys.stdout.write(report + "\n")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report + "\n")
        sys.stderr.write(f"\nwrote {args.out}\n")


if __name__ == "__main__":
    main()
