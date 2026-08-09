# OSF (Orbital State Function)
# Copyright (c) 2026 Winner Brothers Group. All rights reserved.
# Inventor / applicant: LEE JUNGHOON (이정훈).  Patent: PCT WO 2025/127469 A1.
# Licensed under PolyForm Noncommercial 1.0.0 — commercial or production use
# requires a separate license including a patent grant. See LICENSE-COMMERCIAL.md.
# https://github.com/winnerbrothers/osf

"""Shared test bootstrap: make the in-repo `osf` package importable and locate KAT."""
import os
import sys

_TESTS = os.path.dirname(os.path.abspath(__file__))
_PY = os.path.dirname(_TESTS)                    # .../osf-native/python
_ROOT = os.path.dirname(_PY)                     # .../osf-native
SRC = os.path.join(_PY, "src")
KAT_PATH = os.path.join(_ROOT, "kat", "test-vectors.json")

if SRC not in sys.path:
    sys.path.insert(0, SRC)
