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
