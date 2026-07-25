"""Sample for aliased / from-imports (Phase 4).

All three calls below ARE dangerous, but written in forms the literal-name
rules miss. After Phase 4 they should all be flagged.
"""
import os as o
from os import system
from pickle import loads


def run_aliased_module(cmd):
    # BAD: os.system via an aliased module import (o == os)
    o.system(cmd)


def run_from_import(cmd):
    # BAD: os.system imported directly as a bare name
    system(cmd)


def load_from_import(data):
    # BAD: pickle.loads imported directly as a bare name
    return loads(data)
