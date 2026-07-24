"""
Loads rule metadata from rules.json.

Detection *logic* lives in engine.py (real AST matching). This file only holds
the descriptive metadata for each rule id: cwe, severity, message, fix. Keeping
metadata as data means adding or editing a rule's description is a data change,
not a code change. Uses the standard-library json module, so the Tier 1 core
still has zero third-party dependencies.
"""
import json
import os

_RULES_PATH = os.path.join(os.path.dirname(__file__), "rules.json")


def load_rules() -> dict:
    with open(_RULES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# Loaded once at import time.
RULES = load_rules()
