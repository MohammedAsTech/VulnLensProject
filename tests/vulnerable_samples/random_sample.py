"""Sample for the weak-random rule (CWE-330)."""
import random
import secrets


def make_reset_token():
    # BAD: random is predictable, unsafe for security tokens
    return str(random.randint(100000, 999999))


def make_reset_token_safe():
    # SAFE: secrets uses cryptographically strong randomness
    return secrets.token_hex(16)
