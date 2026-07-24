"""Sample for the weak-hash rule (CWE-327)."""
import hashlib


def hash_password_bad(password):
    # BAD: MD5 is broken and unsafe for passwords
    return hashlib.md5(password.encode()).hexdigest()


def hash_data_safe(data):
    # SAFE: SHA-256 is a strong hash
    return hashlib.sha256(data.encode()).hexdigest()
