"""Sample for the unsafe-deserialization rule (CWE-502)."""
import pickle
import json


def load_session(raw_bytes):
    # BAD: unpickling untrusted data can execute arbitrary code
    return pickle.loads(raw_bytes)


def load_session_safe(raw_text):
    # SAFE: JSON only produces plain data structures
    return json.loads(raw_text)
