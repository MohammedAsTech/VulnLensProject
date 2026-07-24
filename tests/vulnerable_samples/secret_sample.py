"""Sample for the hardcoded-secret rule (CWE-798)."""
import os


# BAD: real credentials committed into source
password = "SuperSecret123"
api_key = "sk-live-abc123def456"

# SAFE: loaded from the environment at runtime
db_password = os.environ.get("DB_PASSWORD")
timeout = 30  # SAFE: not a secret, just a number
