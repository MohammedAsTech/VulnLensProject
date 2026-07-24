"""Sample for the unsafe-yaml-load rule (CWE-502)."""
import yaml


def load_config_bad(text):
    # BAD: yaml.load without a safe loader can execute arbitrary code
    return yaml.load(text)


def load_config_safe(text):
    # SAFE: safe_load only produces plain data
    return yaml.safe_load(text)
