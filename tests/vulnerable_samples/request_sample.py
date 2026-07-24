"""Sample for the insecure-request rule (CWE-295)."""
import requests


def fetch_bad(url):
    # BAD: verify=False disables TLS certificate checking
    return requests.get(url, verify=False)


def fetch_safe(url):
    # SAFE: certificate verification stays on by default
    return requests.get(url)
