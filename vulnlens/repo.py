"""
GitHub repo support: turn a github.com URL into a local shallow clone to scan.

Only https://github.com/<owner>/<repo>[.git] URLs are accepted, and the URL is passed
to git after `--`, so a hostile string can't be read as a git option. The clone is
read-only analysis input: nothing in it is ever executed.
"""
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager

_GITHUB_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+?(?:\.git)?/?$")


def is_github_url(target: str) -> bool:
    return bool(_GITHUB_RE.match(target))


def repo_name(url: str) -> str:
    """'https://github.com/owner/repo.git' -> 'owner/repo'."""
    return url.rstrip("/").removesuffix(".git").split("github.com/")[-1]


def _force_remove(func, path, _exc):
    # Git pack files are read-only on Windows; clear the flag and retry.
    os.chmod(path, 0o700)
    func(path)


@contextmanager
def cloned(url: str):
    """Shallow-clone `url` into a temp dir, yield its path, and always clean up."""
    tmp = tempfile.mkdtemp(prefix="vulnlens-")
    try:
        try:
            subprocess.run(["git", "clone", "--depth", "1", "--quiet", "--", url, tmp],
                           check=True, capture_output=True, text=True, timeout=300)
        except FileNotFoundError:
            raise RuntimeError("git is not installed or not on PATH")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"could not clone {url}: {e.stderr.strip() or 'git failed'}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"cloning {url} timed out")
        yield tmp
    finally:
        shutil.rmtree(tmp, onerror=_force_remove)
