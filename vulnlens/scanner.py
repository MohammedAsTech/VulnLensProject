"""
Language dispatch layer.

This is what makes VulnLens multi-language. scan_file() looks at a file's
extension and routes it to the right engine:
    .py                         -> the Python AST engine (engine.py)
    .c/.cpp/.cc/.h/.hpp/...      -> the C++ tree-sitter engine (cpp_engine.py)

Both engines return the SAME Finding objects, so everything downstream (report,
JSON, SARIF, CI) is language-agnostic and shared. Adding a language = adding an
engine here, not rewriting the tool.
"""
import os

from vulnlens import engine, cpp_engine

PY_EXT = {".py"}
CPP_EXT = {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hpp", ".hh", ".hxx"}
SUPPORTED = PY_EXT | CPP_EXT
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}


def language_of(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in PY_EXT:
        return "python"
    if ext in CPP_EXT:
        return "cpp"
    return "unknown"


def scan_file(path: str):
    """Dispatch a single file to the engine for its language."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        source = f.read()
    lang = language_of(path)
    if lang == "cpp":
        return cpp_engine.scan_source(source)
    return engine.scan_source(source)


def collect_files(target: str) -> list[str]:
    """Return all supported source files under a file or folder."""
    if os.path.isfile(target):
        return [target] if language_of(target) != "unknown" else []
    files = []
    for root, dirs, names in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            if language_of(name) != "unknown":
                files.append(os.path.join(root, name))
    return sorted(files)
