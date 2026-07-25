"""
VulnLens Tier 1 rule engine.

Tier 1 is the deterministic, rule-based scanner. Every finding it produces is
"confirmed": it fired on a specific AST pattern, so it is reported with high
confidence. (The AI heuristic pass in Tier 2 is kept completely separate.)

Design: subclass ast.NodeVisitor. Each rule is a check inside a visit_* method.
- visit_Import / visit_ImportFrom -> track how names were imported (aliases)
- visit_Call   -> function/method calls (eval, os.system, pickle.loads, ...)
- visit_Assign -> assignments (hardcoded secrets)

Import resolution: _resolve_call(node) returns a canonical (module, func) pair,
so a call is matched no matter how it was imported:
    import os;          os.system(x)      -> ("os", "system")
    import os as o;     o.system(x)       -> ("os", "system")
    from os import system; system(x)      -> ("os", "system")
This closes the aliased / from-import blind spot.

A match is recorded via self._flag(rule_id, node), which pulls that rule's
metadata (cwe, severity, message, fix) from rules.json. Detection LOGIC lives
here; rule METADATA lives in data.
"""
import ast
from dataclasses import dataclass

from vulnlens.rules import RULES


@dataclass
class Finding:
    rule: str
    cwe: str
    severity: str      # "HIGH" | "MEDIUM" | "LOW"
    line: int
    message: str
    fix: str
    analogy: str = ""  # plain-English explanation, filled in by the AI layer (optional)


# Variable names that should never hold a hardcoded string secret.
SECRET_NAMES = {"password", "passwd", "secret", "api_key", "apikey", "token"}


class RuleEngine(ast.NodeVisitor):
    def __init__(self):
        self.findings: list[Finding] = []
        # `import os as o`  -> aliases["o"] = "os"      (module alias -> real module)
        self.aliases: dict[str, str] = {}
        # `from os import system as run` -> imported["run"] = ("os", "system")
        self.imported: dict[str, tuple[str, str]] = {}

    def _flag(self, rule_id: str, node):
        """Record a finding, pulling metadata for rule_id from rules.json."""
        meta = RULES[rule_id]
        self.findings.append(Finding(
            rule=rule_id,
            cwe=meta["cwe"],
            severity=meta["severity"],
            line=node.lineno,
            message=meta["message"],
            fix=meta["fix"],
        ))

    # ------------------------------------------------------------------
    # IMPORT TRACKING  (runs before the calls that use these names)
    # ------------------------------------------------------------------
    def visit_Import(self, node):
        # import os            -> aliases["os"] = "os"
        # import os as o       -> aliases["o"]  = "os"
        for a in node.names:
            self.aliases[a.asname or a.name] = a.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        # from os import system            -> imported["system"] = ("os", "system")
        # from os import system as run     -> imported["run"]    = ("os", "system")
        module = node.module or ""
        for a in node.names:
            self.imported[a.asname or a.name] = (module, a.name)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # CALL RESOLUTION
    # ------------------------------------------------------------------
    def _resolve_call(self, node):
        """Return a canonical (module, func) for a call node, resolving imports.

        - bare call foo(...)   -> (module, orig) if foo came from `from module import orig`,
                                  else (None, "foo")   e.g. builtins like eval
        - dotted call X.m(...) -> (resolved_module, "m"), resolving `import X as Y`
        - anything else        -> (None, None)
        """
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
            if name in self.imported:
                return self.imported[name]        # (module, original_name)
            return (None, name)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            base = func.value.id
            module = self.aliases.get(base, base)  # resolve alias; default to the name itself
            return (module, func.attr)
        return (None, None)

    @staticmethod
    def _has_kwarg_true(node, name) -> bool:
        """True if the call has keyword `name` set to the literal True/False sentinel."""
        for kw in node.keywords:
            if kw.arg == name and isinstance(kw.value, ast.Constant):
                return kw.value.value
        return None

    # ------------------------------------------------------------------
    # RULES ON FUNCTION CALLS
    # ------------------------------------------------------------------
    def visit_Call(self, node):
        module, func = self._resolve_call(node)

        # --- Rule 1: dangerous-eval (CWE-95) --- builtin, no real module
        if func in {"eval", "exec", "compile"} and module in (None, "builtins"):
            self._flag("dangerous-eval", node)

        # --- Rule 2: shell-injection via os.system (CWE-78) ---
        if module == "os" and func == "system":
            self._flag("shell-injection", node)

        # --- Rule 3: subprocess(..., shell=True) (CWE-78) ---
        if module == "subprocess" and self._has_kwarg_true(node, "shell") is True:
            self._flag("shell-injection", node)

        # --- Rule 4: unsafe-deserialization via pickle.loads (CWE-502) ---
        if module == "pickle" and func == "loads":
            self._flag("unsafe-deserialization", node)

        # --- Rule 5: weak-random (CWE-330) ---
        if module == "random":
            self._flag("weak-random", node)

        # --- Rule 6: weak-hash (CWE-327) ---
        if module == "hashlib" and func in {"md5", "sha1"}:
            self._flag("weak-hash", node)

        # --- Rule 7: unsafe-yaml-load (CWE-502) ---
        if module == "yaml" and func == "load":
            self._flag("unsafe-yaml-load", node)

        # --- Rule 8: insecure-request via requests(..., verify=False) (CWE-295) ---
        if module == "requests" and self._has_kwarg_true(node, "verify") is False:
            self._flag("insecure-request", node)

        self.generic_visit(node)   # keep descending into children

    # ------------------------------------------------------------------
    # RULES ON ASSIGNMENTS
    # ------------------------------------------------------------------
    def visit_Assign(self, node):
        # --- Rule 9: hardcoded-secret (CWE-798) ---
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.lower() in SECRET_NAMES:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self._flag("hardcoded-secret", node)

        self.generic_visit(node)


# ----------------------------------------------------------------------
# Entry points
# ----------------------------------------------------------------------
def scan_source(source: str) -> list[Finding]:
    """Parse Python source text and return Tier 1 findings."""
    tree = ast.parse(source)
    engine = RuleEngine()
    engine.visit(tree)
    return engine.findings


def scan_file(path: str) -> list[Finding]:
    with open(path, "r", encoding="utf-8") as f:
        return scan_source(f.read())
