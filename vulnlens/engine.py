"""
VulnLens Tier 1 rule engine.

Tier 1 is the deterministic, rule-based scanner. Every finding it produces is
"confirmed": it fired on a specific AST pattern, so it is reported with high
confidence. (The AI heuristic pass in Tier 2 is kept completely separate.)

Design: subclass ast.NodeVisitor. Each rule is a check inside a visit_* method.
- visit_Call   -> function/method calls (eval, os.system, pickle.loads, ...)
- visit_Assign -> assignments (hardcoded secrets)
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
    # RULES ON FUNCTION CALLS
    # ------------------------------------------------------------------
    def visit_Call(self, node):
        # --- Rule 1: dangerous-eval (CWE-95) ---
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "compile"}:
            self._flag("dangerous-eval", node)

        # --- Rule 2: shell-injection via os.system (CWE-78) ---
        if (isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr == "system"):
            self._flag("shell-injection", node)

        # --- Rule 3: subprocess(..., shell=True) (CWE-78) ---
        if (isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._flag("shell-injection", node)

        # --- Rule 4: unsafe-deserialization via pickle.loads (CWE-502) ---
        if (isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "pickle"
                and node.func.attr == "loads"):
            self._flag("unsafe-deserialization", node)

        # --- Rule 5: weak-random (CWE-330) ---
        if (isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "random"):
            self._flag("weak-random", node)

        self.generic_visit(node)   # keep descending into children

    # ------------------------------------------------------------------
    # RULES ON ASSIGNMENTS
    # ------------------------------------------------------------------
    def visit_Assign(self, node):
        # --- Rule 6: hardcoded-secret (CWE-798) ---
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
