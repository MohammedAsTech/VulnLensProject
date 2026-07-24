"""
VulnLens Tier 1 rule engine.

Tier 1 is the deterministic, rule-based scanner. Every finding it produces is
"confirmed": it fired on a specific AST pattern, so it is reported with high
confidence. (The AI heuristic pass in Tier 2 is kept completely separate.)

Design: subclass ast.NodeVisitor. Each rule is a check inside a visit_* method.
- visit_Call   -> function/method calls (eval, os.system, pickle.loads, ...)
- visit_Assign -> assignments (hardcoded secrets)
Each match is recorded as a Finding via self._record(...).
"""
import ast
from dataclasses import dataclass


@dataclass
class Finding:
    rule: str
    cwe: str
    severity: str      # "HIGH" | "MEDIUM" | "LOW"
    line: int
    message: str
    fix: str


# Variable names that should never hold a hardcoded string secret.
SECRET_NAMES = {"password", "passwd", "secret", "api_key", "apikey", "token"}


class RuleEngine(ast.NodeVisitor):
    def __init__(self):
        self.findings: list[Finding] = []

    def _record(self, rule, cwe, severity, node, message, fix):
        """Helper: append a Finding using the node's line number."""
        self.findings.append(Finding(
            rule=rule, cwe=cwe, severity=severity,
            line=node.lineno, message=message, fix=fix,
        ))

    # ------------------------------------------------------------------
    # RULES ON FUNCTION CALLS
    # ------------------------------------------------------------------
    def visit_Call(self, node):
        # --- Rule 1: dangerous-eval (CWE-95) --- [DONE: reference implementation]
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "compile"}:
            self._record(
                "dangerous-eval", "CWE-95", "HIGH", node,
                f"Call to {node.func.id}() executes arbitrary code.",
                "Avoid eval/exec on untrusted input; use ast.literal_eval or explicit parsing.",
            )

        # --- Rule 2: shell-injection via os.system (CWE-78) --- [DONE: reference]
        if (isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr == "system"):
            self._record(
                "shell-injection", "CWE-78", "HIGH", node,
                "os.system runs a shell command; user input can inject commands.",
                "Use subprocess.run with an argument list; avoid os.system.",
            )

        # --- Rule 3: subprocess(..., shell=True) (CWE-78) --- TODO (YOU WRITE THIS)
        # Detect a call to subprocess.<anything> that has a keyword shell=True.
        # Hints:
        #   - node.func is an ast.Attribute with value.id == "subprocess"
        #   - loop over node.keywords; each kw has kw.arg (the name) and kw.value
        #   - you want kw.arg == "shell" and kw.value is an ast.Constant whose .value is True
        #   - record: rule="shell-injection", cwe="CWE-78", severity="HIGH"
        if (isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._record(
                        "shell-injection", "CWE-78", "HIGH", node,
                        "subprocess called with shell=True; user input can inject commands.",
                        "Remove shell=True and pass the command as a list of arguments.",
                    )

        # --- Rule 4: unsafe-deserialization via pickle.loads (CWE-502) --- TODO (YOU WRITE)
        # Same shape as os.system, but module "pickle" and method "loads".
        #   - record: rule="unsafe-deserialization", cwe="CWE-502", severity="HIGH"
        if (isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "pickle"
                and node.func.attr == "loads"):
            self._record(
                "unsafe-deserialization", "CWE-502", "HIGH", node,
                "pickle.loads on untrusted data can execute arbitrary code.",
                "Don't unpickle untrusted data; use JSON or another safe format.",
            )

        # --- Rule 5: weak-random (CWE-330) --- TODO (YOU WRITE)
        # Detect use of the random module for tokens, e.g. random.randint / random.random.
        #   - node.func is an ast.Attribute with value.id == "random"
        #   - record: rule="weak-random", cwe="CWE-330", severity="MEDIUM"
        if (isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "random"):
            self._record(
                "weak-random", "CWE-330", "MEDIUM", node,
                "random module is not cryptographically secure; its output is predictable.",
                "Use the secrets module (e.g. secrets.token_hex) for tokens, passwords, or keys.",
            )

        self.generic_visit(node)   # keep descending into children

    # ------------------------------------------------------------------
    # RULES ON ASSIGNMENTS
    # ------------------------------------------------------------------
    def visit_Assign(self, node):
        # --- Rule 6: hardcoded-secret (CWE-798) --- TODO (YOU WRITE THIS)
        # Detect: a secret-named variable assigned a string literal.
        # Hints:
        #   - loop over node.targets; a target may be an ast.Name with .id
        #   - check target.id.lower() in SECRET_NAMES
        #   - check node.value is an ast.Constant whose .value is a str
        #   - record: rule="hardcoded-secret", cwe="CWE-798", severity="MEDIUM"
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.lower() in SECRET_NAMES:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self._record(
                        "hardcoded-secret", "CWE-798", "MEDIUM", node,
                        "Hardcoded credential assigned directly in source code.",
                        "Load secrets from environment variables or a secrets manager; never commit them.",
                    )

        self.generic_visit(node)


# ----------------------------------------------------------------------
# Entry points (scaffolding — fine as-is)
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
