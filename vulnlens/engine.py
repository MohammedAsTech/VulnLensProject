"""
VulnLens Tier 1 rule engine.

Tier 1 is the deterministic, rule-based scanner. Every finding it produces is
"confirmed": it fired on a specific AST pattern, so it is reported with high
confidence. (The AI heuristic pass in Tier 2 is kept completely separate.)

Design: subclass ast.NodeVisitor. Each rule is a check inside a visit_* method.
- visit_Import / visit_ImportFrom -> track how names were imported (aliases)
- visit_FunctionDef               -> set up per-function taint tracking
- visit_Call                      -> function/method calls (eval, os.system, ...)
- visit_Assign                    -> assignments (hardcoded secrets + taint flow)

Import resolution: _resolve_call(node) returns a canonical (module, func) pair,
so a call is matched no matter how it was imported (os.system / o.system / system).

Taint analysis (intraprocedural): within each function, values that come from an
untrusted SOURCE (a parameter or input()) are "tainted". Taint propagates through
assignments. When a tainted value reaches a dangerous call (a SINK), the finding
is marked tainted=True -- meaning untrusted input actually reaches the danger, the
highest-priority kind of finding.

A match is recorded via self._flag(rule_id, node, tainted), which pulls that rule's
metadata (cwe, severity, message, fix) from rules.json. Detection LOGIC lives here;
rule METADATA lives in data.
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
    analogy: str = ""   # filled in by the AI layer (optional)
    tainted: bool = False  # True if untrusted input flows into this sink


# Variable names that should never hold a hardcoded string secret.
SECRET_NAMES = {"password", "passwd", "secret", "api_key", "apikey", "token"}

# Bare-call sources of untrusted input (beyond function parameters).
TAINT_SOURCES = {"input"}


class RuleEngine(ast.NodeVisitor):
    def __init__(self):
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}              # import os as o -> {"o": "os"}
        self.imported: dict[str, tuple[str, str]] = {}  # from os import system -> {"system": ("os","system")}
        self.tainted: set[str] = set()                  # tainted var names in the CURRENT function

    def _flag(self, rule_id: str, node, tainted: bool = False):
        """Record a finding, pulling metadata for rule_id from rules.json."""
        meta = RULES[rule_id]
        self.findings.append(Finding(
            rule=rule_id, cwe=meta["cwe"], severity=meta["severity"],
            line=node.lineno, message=meta["message"], fix=meta["fix"],
            tainted=tainted,
        ))

    # ------------------------------------------------------------------
    # IMPORT TRACKING
    # ------------------------------------------------------------------
    def visit_Import(self, node):
        for a in node.names:
            self.aliases[a.asname or a.name] = a.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ""
        for a in node.names:
            self.imported[a.asname or a.name] = (module, a.name)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # TAINT: per-function scope. Parameters start tainted (untrusted input).
    # ------------------------------------------------------------------
    def visit_FunctionDef(self, node):
        saved = self.tainted                 # support nested functions
        self.tainted = set()
        args = node.args
        for a in args.posonlyargs + args.args + args.kwonlyargs:
            self.tainted.add(a.arg)
        if args.vararg:
            self.tainted.add(args.vararg.arg)
        if args.kwarg:
            self.tainted.add(args.kwarg.arg)
        self.generic_visit(node)             # walk the body (in order) with this taint set
        self.tainted = saved

    visit_AsyncFunctionDef = visit_FunctionDef

    def _is_tainted(self, expr) -> bool:
        """True if an expression references a tainted name or a source call."""
        for n in ast.walk(expr):
            if isinstance(n, ast.Name) and n.id in self.tainted:
                return True
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id in TAINT_SOURCES):
                return True
        return False

    def _call_is_tainted(self, node) -> bool:
        """True if any argument to this call carries tainted data."""
        return (any(self._is_tainted(a) for a in node.args)
                or any(self._is_tainted(kw.value) for kw in node.keywords))

    # ------------------------------------------------------------------
    # CALL RESOLUTION
    # ------------------------------------------------------------------
    def _resolve_call(self, node):
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
            if name in self.imported:
                return self.imported[name]
            return (None, name)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            base = func.value.id
            return (self.aliases.get(base, base), func.attr)
        return (None, None)

    @staticmethod
    def _kwarg_const(node, name):
        for kw in node.keywords:
            if kw.arg == name and isinstance(kw.value, ast.Constant):
                return kw.value.value
        return None

    # ------------------------------------------------------------------
    # RULES ON FUNCTION CALLS
    # ------------------------------------------------------------------
    def visit_Call(self, node):
        module, func = self._resolve_call(node)
        tainted = self._call_is_tainted(node)

        if func in {"eval", "exec", "compile"} and module in (None, "builtins"):
            self._flag("dangerous-eval", node, tainted)

        if module == "os" and func == "system":
            self._flag("shell-injection", node, tainted)

        if module == "subprocess" and self._kwarg_const(node, "shell") is True:
            self._flag("shell-injection", node, tainted)

        if module == "pickle" and func == "loads":
            self._flag("unsafe-deserialization", node, tainted)

        if module == "random":
            self._flag("weak-random", node, tainted)

        if module == "hashlib" and func in {"md5", "sha1"}:
            self._flag("weak-hash", node, tainted)

        if module == "yaml" and func == "load":
            self._flag("unsafe-yaml-load", node, tainted)

        if module == "requests" and self._kwarg_const(node, "verify") is False:
            self._flag("insecure-request", node, tainted)

        self.generic_visit(node)

    # ------------------------------------------------------------------
    # RULES ON ASSIGNMENTS  (+ taint propagation)
    # ------------------------------------------------------------------
    def visit_Assign(self, node):
        # Rule: hardcoded-secret (CWE-798)
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.lower() in SECRET_NAMES:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self._flag("hardcoded-secret", node)

        # Taint propagation: if the right-hand side is tainted, the assigned
        # names become tainted too (e.g. cmd = "ls " + user_input).
        if self._is_tainted(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)

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
