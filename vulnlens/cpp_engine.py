"""
VulnLens C++ engine (Tier 1 for C/C++).

Mirrors the Python engine's job for C++: parse the source into a syntax tree and
flag dangerous call patterns. Python's `ast` only parses Python, so C++ uses
tree-sitter (a fast multi-language parser) with its C++ grammar. The philosophy
is identical to the Python side -- match code STRUCTURE (real call nodes), not text
-- and it produces the SAME Finding objects, so the report, JSON, SARIF, and CI
layers are reused unchanged.

Like engine.py, this does two things beyond bare pattern matching:
- Name resolution: `std::system(x)` is matched as `system`, the same way the
  Python engine resolves `os.system` through an alias or a from-import.
  (_call_name)
- Intraprocedural taint analysis: within each function, parameters and known
  input sources (gets/scanf/fgets/getenv/...) are "tainted". Taint propagates
  through plain assignments and initializers. A finding is marked tainted=True
  when untrusted data actually reaches the dangerous call. (CppRuleEngine.tainted)

Graceful degradation: if tree-sitter isn't installed, cpp_available() is False and
scan_source() returns [] -- Python scanning keeps working with or without C++.
"""
from vulnlens.engine import Finding, SECRET_NAMES
from vulnlens.rules import RULES

try:
    import tree_sitter_cpp as tscpp
    from tree_sitter import Language, Parser
    _CPP_LANGUAGE = Language(tscpp.language())
except Exception:
    _CPP_LANGUAGE = None

# Dangerous C/C++ functions grouped by rule. Matched by bare name (after
# resolving any std:: qualification), same spirit as the Python engine's
# module/func matching.
BUFFER_OVERFLOW = {"gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf"}
COMMAND_INJECTION = {"system", "popen"}
WEAK_RANDOM = {"rand", "random"}
PRINTF_FAMILY = {"printf"}   # first arg is the format string
WEAK_HASH = {"MD5", "SHA1", "MD5_Init", "SHA1_Init", "CC_MD5", "CC_SHA1"}

# Calls that introduce untrusted data into a function (beyond parameters).
TAINT_SOURCE_CALLS = {"gets", "scanf", "fgets", "getenv", "recv", "read"}


def cpp_available() -> bool:
    return _CPP_LANGUAGE is not None


def _make_parser():
    """Build a tree-sitter parser, tolerant of API differences across versions."""
    try:
        return Parser(_CPP_LANGUAGE)          # tree-sitter >= 0.22
    except TypeError:
        p = Parser()
        try:
            p.set_language(_CPP_LANGUAGE)      # older API
        except AttributeError:
            p.language = _CPP_LANGUAGE
        return p


class CppRuleEngine:
    def __init__(self, data: bytes):
        self.data = data
        self.findings: list[Finding] = []
        self.tainted: set[str] = set()   # tainted var names in the CURRENT function

    def text(self, node) -> str:
        return self.data[node.start_byte:node.end_byte].decode("utf8", "replace")

    def _flag(self, rule_id: str, node, tainted: bool = False):
        meta = RULES[rule_id]
        self.findings.append(Finding(
            rule=rule_id, cwe=meta["cwe"], severity=meta["severity"],
            line=node.start_point[0] + 1,       # tree-sitter rows are 0-based
            message=meta["message"], fix=meta["fix"],
            tainted=tainted,
        ))

    # ------------------------------------------------------------------
    # NAME RESOLUTION: strip std:: (or any other) qualification.
    # ------------------------------------------------------------------
    def _call_name(self, node):
        fn = node.child_by_field_name("function")
        if fn is None:
            return None
        if fn.type == "identifier":
            return self.text(fn)
        if fn.type == "qualified_identifier":
            name = fn.child_by_field_name("name")
            return self.text(name) if name is not None else None
        return None

    # ------------------------------------------------------------------
    # TAINT: per-function scope. Parameters and source calls start tainted.
    # ------------------------------------------------------------------
    @staticmethod
    def _innermost_identifier(declarator):
        """Unwrap pointer_declarator / array_declarator / ... down to the identifier."""
        node = declarator
        while node is not None and node.type != "identifier":
            node = node.child_by_field_name("declarator")
        return node

    @staticmethod
    def _find_function_declarator(declarator):
        """Unwrap e.g. `char* g(...)`'s pointer_declarator to the function_declarator."""
        node = declarator
        while node is not None and node.type != "function_declarator":
            node = node.child_by_field_name("declarator")
        return node

    def _param_names(self, func_declarator) -> list[str]:
        names = []
        if func_declarator is None:
            return names
        params = func_declarator.child_by_field_name("parameters")
        if params is None:
            return names
        for p in params.named_children:
            if p.type != "parameter_declaration":
                continue
            ident = self._innermost_identifier(p.child_by_field_name("declarator"))
            if ident is not None:
                names.append(self.text(ident))
        return names

    def _is_tainted_expr(self, node) -> bool:
        if node is None:
            return False
        if node.type == "identifier" and self.text(node) in self.tainted:
            return True
        if node.type == "call_expression" and self._call_name(node) in TAINT_SOURCE_CALLS:
            return True
        return any(self._is_tainted_expr(c) for c in node.children)

    def _call_is_tainted(self, node) -> bool:
        args = node.child_by_field_name("arguments")
        if args is None:
            return False
        return any(self._is_tainted_expr(a) for a in args.named_children)

    # ------------------------------------------------------------------
    # WALK: dispatches by tree-sitter node type, mirroring ast.NodeVisitor.
    # ------------------------------------------------------------------
    def walk(self, node):
        if node.type == "function_definition":
            self._visit_function(node)
            return
        if node.type == "call_expression":
            self._visit_call(node)
        elif node.type == "assignment_expression":
            self._visit_assignment(node)
        elif node.type == "init_declarator":
            self._visit_init_declarator(node)
        for child in node.children:
            self.walk(child)

    def _visit_function(self, node):
        func_declarator = self._find_function_declarator(node.child_by_field_name("declarator"))
        saved = self.tainted                  # support nested/local functions
        self.tainted = set(self._param_names(func_declarator))
        body = node.child_by_field_name("body")
        if body is not None:
            self.walk(body)
        self.tainted = saved

    def _visit_assignment(self, node):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or left.type != "identifier":
            return
        name = self.text(left)
        if self._is_tainted_expr(right):
            self.tainted.add(name)
        if right is not None and right.type == "string_literal" and name.lower() in SECRET_NAMES:
            self._flag("cpp-hardcoded-secret", node)

    def _visit_init_declarator(self, node):
        ident = self._innermost_identifier(node.child_by_field_name("declarator"))
        value = node.child_by_field_name("value")
        if ident is None:
            return
        name = self.text(ident)
        if self._is_tainted_expr(value):
            self.tainted.add(name)
        if value is not None and value.type == "string_literal" and name.lower() in SECRET_NAMES:
            self._flag("cpp-hardcoded-secret", node)

    def _visit_call(self, node):
        name = self._call_name(node)
        tainted = self._call_is_tainted(node)

        if name in BUFFER_OVERFLOW:
            self._flag("cpp-buffer-overflow", node, tainted)
        if name in COMMAND_INJECTION:
            self._flag("cpp-command-injection", node, tainted)
        if name in WEAK_RANDOM:
            self._flag("cpp-weak-random", node, tainted)
        if name in WEAK_HASH:
            self._flag("cpp-weak-hash", node, tainted)
        if name in PRINTF_FAMILY:
            args = node.child_by_field_name("arguments")
            first = args.named_children[0] if (args and args.named_children) else None
            # printf(var) is a format-string bug; printf("...") is fine.
            if first is not None and first.type != "string_literal":
                self._flag("cpp-format-string", node, tainted)


def scan_source(source: str) -> list[Finding]:
    """Parse C/C++ source and return Tier 1 findings. [] if tree-sitter absent."""
    if _CPP_LANGUAGE is None:
        return []

    data = bytes(source, "utf8")
    tree = _make_parser().parse(data)
    eng = CppRuleEngine(data)
    eng.walk(tree.root_node)
    return eng.findings
