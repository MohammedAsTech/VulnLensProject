"""
VulnLens C++ engine (Tier 1 for C/C++).

Mirrors the Python engine's job for C++: parse the source into a syntax tree and
flag dangerous call patterns. Python's `ast` only parses Python, so C++ uses
tree-sitter (a fast multi-language parser) with its C++ grammar. The philosophy
is identical to the Python side -- match code STRUCTURE (real call nodes), not text
-- and it produces the SAME Finding objects, so the report, JSON, SARIF, and CI
layers are reused unchanged.

Graceful degradation: if tree-sitter isn't installed, cpp_available() is False and
scan_source() returns [] -- Python scanning keeps working with or without C++.
"""
from vulnlens.engine import Finding
from vulnlens.rules import RULES

try:
    import tree_sitter_cpp as tscpp
    from tree_sitter import Language, Parser
    _CPP_LANGUAGE = Language(tscpp.language())
except Exception:
    _CPP_LANGUAGE = None

# Dangerous C/C++ functions grouped by rule.
BUFFER_OVERFLOW = {"gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf"}
COMMAND_INJECTION = {"system", "popen"}
WEAK_RANDOM = {"rand", "random"}
PRINTF_FAMILY = {"printf"}   # first arg is the format string


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


def _finding(rule_id: str, node) -> Finding:
    meta = RULES[rule_id]
    return Finding(
        rule=rule_id, cwe=meta["cwe"], severity=meta["severity"],
        line=node.start_point[0] + 1,       # tree-sitter rows are 0-based
        message=meta["message"], fix=meta["fix"],
    )


def scan_source(source: str) -> list[Finding]:
    """Parse C/C++ source and return Tier 1 findings. [] if tree-sitter absent."""
    if _CPP_LANGUAGE is None:
        return []

    data = bytes(source, "utf8")
    tree = _make_parser().parse(data)
    findings: list[Finding] = []

    def text(n) -> str:
        return data[n.start_byte:n.end_byte].decode("utf8", "replace")

    def walk(node):
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "identifier":
                name = text(fn)
                if name in BUFFER_OVERFLOW:
                    findings.append(_finding("cpp-buffer-overflow", node))
                if name in COMMAND_INJECTION:
                    findings.append(_finding("cpp-command-injection", node))
                if name in WEAK_RANDOM:
                    findings.append(_finding("cpp-weak-random", node))
                if name in PRINTF_FAMILY:
                    args = node.child_by_field_name("arguments")
                    first = args.named_children[0] if (args and args.named_children) else None
                    # printf(var) is a format-string bug; printf("...") is fine.
                    if first is not None and first.type != "string_literal":
                        findings.append(_finding("cpp-format-string", node))
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return findings
