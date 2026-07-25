"""Sample for taint analysis (Phase 5).

Same dangerous sinks, but only some actually receive untrusted input.
Taint analysis should mark the param-fed ones as tainted, and leave the
constant-fed ones un-tainted (still flagged, but lower priority).
"""
import os


def eval_tainted(user_input):
    # TAINTED: the parameter flows straight into eval
    return eval(user_input)


def eval_constant():
    # NOT tainted: a hardcoded expression, no untrusted input
    return eval("1 + 1")


def system_propagated(filename):
    # TAINTED via propagation: taint flows param -> cmd -> os.system
    cmd = "ls " + filename
    os.system(cmd)


def system_constant():
    # NOT tainted: fixed command, no untrusted input
    os.system("ls -la")
