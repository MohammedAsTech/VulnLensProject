"""Sample for the dangerous-eval rule (CWE-95)."""


def calculate(user_input):
    # BAD: executes arbitrary code from the user
    result = eval(user_input)
    return result


def safe_calculate(user_input):
    # SAFE: literal_eval only parses data, never executes code
    import ast
    result = ast.literal_eval(user_input)
    return result
