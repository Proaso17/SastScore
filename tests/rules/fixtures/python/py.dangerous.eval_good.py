import ast


def run(expr: str) -> object:
    return ast.literal_eval(expr)
