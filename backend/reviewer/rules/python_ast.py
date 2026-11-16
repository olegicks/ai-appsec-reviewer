"""Small helpers for AST-based rules."""
import ast
from typing import Dict, Iterator, Optional, Set, Tuple


def dotted_name(node: ast.AST) -> str:
    """`a.b.c` for Name/Attribute chains, '' otherwise."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):
        inner = dotted_name(node.func)
        if inner:
            parts.append(inner + "()")
            return ".".join(reversed(parts))
    return ".".join(reversed(parts)) if parts else ""


def call_name(call: ast.Call) -> str:
    return dotted_name(call.func)


def short_name(call: ast.Call) -> str:
    """Last component of the called name: `pymodbus.client.ModbusTcpClient` -> `ModbusTcpClient`."""
    return call_name(call).split(".")[-1]


def iter_calls(tree: ast.AST) -> Iterator[ast.Call]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def kwarg(call: ast.Call, name: str) -> Optional[ast.expr]:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def has_kwarg(call: ast.Call, *names: str) -> bool:
    return any(kw.arg in names for kw in call.keywords) or any(kw.arg is None for kw in call.keywords)


def const_value(node: Optional[ast.AST]):
    """Literal value of a constant node, or None when it is not a literal."""
    if isinstance(node, ast.Constant):
        return node.value
    return None


def is_const(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant)


def arg(call: ast.Call, index: int, name: str = "") -> Optional[ast.expr]:
    """Positional argument `index` or keyword `name`."""
    if name:
        value = kwarg(call, name)
        if value is not None:
            return value
    if len(call.args) > index and not isinstance(call.args[index], ast.Starred):
        return call.args[index]
    return None


def imported_modules(tree: ast.AST) -> Set[str]:
    """Top-level and full module names imported anywhere in the file."""
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.add(node.module.split(".")[0])
    return names


def import_aliases(tree: ast.AST) -> Dict[str, str]:
    """`from x import ModbusTcpClient as MB` -> {'MB': 'ModbusTcpClient'}."""
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
    return aliases


def method_calls(tree: ast.AST, *names: str) -> Iterator[ast.Call]:
    """Calls whose final attribute/name (after resolving import aliases) is one of `names`."""
    wanted = set(names)
    aliases = import_aliases(tree)
    for call in iter_calls(tree):
        name = short_name(call)
        if aliases.get(name, name) in wanted:
            yield call


def module_constants(tree: ast.AST) -> Dict[str, object]:
    """Module-level `NAME = <literal>` assignments, used to resolve hardcoded hosts and ports."""
    consts: Dict[str, object] = {}
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    consts[target.id] = node.value.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and isinstance(node.value, ast.Constant):
            consts[node.target.id] = node.value.value
    return consts


def resolve(node: Optional[ast.AST], consts: Dict[str, object]):
    """Literal value of `node`, following module-level constants."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    return None


def call_receivers(tree: ast.AST, *names: str) -> Iterator[Tuple[ast.Call, str]]:
    """(call, receiver) for `receiver.method(...)` calls with method in `names`."""
    wanted = set(names)
    for call in iter_calls(tree):
        if isinstance(call.func, ast.Attribute) and call.func.attr in wanted:
            yield call, dotted_name(call.func.value)


def names_in(node: ast.AST) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def enclosing_function(tree: ast.AST, target: ast.AST) -> Optional[ast.AST]:
    """Innermost function definition containing `target` (by line range)."""
    best = None
    line = getattr(target, "lineno", 0)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if node.lineno <= line <= end and (best is None or node.lineno >= best.lineno):
                best = node
    return best
