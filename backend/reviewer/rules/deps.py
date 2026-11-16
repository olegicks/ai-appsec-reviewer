"""Direct-dependency parsing for requirements*.txt, pyproject.toml and package.json."""
import json
import re
from dataclasses import dataclass
from typing import List, Optional

from .config import PACKAGE_JSON, PYPROJECT, REQUIREMENTS

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover - older interpreters skip pyproject parsing
    tomllib = None

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(==|===|>=|~=|<=|>|<|!=)?\s*([^\s;,#]*)")
PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(?:\(?\s*(==|===|>=|~=)\s*([^\s;,)]+))?")
NPM_VERSION = re.compile(r"^[~^]?v?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)$")


@dataclass
class Dependency:
    name: str
    version: str  # exact version, or the lower bound for ranges
    ecosystem: str  # PyPI | npm
    file: str
    line: int
    exact: bool

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name.lower()}@{self.version}"


def _line_of(text: str, needle: str) -> int:
    for number, line in enumerate(text.split("\n"), 1):
        if needle in line:
            return number
    return 1


def parse_requirements(path: str, text: str) -> List[Dependency]:
    deps = []
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = REQ_LINE.match(line)
        if m and m.group(3) in ("==", "===", ">=", "~=") and m.group(4) and "*" not in m.group(4):
            deps.append(Dependency(m.group(1), m.group(4), "PyPI", path, number, m.group(3) in ("==", "===")))
    return deps


def parse_pyproject(path: str, text: str) -> List[Dependency]:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, TypeError):
        return []
    deps = []
    for spec in data.get("project", {}).get("dependencies", []) or []:
        m = PEP508.match(str(spec))
        if m and m.group(3) and m.group(4):
            deps.append(Dependency(m.group(1), m.group(4), "PyPI", path, _line_of(text, str(spec)), m.group(3) in ("==", "===")))
    return deps


def parse_package_json(path: str, text: str) -> List[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            m = NPM_VERSION.match(str(spec).strip())
            if m:
                exact = not str(spec).strip().startswith(("^", "~"))
                deps.append(Dependency(name, m.group(1), "npm", path, _line_of(text, f'"{name}"'), exact))
    return deps


def parse_manifest(kind: str, path: str, text: str) -> Optional[List[Dependency]]:
    parser = {REQUIREMENTS: parse_requirements, PYPROJECT: parse_pyproject, PACKAGE_JSON: parse_package_json}.get(kind)
    return parser(path, text) if parser else None
