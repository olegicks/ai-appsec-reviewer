"""Typed rule definition and the per-file context rules match against."""
import ast
from dataclasses import dataclass, field
from functools import cached_property
from typing import Callable, Iterable, List, Optional, Tuple

from ..findings import Finding, max_severity, min_confidence


@dataclass
class Match:
    line: int
    snippet: str = ""
    detail: str = ""  # appended to the rule description, e.g. which topic or port triggered it
    severity: Optional[str] = None  # may raise (never lower) the rule's severity floor
    confidence: Optional[str] = None  # may lower (never raise) the rule's confidence


@dataclass
class FileContext:
    """One (already redacted) file. Rules never see unredacted secrets."""

    path: str
    language: str  # PYTHON, JAVASCRIPT, ..., DOCKERFILE, COMPOSE, K8S, REQUIREMENTS, PYPROJECT, PACKAGE_JSON
    text: str

    @cached_property
    def lines(self) -> List[str]:
        return self.text.split("\n")

    @cached_property
    def tree(self) -> Optional[ast.AST]:
        if self.language != "PYTHON":
            return None
        try:
            return ast.parse(self.text)
        except (SyntaxError, ValueError):
            return None

    def line_text(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].strip()[:240]
        return ""


Matcher = Callable[[FileContext], Iterable[Match]]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity_floor: str
    cwe: str
    stride: Tuple[str, ...]
    description: str
    remediation: str
    references: Tuple[str, ...] = ()
    pack: str = ""
    languages: Tuple[str, ...] = ("*",)
    confidence: str = "HIGH"
    exposure: bool = False
    user_input: bool = False
    owasp: str = ""
    match_ast: Optional[Matcher] = field(default=None, compare=False)
    match_text: Optional[Matcher] = field(default=None, compare=False)
    match_config: Optional[Matcher] = field(default=None, compare=False)

    def applies_to(self, ctx: FileContext) -> bool:
        return "*" in self.languages or ctx.language in self.languages

    def match(self, ctx: FileContext) -> List[Tuple[Match, str]]:
        """Prefer the AST matcher for parseable Python, fall back to text; config rules use config."""
        if not self.applies_to(ctx):
            return []
        if self.match_config is not None:
            return [(m, "config") for m in self.match_config(ctx)]
        if self.match_ast is not None and ctx.tree is not None:
            return [(m, "python_ast") for m in self.match_ast(ctx)]
        if self.match_text is not None:
            return [(m, "text") for m in self.match_text(ctx)]
        return []

    def to_finding(self, ctx: FileContext, m: Match, engine: str) -> Finding:
        description = self.description + (f" {m.detail}" if m.detail else "")
        return Finding(
            rule_id=self.id,
            title=self.title,
            category=self.category,
            engine=engine,
            severity=max_severity(self.severity_floor, m.severity or self.severity_floor),
            confidence=min_confidence(self.confidence, m.confidence or self.confidence),
            file=ctx.path,
            line=m.line,
            snippet=m.snippet or ctx.line_text(m.line),
            cwe=self.cwe,
            stride=list(self.stride),
            description=description,
            remediation=self.remediation,
            references=list(self.references),
            owasp=self.owasp,
            pack=self.pack,
            exposure=self.exposure,
            user_input=self.user_input,
        )
