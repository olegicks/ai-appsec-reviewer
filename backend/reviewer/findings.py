"""Normalised finding model shared by every engine (rules, Bandit, secrets, dependencies, LLM)."""
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
CONFIDENCES = ("HIGH", "MEDIUM", "LOW")
STRIDE = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)

_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_CONF_RANK = {c: i for i, c in enumerate(CONFIDENCES)}


def max_severity(*severities: str) -> str:
    """Most severe of the given values (CRITICAL wins)."""
    valid = [s for s in severities if s in _SEV_RANK]
    return min(valid, key=_SEV_RANK.__getitem__) if valid else "INFO"


def severity_rank(severity: str) -> int:
    return _SEV_RANK.get(severity, len(SEVERITIES))


def min_confidence(*confidences: str) -> str:
    valid = [c for c in confidences if c in _CONF_RANK]
    return max(valid, key=_CONF_RANK.__getitem__) if valid else "LOW"


def normalize_cwe(value: Any) -> str:
    """'CWE-79', 'cwe 79', 79 -> 'CWE-79'; anything without a number -> ''."""
    match = re.search(r"\d+", str(value or ""))
    return f"CWE-{int(match.group())}" if match else ""


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str  # ot_ics | config | dependency | secret | sast | ai
    engine: str  # python_ast | text | config | deps | bandit | secrets | llm
    severity: str
    confidence: str
    file: str
    line: int
    snippet: str = ""
    cwe: str = ""
    stride: List[str] = field(default_factory=list)
    description: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    owasp: str = ""
    pack: str = ""
    engines: List[str] = field(default_factory=list)  # every engine that reported this issue
    ai_verdict: str = "not_reviewed"  # not_reviewed | confirmed | disputed | ai_only
    ai_note: str = ""
    # Likelihood hints set by the engine; risk scoring stays in risk.py.
    exposure: bool = False
    user_input: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.cwe = normalize_cwe(self.cwe)
        if not self.engines:
            self.engines = [self.engine]

    @property
    def fingerprint(self) -> str:
        """Stable id: rule + file + line + hash of the (redacted) code excerpt."""
        basis = " ".join(self.snippet.split())
        if self.engine == "deps":  # one manifest line can carry several advisories
            basis += "|" + str(self.extra.get("dependency", {}).get("vuln_id", ""))
        if self.engine == "llm":  # AI findings have no rule id of their own; the title tells them apart
            basis += "|".join(("", self.title, self.severity, self.description))
        snippet_hash = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]
        raw = f"{self.rule_id}|{self.file}|{self.line}|{snippet_hash}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def dedupe(findings: List[Finding]) -> List[Finding]:
    """Drop exact duplicates (same fingerprint) and fold findings of different engines that
    describe the same weakness on the same line (same file, line and CWE) into one."""
    by_fp: Dict[str, Finding] = {}
    for f in findings:
        by_fp.setdefault(f.fingerprint, f)

    merged: List[Finding] = []
    index: Dict[tuple, Finding] = {}
    for f in by_fp.values():
        key = (f.file, f.line, f.cwe) if f.cwe else None
        existing = index.get(key) if key else None
        if existing is not None and existing.engine == f.engine:
            existing = None  # only fold findings of *different* engines together
        if existing is None:
            merged.append(f)
            if key and key not in index:
                index[key] = f
            continue
        # Prefer the rule engine's metadata, keep the stricter severity, record both engines.
        primary, other = (existing, f) if _prefer(existing, f) else (f, existing)
        primary.severity = max_severity(primary.severity, other.severity)
        primary.engines = sorted(set(primary.engines) | set(other.engines))
        primary.exposure = primary.exposure or other.exposure
        primary.user_input = primary.user_input or other.user_input
        if primary is not existing:
            merged[merged.index(existing)] = primary
            index[key] = primary
    return merged


_ENGINE_PRIORITY = {"python_ast": 0, "config": 0, "deps": 0, "text": 1, "bandit": 2, "secrets": 3, "llm": 4}


def _prefer(a: Finding, b: Finding) -> bool:
    return _ENGINE_PRIORITY.get(a.engine, 9) <= _ENGINE_PRIORITY.get(b.engine, 9)
