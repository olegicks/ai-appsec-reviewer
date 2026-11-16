"""Runs rule packs and converts Bandit / secret-scanner output into normalised findings."""
from typing import Iterable, List, Optional, Sequence

from ..findings import Finding
from ..secrets import SecretFinding
from .base import FileContext, Rule

BANDIT_SEVERITY = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}

# Bandit checks that involve data an attacker usually controls.
BANDIT_USER_INPUT = {"B602", "B605", "B608", "B307", "B301", "B506", "B310", "B323"}


def run_rules(ctx: FileContext, rules: Optional[Sequence[Rule]] = None) -> List[Finding]:
    from . import ALL_RULES  # late import: the registry imports the rule packs

    findings: List[Finding] = []
    for rule in rules if rules is not None else ALL_RULES:
        seen_lines = set()
        for match, engine in rule.match(ctx):
            if match.line in seen_lines:  # one finding per rule per line
                continue
            seen_lines.add(match.line)
            findings.append(rule.to_finding(ctx, match, engine))
    return findings


def bandit_findings(ctx: FileContext, raw: Iterable[dict]) -> List[Finding]:
    findings = []
    for item in raw:
        line = int(item.get("line_number") or 0)
        test_id = item.get("test_id") or "BANDIT"
        findings.append(Finding(
            rule_id=test_id,
            title=item.get("test_name") or item.get("issue_text") or test_id,
            category="sast",
            engine="bandit",
            severity=BANDIT_SEVERITY.get(str(item.get("issue_severity")).upper(), "LOW"),
            confidence=BANDIT_SEVERITY.get(str(item.get("issue_confidence")).upper(), "LOW"),
            file=ctx.path,
            line=line,
            snippet=ctx.line_text(line),
            cwe=item.get("cwe") or "",
            description=item.get("issue_text") or "",
            remediation="Review the flagged call and apply the secure alternative recommended by Bandit.",
            references=[f"https://bandit.readthedocs.io/en/latest/search.html?q={test_id}"],
            user_input=test_id in BANDIT_USER_INPUT,
        ))
    return findings


def secret_findings(ctx: FileContext, raw: Iterable[SecretFinding]) -> List[Finding]:
    findings = []
    for s in raw:
        slug = s.type.upper().replace(" ", "-")
        findings.append(Finding(
            rule_id=f"SECRET-{slug}",
            title=f"{s.type} in source",
            category="secret",
            engine="secrets",
            severity="HIGH",
            confidence="MEDIUM",
            file=ctx.path,
            line=s.line,
            snippet=ctx.line_text(s.line),  # the context is already redacted
            cwe="CWE-798",
            stride=["Spoofing", "Information Disclosure", "Elevation of Privilege"],
            description=f"A value that looks like a {s.type.lower()} is embedded in the source. "
                        "Anyone with read access to the code or its history can reuse it.",
            remediation="Remove the value from the code, rotate it, and load it from a secret manager or "
                        "environment variable at runtime.",
            references=["https://cwe.mitre.org/data/definitions/798.html"],
        ))
    return findings
