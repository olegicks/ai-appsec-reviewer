"""Converts internal findings into the (backwards compatible) API response shape."""
from typing import Dict, List, Optional

from .findings import SEVERITIES, Finding
from .schemas import FindingOut, RiskOut
from .taxonomy import owasp_for

ENGINE_LABEL = {
    "python_ast": "Rule engine",
    "text": "Rule engine",
    "config": "Rule engine",
    "deps": "OSV",
    "bandit": "Bandit",
    "secrets": "Secret Scanner",
    "llm": "AI Analysis",
}


def source_label(f: Finding) -> str:
    labels: List[str] = []
    for engine in [f.engine] + [e for e in f.engines if e != f.engine]:
        label = ENGINE_LABEL.get(engine, engine)
        if label not in labels:
            labels.append(label)
    return " + ".join(labels)


def to_output(f: Finding, risk: Optional[RiskOut] = None, compliance: Optional[Dict[str, List[str]]] = None) -> FindingOut:
    explanation = f.description
    if f.ai_note and f.engine != "llm":
        explanation += f" AI review: {f.ai_note}"
    return FindingOut(
        file=f.file,
        line=f"Line {f.line}" if f.line else "N/A",
        vulnerability=f.title,
        severity=f.severity,
        confidence=f.confidence,
        cwe=f.cwe or "N/A",
        owasp=f.owasp or owasp_for(f.cwe) or "N/A",
        source=source_label(f),
        risk_explanation=explanation,
        secure_code_snippet=f.remediation,
        id=f.fingerprint,
        rule_id=f.rule_id,
        title=f.title,
        category=f.category,
        pack=f.pack,
        engine=f.engine,
        engines=f.engines,
        stride=f.stride,
        line_number=f.line,
        excerpt=f.snippet,
        references=f.references,
        ai_verdict=f.ai_verdict,
        ai_note=f.ai_note,
        risk=risk,
        compliance=compliance or {},
        dependency=f.extra.get("dependency"),
    )


def summarize(findings: List[Finding]) -> Dict[str, int]:
    summary = {s: 0 for s in SEVERITIES}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1
    summary["TOTAL"] = len(findings)
    return summary
