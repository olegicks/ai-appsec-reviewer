"""Deterministic risk scoring: likelihood (1-5) x impact (1-5) on a 5x5 matrix.

Likelihood starts from the finding's confidence (HIGH 3, MEDIUM 2, LOW 1) and gains +1 for network or
industrial-protocol exposure and +1 when attacker-controlled input reaches the sink.
Impact follows severity (CRITICAL 5, HIGH 4, MEDIUM 3, LOW 2, INFO 1); findings in OT/ICS code are
multiplied by 1.25 (rounded up, capped at 5) because integrity and availability failures there can have
physical consequences. Risk = likelihood x impact; bands: Low 1-4, Medium 5-9, High 10-16, Critical 20-25.
"""
import math
import re
from typing import Dict, Iterable, List, Set

from .findings import Finding, severity_rank
from .schemas import RiskOut

FORMULA = (
    "Risk = Likelihood x Impact (each 1-5). Likelihood = confidence (High 3 / Medium 2 / Low 1) "
    "+1 if network- or industrial-protocol-exposed +1 if attacker-controlled input reaches the sink (max 5). "
    "Impact = severity (Critical 5 / High 4 / Medium 3 / Low 2 / Info 1), x1.25 rounded up for OT/ICS code (max 5). "
    "Bands: Low 1-4, Medium 5-9, High 10-16, Critical 20-25."
)
BANDS = (("Critical", 20), ("High", 10), ("Medium", 5), ("Low", 1))
BAND_RANGES = {"Low": "1-4", "Medium": "5-9", "High": "10-16", "Critical": "20-25"}
CONFIDENCE_BASE = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEVERITY_IMPACT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
OT_MULTIPLIER = 1.25

INJECTION_CWES = {"CWE-20", "CWE-22", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-434", "CWE-502",
                  "CWE-601", "CWE-611", "CWE-918"}
USER_INPUT_SOURCES = re.compile(
    r"request\.(args|form|json|values|data|get_json|files|cookies|headers)|\binput\(|sys\.argv|req\.(query|body|params)"
    r"|location\.(search|hash)|URLSearchParams|getParameter\(|msg\.payload|\.recv\(|@app\.(route|get|post)"
)


def band_for(score: int) -> str:
    return next(name for name, low in BANDS if score >= low)


def user_input_files(contexts: Dict[str, object]) -> Set[str]:
    """Files that read obviously attacker-controlled input (HTTP request data, argv, network payloads)."""
    return {path for path, ctx in contexts.items() if USER_INPUT_SOURCES.search(getattr(ctx, "text", ""))}


def score(f: Finding, ot_files: Set[str], input_files: Set[str]) -> RiskOut:
    likelihood = CONFIDENCE_BASE.get(f.confidence, 1)
    factors = [f"Confidence {f.confidence.lower()} -> likelihood base {likelihood}"]
    if f.exposure:
        likelihood += 1
        factors.append("Network / industrial protocol exposure +1")
    if f.user_input or (f.cwe in INJECTION_CWES and f.file in input_files):
        likelihood += 1
        factors.append("Attacker-controlled input reaches the sink +1")
    likelihood = max(1, min(5, likelihood))

    severity = f.extra.get("baseline_severity", f.severity) if f.engine == "llm" else f.severity
    impact = SEVERITY_IMPACT.get(severity, 1)
    factors.append(f"Severity {severity.lower()} -> impact {impact}")
    if f.category == "ot_ics" or f.file in ot_files:
        boosted = min(5, math.ceil(impact * OT_MULTIPLIER))
        if boosted != impact:
            factors.append(f"OT/ICS context x{OT_MULTIPLIER} -> impact {boosted}")
        impact = boosted

    value = likelihood * impact
    return RiskOut(likelihood=likelihood, impact=impact, score=value, band=band_for(value), factors=factors)


def assess(findings: List[Finding], ot_files: Set[str], input_files: Set[str]) -> Dict[str, RiskOut]:
    """Score every finding and assign risk ids R-001.. ordered by score, then severity."""
    risks = {f.fingerprint: score(f, ot_files, input_files) for f in findings}
    ordered = sorted(findings, key=lambda f: (-risks[f.fingerprint].score, severity_rank(f.severity), f.file, f.line))
    for number, f in enumerate(ordered, 1):
        risks[f.fingerprint].id = f"R-{number:03d}"
    return risks


def matrix(findings: Iterable[Finding], risks: Dict[str, RiskOut]) -> Dict:
    cells = {(l, i): [] for l in range(1, 6) for i in range(1, 6)}
    for f in findings:
        r = risks[f.fingerprint]
        cells[(r.likelihood, r.impact)].append(f.fingerprint)
    return {
        "formula": FORMULA,
        "bands": BAND_RANGES,
        "cells": [
            {"likelihood": l, "impact": i, "score": l * i, "band": band_for(l * i), "findings": ids}
            for (l, i), ids in cells.items()
        ],
    }
