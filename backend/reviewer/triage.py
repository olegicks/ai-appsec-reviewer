"""Combines deterministic findings with the LLM's review.

Policy (documented in the README):
* rule-engine findings (OT, config, dependency) are always kept; an AI "false_positive" only marks them
  as disputed,
* Bandit and secret-scanner findings the AI rejects are dropped in standard mode and kept (marked
  disputed, LOW confidence) in aggressive mode; in standard mode Bandit findings below HIGH confidence are
  only kept when the AI confirms them (as in v1, where the AI validated every SAST result),
* findings only the AI reports keep the model's severity label (v1 API behaviour), but risk scoring uses
  the static CWE baseline severity instead, so the model never influences the risk score.
"""
import re
from typing import Dict, List, Optional

from .findings import Finding, dedupe, normalize_cwe
from .rules import FileContext
from .schemas import AIAnalysisResult
from .taxonomy import owasp_for, severity_for, stride_for

SIGNAL_ENGINES = {"bandit", "secrets"}


def parse_line(value) -> int:
    match = re.search(r"\d+", str(value or ""))
    return int(match.group()) if match else 0


def filter_noise(findings: List[Finding], paranoia: str) -> List[Finding]:
    """Standard mode hides low-severity Bandit hygiene checks (e.g. B101 assert, B404 import subprocess)."""
    if paranoia == "aggressive":
        return findings
    return [f for f in findings if not (f.engine == "bandit" and f.severity in ("LOW", "INFO"))]


def apply_ai(findings: List[Finding], ai: AIAnalysisResult, paranoia: str,
             files: Optional[Dict[str, FileContext]] = None) -> List[Finding]:
    files = files or {}
    verdicts = {r.id: r for r in ai.reviews}
    kept: List[Finding] = []

    for f in findings:
        review = verdicts.get(f.fingerprint)
        if review is None:
            kept.append(f)
            continue
        f.ai_note = review.reason
        if review.verdict == "confirmed":
            f.ai_verdict = "confirmed"
            kept.append(f)
        elif f.engine in SIGNAL_ENGINES and paranoia != "aggressive":
            continue  # AI rejected a Bandit/secret signal
        else:
            f.ai_verdict = "disputed"
            if f.engine in SIGNAL_ENGINES:
                f.confidence = "LOW"
            kept.append(f)

    for v in ai.vulnerabilities:
        line = parse_line(v.line)
        cwe = normalize_cwe(v.cwe)
        twin = next((f for f in kept if f.engine != "llm" and f.file == v.file and abs(f.line - line) <= 1
                     and f.cwe and f.cwe == cwe), None)
        if twin is not None:
            twin.engines = sorted(set(twin.engines) | {"llm"})
            if twin.ai_verdict == "not_reviewed":
                twin.ai_verdict = "confirmed"
            twin.ai_note = twin.ai_note or v.risk_explanation
            continue
        ctx = files.get(v.file)
        kept.append(Finding(
            rule_id="AI",
            title=v.vulnerability,
            category="ai",
            engine="llm",
            severity=v.severity,
            confidence=v.confidence,
            file=v.file,
            line=line,
            snippet=ctx.line_text(line) if ctx else "",
            cwe=cwe,
            stride=stride_for(cwe),
            description=v.risk_explanation,
            remediation=v.secure_code_snippet,
            owasp=v.owasp if re.match(r"^A\d{2}:20\d\d$", v.owasp or "") else owasp_for(cwe),
            ai_verdict="ai_only",
            extra={"baseline_severity": severity_for(cwe)},
        ))
    if paranoia != "aggressive":
        kept = [f for f in kept if not (f.engine == "bandit" and f.confidence != "HIGH" and f.ai_verdict != "confirmed")]
    return dedupe(kept)
