"""Turns pipeline output (+ optional AI review) into the final API response.

Kept separate from the FastAPI route so the evaluation harness can reuse exactly the same logic.
"""
from typing import List, Optional

from . import compliance, risk
from .findings import STRIDE, Finding, severity_rank
from .output import summarize, to_output
from .pipeline import PipelineContext
from .schemas import AIAnalysisResult, AnalyzeResponse, ScanMeta
from .triage import apply_ai, filter_noise

TOP_RISKS = 5


def build_findings(ctx: PipelineContext, ai_result: Optional[AIAnalysisResult], paranoia: str) -> List[Finding]:
    findings = filter_noise(ctx.findings, paranoia)
    if ai_result is not None:
        findings = apply_ai(findings, ai_result, paranoia, ctx.contexts)
    findings.sort(key=lambda f: (severity_rank(f.severity), f.file, f.line))
    return findings


def build_response(ctx: PipelineContext, findings: List[Finding], *, mode: str, paranoia: str, model: str,
                   ai_status: str, duration_ms: int) -> AnalyzeResponse:
    risks = risk.assess(findings, ctx.ot_files, risk.user_input_files(ctx.contexts))
    findings = sorted(findings, key=lambda f: risks[f.fingerprint].id)
    mapping = {f.fingerprint: compliance.controls_for(f) for f in findings}

    stride_summary = {category: 0 for category in STRIDE}
    for f in findings:
        for category in f.stride:
            stride_summary[category] = stride_summary.get(category, 0) + 1

    engines = sorted(ctx.engines | ({"llm"} if ai_status == "used" else set()))
    return AnalyzeResponse(
        vulnerabilities=[to_output(f, risks[f.fingerprint], mapping[f.fingerprint]) for f in findings],
        summary=summarize(findings),
        meta=ScanMeta(
            mode=mode,
            model=model,
            paranoia_level=paranoia,
            files_scanned=ctx.files_scanned,
            secrets_found=ctx.secrets_found,
            sast_findings=ctx.sast_findings,
            truncated=ctx.truncated,
            duration_ms=duration_ms,
            engines=engines,
            ai_status=ai_status,
            rule_findings=sum(1 for f in findings if f.engine in ("python_ast", "text", "config", "deps")),
            config_files=ctx.config_files,
        ),
        risk_matrix=risk.matrix(findings, risks),
        top_risks=[f.fingerprint for f in findings[:TOP_RISKS]],
        stride_summary=stride_summary,
        compliance_summary=compliance.summary(findings, mapping),
        dependencies=ctx.dependencies,
    )
