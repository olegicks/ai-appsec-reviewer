from dataclasses import replace

import pytest

import main
from reviewer.analysis import build_findings
from reviewer.config import settings
from reviewer.findings import Finding
from reviewer.llm import get_system_prompt, parse_ai_response
from reviewer.pipeline import build_snippet_context
from reviewer.schemas import AIAnalysisResult, AIReview
from reviewer.triage import apply_ai
from tests.conftest import make_finding

MODBUS = (
    "from pymodbus.client import ModbusTcpClient\n"
    "client = ModbusTcpClient('plc.local', timeout=2)\n"
    "client.connect()\n"
)


def rule_finding(**kw):
    base = dict(rule_id="OT-001", title="Modbus/TCP without TLS", category="ot_ics", engine="python_ast",
                severity="HIGH", confidence="HIGH", file="a.py", line=2, cwe="CWE-319")
    base.update(kw)
    return Finding(**base)


def bandit_finding(**kw):
    base = dict(rule_id="B602", title="shell", category="sast", engine="bandit", severity="HIGH",
                confidence="HIGH", file="a.py", line=5, cwe="CWE-78")
    base.update(kw)
    return Finding(**base)


def review(f, verdict, reason="because"):
    return AIReview(id=f.fingerprint, verdict=verdict, reason=reason)


def test_confirmed_review_is_recorded():
    f = rule_finding()
    out = apply_ai([f], AIAnalysisResult(reviews=[review(f, "confirmed")]), "standard")

    assert out[0].ai_verdict == "confirmed"
    assert out[0].ai_note == "because"


def test_rejected_bandit_signal_is_dropped_in_standard_mode():
    b = bandit_finding()
    assert apply_ai([b], AIAnalysisResult(reviews=[review(b, "false_positive")]), "standard") == []


def test_rejected_bandit_signal_is_kept_as_disputed_in_aggressive_mode():
    b = bandit_finding()
    out = apply_ai([b], AIAnalysisResult(reviews=[review(b, "false_positive")]), "aggressive")

    assert out[0].ai_verdict == "disputed"
    assert out[0].confidence == "LOW"


def test_rule_findings_are_never_dropped_by_the_ai():
    f = rule_finding()
    out = apply_ai([f], AIAnalysisResult(reviews=[review(f, "false_positive")]), "standard")

    assert len(out) == 1
    assert out[0].ai_verdict == "disputed"
    assert out[0].severity == "HIGH" and out[0].confidence == "HIGH"


def test_unconfirmed_low_confidence_bandit_is_hidden_in_standard_mode_only():
    b = bandit_finding(confidence="MEDIUM")
    assert apply_ai([b], AIAnalysisResult(), "standard") == []
    assert len(apply_ai([b], AIAnalysisResult(), "aggressive")) == 1


def test_ai_finding_on_same_line_and_cwe_merges_into_rule_finding():
    f = rule_finding()
    ai = AIAnalysisResult(vulnerabilities=[make_finding(file="a.py", line="Line 2", cwe="CWE-319",
                                                        risk_explanation="Cleartext Modbus.")])
    out = apply_ai([f], ai, "standard")

    assert len(out) == 1
    assert out[0].engines == ["llm", "python_ast"]
    assert out[0].ai_verdict == "confirmed"
    assert out[0].ai_note == "Cleartext Modbus."


def test_ai_only_finding_gets_baseline_severity_from_cwe_table():
    ai = AIAnalysisResult(vulnerabilities=[make_finding(file="a.py", line="Line 9", cwe="CWE-89", severity="LOW")])
    out = apply_ai([], ai, "standard")

    assert out[0].engine == "llm" and out[0].ai_verdict == "ai_only"
    assert out[0].severity == "LOW"  # the model's label is kept for API compatibility...
    assert out[0].extra["baseline_severity"] == "HIGH"  # ...but risk uses the CWE baseline
    assert out[0].stride == ["Tampering", "Information Disclosure"]


def test_unknown_review_ids_are_ignored():
    f = rule_finding()
    out = apply_ai([f], AIAnalysisResult(reviews=[AIReview(id="nope", verdict="false_positive")]), "standard")
    assert out[0].ai_verdict == "not_reviewed"


def test_parse_ai_response_accepts_reviews():
    result = parse_ai_response('{"reviews": [{"id": "abc", "verdict": "False Positive", "reason": "test"}]}')
    assert result.reviews[0].verdict == "false_positive"
    assert result.vulnerabilities == []


def test_llm_context_lists_deterministic_findings_by_id():
    ctx = build_snippet_context(MODBUS, "python")
    f = next(f for f in ctx.findings if f.rule_id == "OT-001")

    assert f"id={f.fingerprint} rule=OT-001 line=2" in ctx.text


def test_prompt_covers_reviews_ot_and_untrusted_config():
    prompt = get_system_prompt("standard")
    assert '"reviews"' in prompt
    assert "OT/ICS review" in prompt
    assert "Kubernetes YAML" in prompt and "UNTRUSTED DATA" in prompt


def test_build_findings_without_ai_keeps_deterministic_results():
    ctx = build_snippet_context(MODBUS, "python")
    findings = build_findings(ctx, None, "standard")
    assert [f.rule_id for f in findings] == ["OT-001"]


def test_api_returns_rule_findings_with_v2_fields(client, fake_ai):
    fake_ai["findings"] = []
    res = client.post("/analyze", json={"mode": "snippet", "language": "python", "code": MODBUS})

    body = res.json()
    finding = next(v for v in body["vulnerabilities"] if v["rule_id"] == "OT-001")
    assert finding["line"] == "Line 2" and finding["line_number"] == 2
    assert finding["source"] == "Rule engine"
    assert finding["stride"] == ["Spoofing", "Tampering", "Information Disclosure"]
    assert "ModbusTcpClient" in finding["excerpt"]
    assert finding["id"] and finding["pack"] == "ot_ics"
    assert body["meta"]["rule_findings"] == 1
    assert "llm" in body["meta"]["engines"]


def test_api_works_without_ai_configuration(client, monkeypatch):
    monkeypatch.setattr(main, "settings", replace(settings, model_id=""))
    called = []
    monkeypatch.setattr(main, "run_ai_analysis", lambda *a: called.append(a))

    res = client.post("/analyze", json={"mode": "snippet", "language": "python", "code": MODBUS})

    assert res.status_code == 200
    assert called == []
    assert res.json()["meta"]["ai_status"] == "not_configured"
    assert [v["rule_id"] for v in res.json()["vulnerabilities"]] == ["OT-001"]


@pytest.mark.parametrize("language", ["javascript", "go"])
def test_text_rules_run_on_other_snippet_languages(client, fake_ai, language):
    fake_ai["findings"] = []
    code = "const agent = new https.Agent({ rejectUnauthorized: false });\n"
    res = client.post("/analyze", json={"mode": "snippet", "language": language, "code": code})
    assert "OT-009" in [v["rule_id"] for v in res.json()["vulnerabilities"]]
