import json
from dataclasses import replace
from types import SimpleNamespace

import openai
import pytest

from reviewer import compliance, report, risk
from reviewer.config import settings
from reviewer.findings import Finding
from tests.test_llm import status_error

SMART_GRID = open("tests/fixtures/ot/smart_grid_gateway.py", encoding="utf-8").read()


def finding(**kw):
    base = dict(rule_id="X-1", title="t", category="sast", engine="bandit", severity="HIGH", confidence="HIGH",
                file="a.py", line=1, cwe="CWE-78")
    base.update(kw)
    return Finding(**base)


# --- risk scoring -----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "kw, ot, inputs, expected",
    [
        ({}, set(), set(), (3, 4, 12, "High")),
        ({"confidence": "LOW", "severity": "LOW"}, set(), set(), (1, 2, 2, "Low")),
        ({"exposure": True, "user_input": True, "severity": "CRITICAL"}, set(), set(), (5, 5, 25, "Critical")),
        ({"confidence": "MEDIUM", "severity": "MEDIUM"}, {"a.py"}, set(), (2, 4, 8, "Medium")),
        ({"severity": "LOW", "category": "ot_ics"}, set(), set(), (3, 3, 9, "Medium")),
        ({"severity": "INFO", "category": "ot_ics", "confidence": "LOW"}, set(), set(), (1, 2, 2, "Low")),
        ({"cwe": "CWE-89"}, set(), {"a.py"}, (4, 4, 16, "High")),
        ({"cwe": "CWE-319"}, set(), {"a.py"}, (3, 4, 12, "High")),  # not an injection sink
    ],
)
def test_risk_formula(kw, ot, inputs, expected):
    r = risk.score(finding(**kw), ot, inputs)
    assert (r.likelihood, r.impact, r.score, r.band) == expected
    assert r.factors


def test_ai_only_findings_are_scored_from_the_cwe_baseline():
    f = finding(engine="llm", category="ai", severity="CRITICAL", extra={"baseline_severity": "MEDIUM"})
    assert risk.score(f, set(), set()).impact == 3


@pytest.mark.parametrize("value, band", [(1, "Low"), (4, "Low"), (5, "Medium"), (9, "Medium"), (10, "High"),
                                         (16, "High"), (20, "Critical"), (25, "Critical")])
def test_band_boundaries(value, band):
    assert risk.band_for(value) == band


def test_assess_orders_risk_ids_by_score():
    low = finding(severity="LOW", line=1)
    crit = finding(severity="CRITICAL", line=2, exposure=True)
    risks = risk.assess([low, crit], set(), set())

    assert risks[crit.fingerprint].id == "R-001"
    assert risks[low.fingerprint].id == "R-002"


def test_matrix_places_findings_in_cells():
    f = finding()
    m = risk.matrix([f], risk.assess([f], set(), set()))

    assert len(m["cells"]) == 25
    cell = next(c for c in m["cells"] if c["findings"])
    assert (cell["likelihood"], cell["impact"], cell["score"], cell["band"]) == (3, 4, 12, "High")
    assert "Likelihood" in m["formula"] and m["bands"]["Critical"] == "20-25"


def test_user_input_file_detection():
    ctxs = {"web.py": SimpleNamespace(text="name = request.args.get('n')"), "lib.py": SimpleNamespace(text="x = 1")}
    assert risk.user_input_files(ctxs) == {"web.py"}


# --- compliance ---------------------------------------------------------------------------------

def test_rule_specific_mapping():
    assert compliance.controls_for(finding(rule_id="OT-001", category="ot_ics", cwe="CWE-319")) == {
        "iec62443": ["FR1", "FR3", "FR4", "FR5"], "iso27001": ["A.8.5", "A.8.20", "A.8.24"],
    }


def test_cwe_and_category_mapping():
    dep = compliance.controls_for(finding(rule_id="DEP-001", category="dependency", cwe="CWE-1395"))
    cfg = compliance.controls_for(finding(rule_id="K8S-005", category="config", cwe="CWE-770"))

    assert dep == {"iec62443": ["FR3"], "iso27001": ["A.8.8"]}
    assert cfg == {"iec62443": ["FR7"], "iso27001": ["A.8.6", "A.8.9"]}


def test_stride_fallback_for_unknown_cwe():
    mapped = compliance.controls_for(finding(cwe="CWE-9999", stride=["Repudiation"]))
    assert mapped == {"iec62443": ["FR6"], "iso27001": ["A.8.15", "A.8.16"]}


def test_every_mapped_control_comes_from_the_curated_tables():
    for fr, iso in list(compliance.RULE_MAP.values()) + list(compliance.CWE_MAP.values()) + list(compliance.STRIDE_MAP.values()):
        assert set(fr) <= set(compliance.IEC_62443_FR)
        assert set(iso) <= set(compliance.ISO_27001)


def test_summary_lists_all_controls_with_disclaimer():
    f = finding(rule_id="OT-008", category="ot_ics", cwe="CWE-1392")
    s = compliance.summary([f], {f.fingerprint: compliance.controls_for(f)})

    assert s["disclaimer"] == "Indicative mapping, not a certification or audit result."
    assert [c["id"] for c in s["iec62443"]] == ["FR1", "FR2", "FR3", "FR4", "FR5", "FR6", "FR7"]
    assert next(c for c in s["iec62443"] if c["id"] == "FR1")["findings"] == [f.fingerprint]


# --- API v2 fields ----------------------------------------------------------------------------

@pytest.fixture
def scan_result(client, fake_ai):
    fake_ai["findings"] = []
    res = client.post("/analyze", json={"mode": "snippet", "language": "python", "code": SMART_GRID})
    assert res.status_code == 200
    return res.json()


def test_analyze_returns_risk_matrix_and_compliance(scan_result):
    vulns = scan_result["vulnerabilities"]

    assert [v["risk"]["id"] for v in vulns] == [f"R-{i:03d}" for i in range(1, len(vulns) + 1)]
    assert scan_result["top_risks"] == [v["id"] for v in vulns[:5]]
    assert sum(len(c["findings"]) for c in scan_result["risk_matrix"]["cells"]) == len(vulns)
    assert all(v["compliance"]["iec62443"] for v in vulns)
    assert scan_result["stride_summary"]["Spoofing"] > 0
    assert scan_result["compliance_summary"]["disclaimer"].startswith("Indicative mapping")


# --- Security Assessment Report narrative ------------------------------------------------------

class NarrativeClient:
    def __init__(self, content=None, error=None):
        self.content, self.error, self.calls = content, error, []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **params):
        self.calls.append(params)
        if self.error:
            raise self.error
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=self.content))])


def use_client(monkeypatch, client):
    monkeypatch.setattr(report, "get_client", lambda: client)
    return client


def test_report_without_ai_is_deterministic(client, scan_result, monkeypatch):
    monkeypatch.setattr(report, "settings", replace(settings, model_id=""))
    res = client.post("/report", json={"target": "snippet.py", "result": scan_result})

    body = res.json()
    assert res.status_code == 200
    assert body["generated_by"] == "deterministic"
    assert "not configured" in body["note"]
    assert f"produced {scan_result['summary']['TOTAL']} finding(s)" in body["executive_summary"]
    assert [m["risk_id"] for m in body["mitigations"]] == ["R-001", "R-002", "R-003", "R-004", "R-005"]


def test_report_uses_valid_ai_narrative(client, scan_result, monkeypatch):
    content = json.dumps({
        "executive_summary": "R-001 is the most urgent issue; fix it first.",
        "mitigations": [{"risk_id": "R-001", "text": "Move the link to Modbus/TCP Security."}],
    })
    fake = use_client(monkeypatch, NarrativeClient(content))

    body = client.post("/report", json={"target": "snippet.py", "result": scan_result}).json()

    assert body["generated_by"] == "ai"
    assert body["mitigations"][0]["finding_id"] == scan_result["vulnerabilities"][0]["id"]
    params = fake.calls[0]
    assert params["response_format"]["type"] == "json_schema"
    sent = params["messages"][1]["content"]
    assert "excerpt" not in sent and "[REDACTED]" not in sent  # only computed facts reach the model


@pytest.mark.parametrize(
    "content, reason",
    [
        ({"executive_summary": "There are 99 critical issues.", "mitigations": []}, "numbers"),
        ({"executive_summary": "Fix R-777.", "mitigations": []}, "risk ids"),
        ({"executive_summary": "ok", "mitigations": [{"risk_id": "R-042", "text": "x"}]}, "risk ids"),
        ({"summary": "wrong shape"}, "schema"),
    ],
)
def test_report_rejects_ai_text_that_breaks_the_rules(client, scan_result, monkeypatch, content, reason):
    use_client(monkeypatch, NarrativeClient(json.dumps(content)))
    body = client.post("/report", json={"target": "snippet.py", "result": scan_result}).json()

    assert body["generated_by"] == "deterministic"
    assert reason in body["note"]


def test_report_falls_back_when_the_model_is_unavailable(client, scan_result, monkeypatch):
    use_client(monkeypatch, NarrativeClient(error=status_error(openai.NotFoundError, 404, "model_not_found")))
    body = client.post("/report", json={"target": "snippet.py", "result": scan_result}).json()

    assert body["generated_by"] == "deterministic"
    assert "model_unavailable" in body["note"]


def test_report_rejects_oversized_payload(client, scan_result):
    scan_result["vulnerabilities"] = scan_result["vulnerabilities"][:1] * 301
    assert client.post("/report", json={"target": "x", "result": scan_result}).status_code == 422


def test_report_request_requires_a_result(client):
    assert client.post("/report", json={"target": "x"}).status_code == 422
