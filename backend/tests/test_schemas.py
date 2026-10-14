import json

import pytest
from pydantic import ValidationError

from reviewer.llm import LLMError, get_system_prompt, parse_ai_response
from reviewer.schemas import AnalyzeRequest, VulnerabilityFinding
from tests.conftest import make_finding


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/olegicks/ai-appsec-reviewer",
        "https://github.com/owner/repo/",
        "https://github.com/owner/repo.git",
        "https://github.com/a-b/c_d.e",
    ],
)
def test_accepts_github_urls(url):
    assert AnalyzeRequest(mode="repo", repo_url=url).repo_url == url


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://github.com/owner/repo",
        "https://gitlab.com/owner/repo",
        "https://github.com/owner",
        "https://github.com/owner/repo/tree/main",
        "https://github.com/owner/repo; rm -rf /",
        "file:///etc/passwd",
        "https://github.com.evil.com/owner/repo",
    ],
)
def test_rejects_non_github_urls(url):
    with pytest.raises(ValidationError):
        AnalyzeRequest(mode="repo", repo_url=url)


def test_repo_url_ignored_in_snippet_mode():
    assert AnalyzeRequest(mode="snippet", code="print(1)", repo_url="not a url").mode == "snippet"


@pytest.mark.parametrize("field, value", [("mode", "zip"), ("language", "cobol"), ("paranoia_level", "max")])
def test_rejects_unknown_enum_values(field, value):
    data = {"mode": "snippet", "code": "print(1)", field: value}
    with pytest.raises(ValidationError):
        AnalyzeRequest(**data)


def test_rejects_oversized_snippet():
    with pytest.raises(ValidationError):
        AnalyzeRequest(mode="snippet", code="a" * 50_001)


def test_finding_normalises_case_and_line_numbers():
    finding = VulnerabilityFinding(**make_finding(severity="high", confidence=" Medium ", line=12))

    assert finding.severity == "HIGH"
    assert finding.confidence == "MEDIUM"
    assert finding.line == "Line 12"


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValidationError):
        VulnerabilityFinding(**make_finding(severity="catastrophic"))


def test_parse_ai_response_sorts_by_severity():
    payload = json.dumps({"vulnerabilities": [
        make_finding(severity="LOW"), make_finding(severity="CRITICAL"), make_finding(severity="MEDIUM"),
    ]})
    result = parse_ai_response(payload)

    assert [v.severity for v in result.vulnerabilities] == ["CRITICAL", "MEDIUM", "LOW"]


def test_parse_ai_response_accepts_bare_list():
    result = parse_ai_response(json.dumps([make_finding()]))
    assert len(result.vulnerabilities) == 1


@pytest.mark.parametrize("payload", ["not json", '{"vulnerabilities": [{"file": "x"}]}', ""])
def test_parse_ai_response_rejects_bad_output(payload):
    with pytest.raises(LLMError) as exc:
        parse_ai_response(payload)
    assert exc.value.status_code == 502


def test_system_prompt_guards_against_prompt_injection():
    prompt = get_system_prompt("standard")
    assert "UNTRUSTED DATA" in prompt
    assert "ONLY confidently exploitable" in prompt
    assert "Report ALL potential risks" in get_system_prompt("aggressive")
