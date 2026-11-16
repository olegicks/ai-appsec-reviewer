import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from reviewer import osv
from reviewer.config import settings
from reviewer.pipeline import build_snippet_context
from reviewer.rules.deps import Dependency, parse_package_json, parse_pyproject, parse_requirements

FIXTURES = Path(__file__).parent / "fixtures" / "config"

ADVISORIES = {
    "GHSA-x84v-xcm2-53pg": {
        "id": "GHSA-x84v-xcm2-53pg",
        "summary": "Insufficiently Protected Credentials in Requests",
        "aliases": ["CVE-2018-18074"],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}],
    },
    "GHSA-p6mc-m468-83gw": {
        "id": "GHSA-p6mc-m468-83gw",
        "summary": "Prototype Pollution in lodash",
        "database_specific": {"severity": "MODERATE"},
        "affected": [{"package": {"name": "lodash", "ecosystem": "npm"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]}],
    },
}
VULNERABLE = {("requests", "2.19.0"): ["GHSA-x84v-xcm2-53pg"], ("lodash", "4.17.15"): ["GHSA-p6mc-m468-83gw"]}


def osv_handler(calls):
    def handler(request: httpx.Request):
        calls.append(request.url.path)
        if request.url.path.endswith("/querybatch"):
            queries = json.loads(request.content)["queries"]
            results = []
            for q in queries:
                ids = VULNERABLE.get((q["package"]["name"], q["version"]), [])
                results.append({"vulns": [{"id": i} for i in ids]} if ids else {})
            return httpx.Response(200, json={"results": results})
        vuln_id = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=ADVISORIES[vuln_id])
    return handler


@pytest.fixture
def osv_mock(monkeypatch):
    calls = []
    monkeypatch.setattr(osv, "_make_client", lambda: httpx.Client(transport=httpx.MockTransport(osv_handler(calls))))
    return calls


def test_parse_requirements_keeps_pinned_and_lower_bounds():
    deps = parse_requirements("requirements.txt", (FIXTURES / "requirements.txt").read_text())

    assert [(d.name, d.version, d.exact, d.line) for d in deps] == [
        ("requests", "2.19.0", True, 1), ("flask", "2.0.0", False, 2), ("django", "3.2.0", False, 4),
    ]


def test_parse_package_json_direct_dependencies_only():
    deps = parse_package_json("package.json", (FIXTURES / "package.json").read_text())

    assert [(d.name, d.version, d.exact) for d in deps] == [
        ("lodash", "4.17.15", True), ("express", "4.17.1", False), ("vite", "5.0.0", False),
    ]
    assert deps[0].line == 4


def test_parse_pyproject():
    deps = parse_pyproject("pyproject.toml", (FIXTURES / "pyproject.toml").read_text())
    assert [(d.name, d.version, d.exact) for d in deps] == [("pymodbus", "3.6.2", True), ("paho-mqtt", "1.6.1", False)]


def test_malformed_manifests_are_ignored():
    assert parse_package_json("package.json", "{not json") == []
    assert parse_pyproject("pyproject.toml", "[project\n") == []


def test_lookup_builds_findings_with_fix_versions(osv_mock):
    deps = [Dependency("requests", "2.19.0", "PyPI", "requirements.txt", 1, True),
            Dependency("flask", "2.0.0", "PyPI", "requirements.txt", 2, False),
            Dependency("lodash", "4.17.15", "npm", "package.json", 4, True)]

    findings, status = osv.lookup(deps)

    assert status["status"] == "ok" and status["checked"] == 3 and status["vulnerable"] == 2
    req = next(f for f in findings if f.extra["dependency"]["package"] == "requests")
    assert req.severity == "HIGH" and req.confidence == "HIGH"
    assert req.extra["dependency"]["fixed_version"] == "2.20.0"
    assert req.extra["dependency"]["aliases"] == ["CVE-2018-18074"]
    assert "Upgrade requests to 2.20.0" in req.remediation
    lodash = next(f for f in findings if f.extra["dependency"]["package"] == "lodash")
    assert lodash.severity == "MEDIUM"
    assert osv_mock.count("/v1/querybatch") == 1


def test_lookup_degrades_when_osv_is_unreachable():
    findings, status = osv.lookup([Dependency("requests", "2.19.0", "PyPI", "r.txt", 1, True)])

    assert findings == []
    assert status["status"] == "unavailable"
    assert "unavailable" in status["note"]


def test_lookup_degrades_on_server_error(monkeypatch):
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    _, status = osv.lookup([Dependency("a", "1.0", "PyPI", "r.txt", 1, True)], client=client)
    assert status["status"] == "unavailable"


def test_lookup_can_be_disabled(monkeypatch, osv_mock):
    monkeypatch.setattr(osv, "settings", replace(settings, osv_enabled=False))
    _, status = osv.lookup([Dependency("a", "1.0", "PyPI", "r.txt", 1, True)])

    assert status["status"] == "disabled"
    assert osv_mock == []


def test_lookup_respects_package_and_detail_limits(monkeypatch, osv_mock):
    monkeypatch.setattr(osv, "settings", replace(settings, osv_max_packages=1, osv_max_vulns=0))
    deps = [Dependency("requests", "2.19.0", "PyPI", "r.txt", 1, True), Dependency("lodash", "4.17.15", "npm", "p.json", 2, True)]

    findings, status = osv.lookup(deps)

    assert status["checked"] == 1
    assert "first 1 packages" in status["note"] and "skipped" in status["note"]
    assert len(findings) == 1  # still reported, just without fetched details
    assert not any("/vulns/" in c for c in osv_mock)


def test_two_advisories_on_one_line_keep_distinct_ids():
    dep = Dependency("x", "1.0", "PyPI", "r.txt", 1, True)
    a, b = osv._finding(dep, {"id": "A"}), osv._finding(dep, {"id": "B"})
    assert a.fingerprint != b.fingerprint


def test_snippet_manifest_scan_reports_dependencies(osv_mock):
    ctx = build_snippet_context((FIXTURES / "requirements.txt").read_text(), "config")

    assert ctx.dependencies["status"] == "ok"
    assert [f.rule_id for f in ctx.findings if f.engine == "deps"] == ["DEP-001"]
    assert "deps" in ctx.engines


def test_api_reports_unavailable_dependency_check(client, fake_ai):
    res = client.post("/analyze", json={"mode": "snippet", "language": "config", "code": "requests==2.19.0\n"})

    assert res.status_code == 200
    assert res.json()["dependencies"]["status"] == "unavailable"


def test_api_dependency_findings_have_v2_dependency_block(client, fake_ai, osv_mock):
    fake_ai["findings"] = []
    res = client.post("/analyze", json={"mode": "snippet", "language": "config", "code": "requests==2.19.0\n"})

    dep = res.json()["vulnerabilities"][0]
    assert dep["rule_id"] == "DEP-001" and dep["source"] == "OSV"
    assert dep["dependency"]["vuln_id"] == "GHSA-x84v-xcm2-53pg"
    assert dep["cwe"] == "CWE-1395" and dep["owasp"] == "A06:2021"
