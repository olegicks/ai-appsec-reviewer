import main
from reviewer.llm import LLMError
from reviewer.pipeline import PipelineError
from tests.conftest import make_finding

SNIPPET = {
    "mode": "snippet",
    "language": "python",
    "code": "import sqlite3\ncursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
    "paranoia_level": "standard",
}


def test_root_and_health(client):
    assert client.get("/").json()["status"] == "ok"

    health = client.get("/health").json()
    assert health["status"] == "ok"
    assert health["ai_configured"] is True


def test_analyze_snippet_returns_findings_summary_and_meta(client, fake_ai):
    fake_ai["findings"] = [make_finding(severity="CRITICAL"), make_finding(severity="LOW")]

    res = client.post("/analyze", json=SNIPPET)

    assert res.status_code == 200
    body = res.json()
    assert len(body["vulnerabilities"]) == 2
    assert body["summary"]["CRITICAL"] == 1
    assert body["summary"]["LOW"] == 1
    assert body["summary"]["TOTAL"] == 2
    assert body["meta"]["mode"] == "snippet"
    assert body["meta"]["files_scanned"] == 1
    assert body["meta"]["duration_ms"] >= 0


def test_secrets_never_reach_the_ai(client, fake_ai):
    payload = {**SNIPPET, "code": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\nprint(AWS_KEY)'}

    res = client.post("/analyze", json=payload)

    assert res.status_code == 200
    context, _ = fake_ai["contexts"][0]
    assert "AKIAIOSFODNN7EXAMPLE" not in context
    assert "[REDACTED]" in context
    assert res.json()["meta"]["secrets_found"] == 1


def test_paranoia_level_is_forwarded(client, fake_ai):
    client.post("/analyze", json={**SNIPPET, "paranoia_level": "aggressive"})
    assert fake_ai["contexts"][0][1] == "aggressive"


def test_short_snippet_is_rejected(client, fake_ai):
    res = client.post("/analyze", json={**SNIPPET, "code": "  "})
    assert res.status_code == 400
    assert fake_ai["contexts"] == []


def test_invalid_payload_returns_422(client, fake_ai):
    res = client.post("/analyze", json={"mode": "repo", "repo_url": "https://evil.example/x/y"})
    assert res.status_code == 422


def test_pipeline_errors_are_returned_as_json(client, fake_ai, monkeypatch):
    def boom(url):
        raise PipelineError(400, "Failed to clone repository.")

    monkeypatch.setattr(main, "build_repository_context", boom)
    res = client.post("/analyze", json={"mode": "repo", "repo_url": "https://github.com/owner/missing"})

    assert res.status_code == 400
    assert res.json() == {"detail": "Failed to clone repository."}


def test_ai_errors_are_returned_as_json(client, monkeypatch):
    def fail(context, paranoia):
        raise LLMError(502, "AI returned malformed JSON data.")

    monkeypatch.setattr(main, "run_ai_analysis", fail)
    res = client.post("/analyze", json=SNIPPET)

    assert res.status_code == 502
    assert "malformed" in res.json()["detail"]


def test_rate_limit_kicks_in(client, fake_ai):
    statuses = [client.post("/analyze", json=SNIPPET).status_code for _ in range(6)]
    assert statuses[:5] == [200] * 5
    assert statuses[5] == 429


def test_cors_allows_only_configured_origin(client):
    ok = client.options("/analyze", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"})
    bad = client.options("/analyze", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})

    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in bad.headers


def test_security_headers_present(client):
    res = client.get("/health")
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY"
