import os
import sys

# Deterministic settings for the whole suite; must be set before the app is imported.
os.environ["OPENAI_API_KEY"] = "test-key"
os.environ["FRONTEND_URL"] = "http://localhost:5173"
os.environ.pop("RATE_LIMIT", None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from reviewer.schemas import AIAnalysisResult  # noqa: E402


def make_finding(**overrides):
    finding = {
        "file": "snippet.py",
        "line": "Line 7",
        "vulnerability": "SQL Injection",
        "severity": "HIGH",
        "confidence": "HIGH",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "source": "AI Analysis",
        "risk_explanation": "User input is concatenated into a SQL query.",
        "secure_code_snippet": "cursor.execute('SELECT * FROM users WHERE name = ?', (username,))",
    }
    finding.update(overrides)
    return finding


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    main.limiter.reset()
    yield


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture
def fake_ai(monkeypatch):
    """Replace the OpenAI call; records the prompt context and returns canned findings."""
    calls = {"contexts": [], "findings": [make_finding()]}

    def _fake(context, paranoia):
        calls["contexts"].append((context, paranoia))
        return AIAnalysisResult(vulnerabilities=calls["findings"])

    monkeypatch.setattr(main, "run_ai_analysis", _fake)
    return calls
