import json
from dataclasses import replace
from types import SimpleNamespace

import httpx
import openai
import pytest

import main
from reviewer import llm
from reviewer.config import settings
from reviewer.llm import LLMError, map_openai_error, run_ai_analysis
from tests.conftest import make_finding

REQUEST = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")


def status_error(cls, status, code=None, message="error"):
    body = {"code": code, "message": message} if code else None
    return cls(message, response=httpx.Response(status, request=REQUEST), body=body)


class FakeClient:
    """Mimics client.chat.completions.create; either raises or returns canned findings."""

    def __init__(self, error=None):
        self.error = error
        self.calls = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **params):
        self.calls.append(params)
        if self.error:
            raise self.error
        content = json.dumps({"vulnerabilities": [make_finding()]})
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


@pytest.fixture
def fake_client(monkeypatch):
    client = FakeClient()
    monkeypatch.setattr(llm, "get_client", lambda: client)
    return client


def use_settings(monkeypatch, **overrides):
    monkeypatch.setattr(llm, "settings", replace(settings, **overrides))


def test_uses_configured_model_and_omits_temperature_by_default(fake_client):
    run_ai_analysis("code", "standard")

    params = fake_client.calls[0]
    assert params["model"] == "test-model"
    assert "temperature" not in params
    assert params["response_format"] == {"type": "json_object"}


def test_sends_temperature_only_when_configured(fake_client, monkeypatch):
    use_settings(monkeypatch, temperature=0.0)
    run_ai_analysis("code", "standard")

    assert fake_client.calls[0]["temperature"] == 0.0


@pytest.mark.parametrize(
    "overrides",
    [{"model_id": ""}, {"openai_api_key": ""}],
)
def test_missing_configuration_is_reported(monkeypatch, overrides):
    use_settings(monkeypatch, **overrides)
    llm.get_client.cache_clear()
    try:
        with pytest.raises(LLMError) as exc:
            llm.get_client()
    finally:
        llm.get_client.cache_clear()

    assert exc.value.status_code == 503
    assert exc.value.code == "ai_not_configured"


@pytest.mark.parametrize(
    "error, code, status",
    [
        (status_error(openai.NotFoundError, 404, "model_not_found", "The model `x` does not exist"), "model_unavailable", 503),
        (status_error(openai.BadRequestError, 400, None, "The model `gpt-old` has been deprecated"), "model_unavailable", 503),
        (status_error(openai.PermissionDeniedError, 403), "model_access_denied", 503),
        (status_error(openai.BadRequestError, 400, "unsupported_value", "temperature"), "model_parameter_unsupported", 503),
        (status_error(openai.AuthenticationError, 401, "invalid_api_key"), "ai_auth_failed", 503),
        (status_error(openai.RateLimitError, 429, "insufficient_quota"), "ai_quota_exceeded", 503),
        (status_error(openai.RateLimitError, 429, "rate_limit_exceeded"), "ai_rate_limited", 429),
        (openai.APITimeoutError(request=REQUEST), "ai_unreachable", 504),
        (openai.APIConnectionError(request=REQUEST), "ai_unreachable", 504),
        (status_error(openai.InternalServerError, 500), "ai_error", 502),
        (RuntimeError("boom"), "ai_error", 502),
    ],
)
def test_openai_errors_are_mapped(error, code, status):
    mapped = map_openai_error(error)

    assert mapped.code == code
    assert mapped.status_code == status


def test_unavailable_model_message_names_the_model():
    mapped = map_openai_error(status_error(openai.NotFoundError, 404, "model_not_found"))

    assert "'test-model'" in mapped.detail
    assert "OPENAI_MODEL" in mapped.detail


def test_errors_never_leak_the_api_key(monkeypatch):
    use_settings(monkeypatch, openai_api_key="sk-proj-SUPERSECRET")
    error = status_error(openai.AuthenticationError, 401, "invalid_api_key", "Incorrect API key provided: sk-proj-SUPERSECRET")

    assert "SUPERSECRET" not in map_openai_error(error).detail


def test_api_returns_error_code_for_deprecated_model(client, monkeypatch):
    monkeypatch.setattr(llm, "get_client", lambda: FakeClient(status_error(openai.NotFoundError, 404, "model_not_found")))
    monkeypatch.setattr(main, "run_ai_analysis", llm.run_ai_analysis)

    res = client.post("/analyze", json={"mode": "snippet", "language": "python", "code": "print('hello')"})

    assert res.status_code == 503
    assert res.json()["code"] == "model_unavailable"
    assert "test-model" in res.json()["detail"]


def test_health_reports_unconfigured_model(client, monkeypatch):
    monkeypatch.setattr(main, "settings", replace(settings, model_id=""))

    body = client.get("/health").json()
    assert body["ai_configured"] is False
    assert body["model"] is None
