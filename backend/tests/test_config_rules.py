from pathlib import Path

import pytest

from reviewer.pipeline import PipelineError, build_snippet_context, collect_directory_context
from reviewer.rules import FileContext, rules_by_pack, run_rules
from reviewer.rules.config import detect_from_content, detect_kind, dockerfile_instructions
from reviewer.secrets import scan_and_redact_secrets

FIXTURES = Path(__file__).parent / "fixtures" / "config"
CONFIG_RULES = rules_by_pack("config")


def scan(name: str):
    path = FIXTURES / name
    text = path.read_text(encoding="utf-8")
    kind = detect_kind(name, text)
    redacted, _ = scan_and_redact_secrets(text, name, config=True)
    return run_rules(FileContext(name, kind, redacted), CONFIG_RULES)


def hits(findings):
    return sorted((f.rule_id, f.line) for f in findings)


def test_config_pack_metadata():
    assert len(CONFIG_RULES) == 16
    for rule in CONFIG_RULES:
        assert rule.cwe.startswith("CWE-") and rule.stride and rule.remediation


@pytest.mark.parametrize(
    "name, kind",
    [
        ("Dockerfile", "DOCKERFILE"), ("api.Dockerfile", "DOCKERFILE"), ("docker-compose.prod.yml", "COMPOSE"),
        ("compose.yaml", "COMPOSE"), ("requirements-dev.txt", "REQUIREMENTS"), ("pyproject.toml", "PYPROJECT"),
        ("package.json", "PACKAGE_JSON"), ("notes.txt", None), ("config.yaml", None),
    ],
)
def test_detect_kind_by_filename(name, kind):
    assert detect_kind(name, "key: value\n") == kind


def test_detect_kubernetes_yaml_by_content():
    assert detect_kind("deploy/app.yaml", "apiVersion: v1\nkind: Pod\n") == "K8S"


@pytest.mark.parametrize(
    "text, kind",
    [
        ("FROM alpine:3.20\nRUN apk add curl\n", "DOCKERFILE"),
        ("services:\n  web:\n    image: nginx\n", "COMPOSE"),
        ("apiVersion: v1\nkind: Pod\n", "K8S"),
        ('{"dependencies": {"a": "1.0.0"}}', "PACKAGE_JSON"),
        ("[project]\nname = 'x'\n", "PYPROJECT"),
        ("requests==2.31.0\n", "REQUIREMENTS"),
        ("just some text", None),
    ],
)
def test_detect_from_content(text, kind):
    assert detect_from_content(text) == kind


def test_dockerfile_vulnerable():
    assert hits(scan("Dockerfile.vulnerable")) == [
        ("DOCKER-001", 1), ("DOCKER-002", 1), ("DOCKER-003", 4), ("DOCKER-004", 2), ("DOCKER-004", 3), ("DOCKER-005", 5),
    ]


def test_dockerfile_arg_without_default_has_lower_confidence():
    arg = next(f for f in scan("Dockerfile.vulnerable") if f.rule_id == "DOCKER-004" and f.line == 2)
    assert arg.severity == "HIGH"  # floor stays HIGH; the match cannot lower it
    assert arg.confidence == "MEDIUM"


def test_dockerfile_safe():
    assert scan("Dockerfile.safe") == []


def test_dockerfile_continuations_and_stage_aliases():
    text = "FROM golang:1.22 AS build\nRUN go build \\\n  -o /app\nFROM build\nUSER 0\n"
    instructions = dockerfile_instructions(text)
    assert instructions[1] == (2, "RUN", "go build  -o /app")
    findings = run_rules(FileContext("Dockerfile", "DOCKERFILE", text), CONFIG_RULES)
    assert hits(findings) == [("DOCKER-001", 5)]  # `FROM build` is a stage alias, not an unpinned image


def test_compose_vulnerable():
    assert hits(scan("docker-compose.vulnerable.yml")) == [
        ("COMPOSE-001", 10), ("COMPOSE-002", 11), ("COMPOSE-003", 5), ("COMPOSE-004", 13), ("COMPOSE-005", 2),
    ]


def test_compose_safe():
    assert scan("docker-compose.safe.yml") == []


def test_compose_long_port_syntax():
    text = "services:\n  redis:\n    image: redis:7\n    restart: always\n    healthcheck: {test: [x]}\n" \
           "    ports:\n      - target: 6379\n        published: 6379\n"
    assert hits(run_rules(FileContext("docker-compose.yml", "COMPOSE", text), CONFIG_RULES)) == [("COMPOSE-003", 7)]


def test_kubernetes_vulnerable():
    assert hits(scan("k8s-deployment.vulnerable.yaml")) == [
        ("K8S-001", 20), ("K8S-002", 22), ("K8S-003", 21), ("K8S-004", 15), ("K8S-005", 17), ("K8S-006", 18),
    ]


def test_kubernetes_safe():
    assert scan("k8s-deployment.safe.yaml") == []


def test_invalid_yaml_produces_no_findings():
    assert run_rules(FileContext("docker-compose.yml", "COMPOSE", "services: [unclosed"), CONFIG_RULES) == []


def test_unquoted_config_secrets_are_redacted_before_rules_and_ai():
    ctx = build_snippet_context((FIXTURES / "Dockerfile.vulnerable").read_text(), "config")

    assert "SuperSecret123" not in ctx.text
    assert ctx.config_files == [{"file": "Dockerfile", "kind": "DOCKERFILE"}]
    assert "config" in ctx.engines


def test_config_snippet_must_be_recognised():
    with pytest.raises(PipelineError) as exc:
        build_snippet_context("hello world, not a config", "config")
    assert exc.value.status_code == 422


def test_repository_scan_includes_configs_with_their_own_cap(tmp_path, monkeypatch):
    from dataclasses import replace

    from reviewer import pipeline
    from reviewer.config import settings

    (tmp_path / "app.py").write_text("print('hi')\n")
    (tmp_path / "Dockerfile").write_text((FIXTURES / "Dockerfile.vulnerable").read_text())
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "gateway.yaml").write_text((FIXTURES / "k8s-deployment.vulnerable.yaml").read_text())
    (tmp_path / "notes.yaml").write_text("just: notes\n")
    monkeypatch.setattr(pipeline, "settings", replace(settings, max_config_files=1))

    ctx = collect_directory_context(str(tmp_path))

    assert ctx.files == ["app.py", "Dockerfile"]
    assert ctx.truncated is True
    assert any(f.rule_id == "DOCKER-001" for f in ctx.findings)
