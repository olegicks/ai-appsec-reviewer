import os
import shutil
from dataclasses import replace

import pytest

from reviewer import pipeline
from reviewer.config import settings
from reviewer.pipeline import PipelineError, build_repository_context, build_snippet_context, collect_directory_context


def write(root, rel, content):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


@pytest.fixture
def sample_repo(tmp_path):
    root = str(tmp_path)
    write(root, "app/db.py", "import subprocess\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n")
    write(root, "web/index.js", 'const API_KEY = "AKIAIOSFODNN7EXAMPLE";\n')
    write(root, "node_modules/lib/index.js", "eval(input)\n")
    write(root, "README.md", "# docs\n")
    return root


def limits(monkeypatch, **overrides):
    monkeypatch.setattr(pipeline, "settings", replace(settings, **overrides))


def test_collects_only_source_files_and_skips_vendored_dirs(sample_repo):
    ctx = collect_directory_context(sample_repo)

    assert ctx.files == ["app/db.py", "web/index.js"]
    assert "node_modules" not in ctx.text
    assert "README" not in ctx.text


def test_runs_bandit_on_python_and_redacts_secrets(sample_repo):
    ctx = collect_directory_context(sample_repo)

    assert ctx.sast_findings >= 1
    assert "B602" in ctx.text  # subprocess with shell=True
    assert "AKIAIOSFODNN7EXAMPLE" not in ctx.text
    assert ctx.secrets_found == 1


def test_no_temporary_paths_leak_into_context(sample_repo):
    ctx = collect_directory_context(sample_repo)
    assert sample_repo not in ctx.text
    assert "_scan_target" not in ctx.text


def test_respects_max_file_count(sample_repo, monkeypatch):
    limits(monkeypatch, max_repo_files=1)
    ctx = collect_directory_context(sample_repo)

    assert ctx.files_scanned == 1
    assert ctx.truncated is True


def test_skips_files_over_size_limit(sample_repo, monkeypatch):
    write(sample_repo, "big.py", "x = 1\n" * 10_000)
    limits(monkeypatch, max_file_bytes=1024)

    assert "big.py" not in collect_directory_context(sample_repo).files


def test_context_size_limit_truncates(sample_repo, monkeypatch):
    limits(monkeypatch, max_context_chars=200)
    ctx = collect_directory_context(sample_repo)

    assert ctx.truncated is True
    assert "[TRUNCATED]" in ctx.text


def test_snippet_context_runs_bandit_for_python():
    ctx = build_snippet_context("import pickle\npickle.loads(data)\n", "python")

    assert ctx.files_scanned == 1
    assert "LANGUAGE: PYTHON" in ctx.text
    assert "B301" in ctx.text


def test_snippet_context_skips_bandit_for_other_languages():
    ctx = build_snippet_context("document.body.innerHTML = location.hash;", "javascript")

    assert "BANDIT SAST: N/A" in ctx.text
    assert "--- FILE: snippet.js ---" in ctx.text


def test_repository_context_uses_clone(monkeypatch, sample_repo):
    def fake_clone(url, dest):
        shutil.copytree(sample_repo, dest, dirs_exist_ok=True)

    monkeypatch.setattr(pipeline, "clone_repository", fake_clone)
    ctx = build_repository_context("https://github.com/owner/repo")

    assert ctx.files == ["app/db.py", "web/index.js"]


def test_empty_repository_is_rejected(monkeypatch):
    monkeypatch.setattr(pipeline, "clone_repository", lambda url, dest: None)

    with pytest.raises(PipelineError) as exc:
        build_repository_context("https://github.com/owner/empty")
    assert exc.value.status_code == 422
