"""Builds the LLM context: discovery -> secret redaction -> SAST -> size-limited context."""
import logging
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import List

from .config import settings
from .sast import run_bandit_on_file
from .secrets import format_secret_findings, scan_and_redact_secrets

logger = logging.getLogger(__name__)

LANGUAGE_BY_EXT = {
    ".py": "PYTHON",
    ".js": "JAVASCRIPT",
    ".jsx": "JAVASCRIPT",
    ".mjs": "JAVASCRIPT",
    ".ts": "TYPESCRIPT",
    ".tsx": "TYPESCRIPT",
    ".java": "JAVA",
    ".cpp": "CPP",
    ".cc": "CPP",
    ".c": "C",
    ".h": "C",
    ".go": "GO",
    ".php": "PHP",
    ".rb": "RUBY",
}

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "venv", ".venv", "__pycache__",
    "site-packages", ".next", "coverage", "third_party",
}

SNIPPET_EXT = {"python": ".py", "javascript": ".js", "typescript": ".ts", "java": ".java", "cpp": ".cpp", "go": ".go"}


class PipelineError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class PipelineContext:
    text: str = ""
    files_scanned: int = 0
    secrets_found: int = 0
    sast_findings: int = 0
    truncated: bool = False
    files: List[str] = field(default_factory=list)


def _force_rmtree(path: str) -> None:
    """rmtree that also removes read-only files (git pack files on Windows)."""
    def _onerror(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_onerror)
    else:
        shutil.rmtree(path, onerror=_onerror)


def build_file_context(rel_path: str, language: str, code: str, workdir: str) -> tuple:
    """Redact secrets, run SAST where supported and render one file block for the prompt."""
    redacted_code, secrets = scan_and_redact_secrets(code, rel_path)
    sast_text, sast = "N/A", []

    if language == "PYTHON":
        # Bandit only ever sees the redacted version of the code.
        tmp_path = os.path.join(workdir, "_scan_target.py")
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(redacted_code)
        try:
            sast_text, sast = run_bandit_on_file(tmp_path, rel_path)
        finally:
            os.remove(tmp_path)

    block = (
        f"\n--- FILE: {rel_path} ---\n"
        f"LANGUAGE: {language}\n"
        f"STATIC SECRETS: {format_secret_findings(secrets)}\n"
        f"BANDIT SAST: {sast_text}\n"
        f"CODE:\n{redacted_code}\n"
    )
    return block, len(secrets), len(sast)


def build_snippet_context(code: str, language: str) -> PipelineContext:
    workdir = tempfile.mkdtemp(prefix="appsec-snippet-")
    try:
        block, n_secrets, n_sast = build_file_context(
            f"snippet{SNIPPET_EXT.get(language, '')}", language.upper(), code, workdir
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return PipelineContext(text=block, files_scanned=1, secrets_found=n_secrets, sast_findings=n_sast,
                           files=["snippet"])


def iter_source_files(root: str):
    """Yield (absolute path, relative path, language) in a stable order, skipping vendored dirs."""
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            ext = os.path.splitext(name)[1].lower()
            if ext in LANGUAGE_BY_EXT:
                path = os.path.join(current, name)
                yield path, os.path.relpath(path, root).replace(os.sep, "/"), LANGUAGE_BY_EXT[ext]


def collect_directory_context(root: str) -> PipelineContext:
    ctx = PipelineContext()
    workdir = tempfile.mkdtemp(prefix="appsec-work-")
    try:
        for path, rel_path, language in iter_source_files(root):
            if ctx.files_scanned >= settings.max_repo_files:
                ctx.truncated = True
                break
            try:
                if os.path.getsize(path) > settings.max_file_bytes:
                    continue
                with open(path, "r", encoding="utf-8") as f:
                    code = f.read()
            except (OSError, UnicodeDecodeError):
                continue

            block, n_secrets, n_sast = build_file_context(rel_path, language, code, workdir)
            if len(ctx.text) + len(block) > settings.max_context_chars:
                ctx.text += "\n--- [TRUNCATED] Maximum context limit reached ---\n"
                ctx.truncated = True
                break

            ctx.text += block
            ctx.files_scanned += 1
            ctx.secrets_found += n_secrets
            ctx.sast_findings += n_sast
            ctx.files.append(rel_path)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return ctx


def clone_repository(repo_url: str, dest: str) -> None:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}  # never hang on a credential prompt for private repos
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", repo_url, dest],
            check=True, capture_output=True, timeout=settings.clone_timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        raise PipelineError(504, "Repository clone timed out.")
    except subprocess.CalledProcessError:
        raise PipelineError(400, "Failed to clone repository. Make sure it exists and is public.")


def build_repository_context(repo_url: str) -> PipelineContext:
    temp_dir = tempfile.mkdtemp(prefix="appsec-repo-")
    try:
        clone_repository(repo_url, temp_dir)
        ctx = collect_directory_context(temp_dir)
    finally:
        _force_rmtree(temp_dir)
    if not ctx.files_scanned:
        raise PipelineError(422, "No supported source files found in the repository.")
    return ctx
