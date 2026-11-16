"""Discovery -> secret redaction -> deterministic engines (rules, Bandit) -> size-limited LLM context."""
import logging
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Set

from .config import settings
from .findings import Finding, dedupe
from .rules import FileContext, bandit_findings, run_rules, secret_findings
from .rules.ot_ics import is_ot_file
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
class FileScan:
    ctx: FileContext  # redacted content
    findings: List[Finding]
    secrets: int
    sast: int
    block: str


@dataclass
class PipelineContext:
    text: str = ""
    files_scanned: int = 0
    secrets_found: int = 0
    sast_findings: int = 0
    truncated: bool = False
    files: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    contexts: Dict[str, FileContext] = field(default_factory=dict)
    ot_files: Set[str] = field(default_factory=set)
    config_files: List[Dict[str, str]] = field(default_factory=list)
    dependencies: Dict = field(default_factory=dict)
    engines: Set[str] = field(default_factory=set)

    def add(self, scan: FileScan) -> None:
        self.text += scan.block
        self.files_scanned += 1
        self.secrets_found += scan.secrets
        self.sast_findings += scan.sast
        self.files.append(scan.ctx.path)
        self.findings.extend(scan.findings)
        self.contexts[scan.ctx.path] = scan.ctx
        if is_ot_file(scan.ctx):
            self.ot_files.add(scan.ctx.path)


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


def render_block(scan: FileScan, secret_text: str, sast_text: str) -> str:
    listed = "\n".join(
        f"- id={f.fingerprint} rule={f.rule_id} line={f.line}: {f.title}" for f in scan.findings
    ) or "none"
    return (
        f"\n--- FILE: {scan.ctx.path} ---\n"
        f"LANGUAGE: {scan.ctx.language}\n"
        f"STATIC SECRETS: {secret_text}\n"
        f"BANDIT SAST: {sast_text}\n"
        f"DETERMINISTIC FINDINGS (review each id):\n{listed}\n"
        f"CODE:\n{scan.ctx.text}\n"
    )


def scan_file(rel_path: str, language: str, code: str, workdir: str) -> FileScan:
    """Redact secrets first; every engine below only ever sees the redacted text."""
    redacted_code, secrets = scan_and_redact_secrets(code, rel_path)
    ctx = FileContext(rel_path, language, redacted_code)
    sast_text, sast = "N/A", []

    if language == "PYTHON":
        tmp_path = os.path.join(workdir, "_scan_target.py")
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(redacted_code)
        try:
            sast_text, sast = run_bandit_on_file(tmp_path, rel_path)
        finally:
            os.remove(tmp_path)

    findings = dedupe(run_rules(ctx) + bandit_findings(ctx, sast) + secret_findings(ctx, secrets))
    scan = FileScan(ctx=ctx, findings=findings, secrets=len(secrets), sast=len(sast), block="")
    scan.block = render_block(scan, format_secret_findings(secrets), sast_text)
    return scan


def build_snippet_context(code: str, language: str) -> PipelineContext:
    workdir = tempfile.mkdtemp(prefix="appsec-snippet-")
    try:
        scan = scan_file(f"snippet{SNIPPET_EXT.get(language, '')}", language.upper(), code, workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    ctx = PipelineContext()
    ctx.add(scan)
    ctx.engines = _engines(ctx, language.upper())
    return ctx


def _engines(ctx: PipelineContext, *languages: str) -> Set[str]:
    engines = {"secrets", "rules"}
    if "PYTHON" in languages:
        engines.add("bandit")
    return engines


def iter_source_files(root: str):
    """Yield (absolute path, relative path, language) in a stable order, skipping vendored dirs."""
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            ext = os.path.splitext(name)[1].lower()
            if ext in LANGUAGE_BY_EXT:
                path = os.path.join(current, name)
                yield path, os.path.relpath(path, root).replace(os.sep, "/"), LANGUAGE_BY_EXT[ext]


def _read(path: str):
    try:
        if os.path.getsize(path) > settings.max_file_bytes:
            return None
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def collect_directory_context(root: str) -> PipelineContext:
    ctx = PipelineContext()
    languages = set()
    workdir = tempfile.mkdtemp(prefix="appsec-work-")
    try:
        for path, rel_path, language in iter_source_files(root):
            if ctx.files_scanned >= settings.max_repo_files:
                ctx.truncated = True
                break
            code = _read(path)
            if code is None:
                continue

            scan = scan_file(rel_path, language, code, workdir)
            if len(ctx.text) + len(scan.block) > settings.max_context_chars:
                ctx.text += "\n--- [TRUNCATED] Maximum context limit reached ---\n"
                ctx.truncated = True
                break
            ctx.add(scan)
            languages.add(language)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    ctx.engines = _engines(ctx, *languages)
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
