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

from . import osv
from .config import settings
from .findings import Finding, dedupe
from .rules import FileContext, bandit_findings, run_rules, secret_findings
from .rules.config import (
    COMPOSE, CONFIG_KINDS, DOCKERFILE, K8S, MANIFEST_KINDS, PACKAGE_JSON, PYPROJECT, REQUIREMENTS, detect_from_content,
    detect_kind,
)
from .rules.deps import parse_manifest
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

CONFIG_EXTS = {".yml", ".yaml", ".txt", ".toml", ".json", ".dockerfile"}

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
    is_config = language in CONFIG_KINDS + MANIFEST_KINDS
    redacted_code, secrets = scan_and_redact_secrets(code, rel_path, config=is_config)
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


CONFIG_SNIPPET_NAMES = {
    DOCKERFILE: "Dockerfile", COMPOSE: "docker-compose.yml", K8S: "manifest.yaml",
    REQUIREMENTS: "requirements.txt", PYPROJECT: "pyproject.toml", PACKAGE_JSON: "package.json",
}


def build_snippet_context(code: str, language: str) -> PipelineContext:
    if language == "config":
        kind = detect_from_content(code)
        if kind is None:
            raise PipelineError(422, "Unrecognised configuration. Paste a Dockerfile, docker-compose file, Kubernetes "
                                     "manifest, requirements.txt, pyproject.toml or package.json.")
        path, file_language = CONFIG_SNIPPET_NAMES[kind], kind
    else:
        path, file_language = f"snippet{SNIPPET_EXT.get(language, '')}", language.upper()

    workdir = tempfile.mkdtemp(prefix="appsec-snippet-")
    try:
        scan = scan_file(path, file_language, code, workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    ctx = PipelineContext()
    ctx.add(scan)
    _register_config(ctx, scan.ctx)
    _check_dependencies(ctx)
    ctx.engines = _engines(ctx, file_language)
    return ctx


def _register_config(ctx: PipelineContext, file_ctx: FileContext) -> None:
    if file_ctx.language in CONFIG_KINDS + MANIFEST_KINDS:
        ctx.config_files.append({"file": file_ctx.path, "kind": file_ctx.language})


def _check_dependencies(ctx: PipelineContext) -> None:
    """Parse every scanned manifest and run one batched OSV lookup."""
    deps = []
    for file_ctx in ctx.contexts.values():
        if file_ctx.language in MANIFEST_KINDS:
            deps.extend(parse_manifest(file_ctx.language, file_ctx.path, file_ctx.text) or [])
    if not any(c["kind"] in MANIFEST_KINDS for c in ctx.config_files):
        ctx.dependencies = {"status": "not_applicable", "source": "OSV.dev", "checked": 0, "vulnerable": 0,
                            "note": "No dependency manifests found."}
        return
    findings, status = osv.lookup(deps)
    if not deps:
        status = {**status, "note": "No pinned dependency versions found to check."}
    ctx.findings.extend(findings)
    ctx.dependencies = status


def _engines(ctx: PipelineContext, *languages: str) -> Set[str]:
    engines = {"secrets", "rules"}
    if "PYTHON" in languages:
        engines.add("bandit")
    if any(c["kind"] in CONFIG_KINDS for c in ctx.config_files):
        engines.add("config")
    if any(c["kind"] in MANIFEST_KINDS for c in ctx.config_files):
        engines.add("deps")
    return engines


def iter_source_files(root: str):
    """Yield (absolute path, relative path, language) in a stable order, skipping vendored dirs.

    Source files come first; config files and dependency manifests follow with their own cap.
    """
    configs = []
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            path = os.path.join(current, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            ext = os.path.splitext(name)[1].lower()
            if ext in LANGUAGE_BY_EXT:
                yield path, rel, LANGUAGE_BY_EXT[ext]
            elif ext in CONFIG_EXTS or name.lower().startswith("dockerfile"):
                configs.append((path, rel))
    for path, rel in configs:
        kind = detect_kind(rel, _read(path) or "")
        if kind:
            yield path, rel, kind


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
    counts = {"code": 0, "config": 0}
    limits = {"code": settings.max_repo_files, "config": settings.max_config_files}
    workdir = tempfile.mkdtemp(prefix="appsec-work-")
    try:
        for path, rel_path, language in iter_source_files(root):
            group = "config" if language in CONFIG_KINDS + MANIFEST_KINDS else "code"
            if counts[group] >= limits[group]:
                ctx.truncated = True
                continue
            code = _read(path)
            if code is None:
                continue

            scan = scan_file(rel_path, language, code, workdir)
            if len(ctx.text) + len(scan.block) > settings.max_context_chars:
                ctx.text += "\n--- [TRUNCATED] Maximum context limit reached ---\n"
                ctx.truncated = True
                break
            ctx.add(scan)
            _register_config(ctx, scan.ctx)
            languages.add(language)
            counts[group] += 1
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    _check_dependencies(ctx)
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
        raise PipelineError(422, "No supported source or configuration files found in the repository.")
    return ctx
