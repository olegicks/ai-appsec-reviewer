"""Bandit integration for Python files."""
import json
import logging
import subprocess
import sys
from typing import List, Tuple

from .config import settings

logger = logging.getLogger(__name__)


def run_bandit_on_file(filepath: str, rel_path: str) -> Tuple[str, List[dict]]:
    """Run Bandit on a single file and return (context string for the LLM, raw findings).

    Absolute temp paths are replaced with the repository-relative path so they never leak
    into the prompt or the API response.
    """
    try:
        # Invoke through the current interpreter so the venv's bandit is used even when it is not on PATH.
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-f", "json", "-q", filepath],
            capture_output=True,
            text=True,
            timeout=settings.bandit_timeout,
        )
    except subprocess.TimeoutExpired:
        return "Bandit scan timed out.", []
    except OSError:
        logger.exception("Bandit could not be started")
        return "Bandit scan failed.", []

    if not result.stdout:
        return "No Bandit findings.", []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return "Bandit scan failed.", []

    findings = []
    for f in data.get("results", []):
        findings.append({
            "filename": rel_path,
            "line_number": f.get("line_number"),
            "test_id": f.get("test_id"),
            "issue_text": f.get("issue_text"),
            "issue_severity": f.get("issue_severity"),
            "issue_confidence": f.get("issue_confidence"),
            "cwe": (f.get("issue_cwe") or {}).get("id"),
        })

    if not findings:
        return "No Bandit findings.", []
    return json.dumps(findings), findings
