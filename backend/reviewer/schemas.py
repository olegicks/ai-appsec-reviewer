import re
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
CONFIDENCES = ("HIGH", "MEDIUM", "LOW")
SNIPPET_LANGUAGES = ("python", "javascript", "typescript", "java", "cpp", "go")

GITHUB_REPO_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(\.git)?/?$")


class AnalyzeRequest(BaseModel):
    mode: str = Field(pattern="^(snippet|repo)$")
    code: Optional[str] = Field(default="", max_length=50_000)
    language: str = Field(default="python", pattern=f"^({'|'.join(SNIPPET_LANGUAGES)})$")
    repo_url: Optional[str] = Field(default="")
    paranoia_level: str = Field(default="standard", pattern="^(standard|aggressive)$")

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v, info):
        if info.data.get("mode") == "repo":
            v = (v or "").strip()
            if not GITHUB_REPO_RE.match(v):
                raise ValueError("Only public https://github.com/owner/repo URLs are allowed")
        return v


class VulnerabilityFinding(BaseModel):
    file: str
    line: str
    vulnerability: str
    severity: str = Field(pattern=f"^({'|'.join(SEVERITIES)})$")
    confidence: str = Field(pattern=f"^({'|'.join(CONFIDENCES)})$")
    cwe: str
    owasp: str
    source: str
    risk_explanation: str
    secure_code_snippet: str

    @field_validator("severity", "confidence", mode="before")
    @classmethod
    def normalize_upper(cls, v):
        # LLMs frequently answer "High" or "medium" - normalise before strict pattern checks.
        return str(v).strip().upper() if v is not None else v

    @field_validator("line", mode="before")
    @classmethod
    def coerce_line(cls, v):
        if isinstance(v, int):
            return f"Line {v}"
        return str(v) if v is not None else "N/A"


class AIAnalysisResult(BaseModel):
    vulnerabilities: List[VulnerabilityFinding]


class ScanMeta(BaseModel):
    mode: str
    model: str
    paranoia_level: str
    files_scanned: int
    secrets_found: int
    sast_findings: int
    truncated: bool
    duration_ms: int


class AnalyzeResponse(BaseModel):
    vulnerabilities: List[VulnerabilityFinding]
    summary: Dict[str, int]
    meta: ScanMeta
