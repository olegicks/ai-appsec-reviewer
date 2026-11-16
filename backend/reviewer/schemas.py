import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
CONFIDENCES = ("HIGH", "MEDIUM", "LOW")
SNIPPET_LANGUAGES = ("python", "javascript", "typescript", "java", "cpp", "go", "config")

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


class AIReview(BaseModel):
    """The model's verdict on one deterministic finding, referenced by its fingerprint."""

    id: str = Field(max_length=64)
    verdict: str = Field(pattern="^(confirmed|false_positive)$")
    reason: str = Field(default="", max_length=1000)

    @field_validator("verdict", mode="before")
    @classmethod
    def normalize_verdict(cls, v):
        return str(v).strip().lower().replace(" ", "_").replace("-", "_") if v is not None else v


class AIAnalysisResult(BaseModel):
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list)
    reviews: List[AIReview] = Field(default_factory=list)


class RiskOut(BaseModel):
    id: str = ""
    likelihood: int
    impact: int
    score: int
    band: str
    factors: List[str] = Field(default_factory=list)


class FindingOut(VulnerabilityFinding):
    """v1 fields above stay unchanged; everything below is additive (v2)."""

    id: str = ""
    rule_id: str = ""
    title: str = ""
    category: str = ""
    pack: str = ""
    engine: str = ""
    engines: List[str] = Field(default_factory=list)
    stride: List[str] = Field(default_factory=list)
    line_number: int = 0
    excerpt: str = ""
    references: List[str] = Field(default_factory=list)
    ai_verdict: str = "not_reviewed"
    ai_note: str = ""
    risk: Optional[RiskOut] = None
    compliance: Dict[str, List[str]] = Field(default_factory=dict)
    dependency: Optional[Dict[str, Any]] = None


class ScanMeta(BaseModel):
    mode: str
    model: str
    paranoia_level: str
    files_scanned: int
    secrets_found: int
    sast_findings: int
    truncated: bool
    duration_ms: int
    # v2 (additive)
    engines: List[str] = Field(default_factory=list)
    ai_status: str = "used"  # used | not_configured
    rule_findings: int = 0
    config_files: List[Dict[str, str]] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    vulnerabilities: List[FindingOut]
    summary: Dict[str, int]
    meta: ScanMeta
    # v2 (additive)
    risk_matrix: Dict[str, Any] = Field(default_factory=dict)
    top_risks: List[str] = Field(default_factory=list)
    stride_summary: Dict[str, int] = Field(default_factory=dict)
    compliance_summary: Dict[str, Any] = Field(default_factory=dict)
    dependencies: Dict[str, Any] = Field(default_factory=dict)
