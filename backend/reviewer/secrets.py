"""Lightweight secret scanner that also redacts what it finds before code ever reaches the LLM."""
import re
from dataclasses import asdict, dataclass
from typing import List, Tuple

REDACTED = "[REDACTED]"

# Every pattern exposes the sensitive value as the named group "secret".
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"(?P<secret>\b(?:AKIA|ASIA)[0-9A-Z]{16}\b)"),
    "GitHub Token": re.compile(r"(?P<secret>\bgh[pousr]_[A-Za-z0-9]{36,})"),
    "OpenAI API Key": re.compile(r"(?P<secret>\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,})"),
    "Google API Key": re.compile(r"(?P<secret>\bAIza[0-9A-Za-z_\-]{35})"),
    "Slack Token": re.compile(r"(?P<secret>\bxox[abprs]-[A-Za-z0-9-]{10,})"),
    "JSON Web Token": re.compile(r"(?P<secret>\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
    "Bearer Token": re.compile(r"(?i)\bBearer\s+(?P<secret>[A-Za-z0-9\-._~+/]{10,}=*)"),
    "Hardcoded Credential": re.compile(
        r"(?i)\b[\w.-]*(?:passw(?:or)?d|pass|pwd|secret|token|api[_-]?key|auth[_-]?key|credential)s?[\w-]*\b[\"']?"
        r"\s*[:=]\s*[\"'](?P<secret>[^\"'\s]{6,})[\"']"
    ),
}

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)


@dataclass
class SecretFinding:
    file: str
    line: int
    type: str

    def __str__(self) -> str:
        return f"[{self.file}] Line {self.line}: {self.type} detected."


def scan_and_redact_secrets(code: str, filename: str) -> Tuple[str, List[SecretFinding]]:
    """Return the code with every detected secret replaced by [REDACTED] plus the list of findings."""
    findings: List[SecretFinding] = []

    def _redact_key(match: re.Match) -> str:
        line = code.count("\n", 0, match.start()) + 1
        findings.append(SecretFinding(filename, line, "Private Key"))
        return "-----BEGIN PRIVATE KEY-----" + REDACTED + "-----END PRIVATE KEY-----"

    code = PRIVATE_KEY_RE.sub(_redact_key, code)

    redacted_lines = []
    for line_num, line in enumerate(code.split("\n"), 1):
        seen_spans = []
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(line):
                span = match.span("secret")
                if any(span[0] < s[1] and s[0] < span[1] for s in seen_spans):
                    continue
                seen_spans.append(span)
                findings.append(SecretFinding(filename, line_num, secret_type))
        # Replace right-to-left so earlier offsets stay valid.
        for start, end in sorted(seen_spans, reverse=True):
            line = line[:start] + REDACTED + line[end:]
        redacted_lines.append(line)

    findings.sort(key=lambda f: f.line)
    return "\n".join(redacted_lines), findings


def format_secret_findings(findings: List[SecretFinding]) -> str:
    if not findings:
        return "No secrets detected."
    return "; ".join(str(f) for f in findings)


def findings_as_dicts(findings: List[SecretFinding]) -> list:
    return [asdict(f) for f in findings]
