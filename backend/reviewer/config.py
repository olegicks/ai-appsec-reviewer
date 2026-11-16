import os
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _float_env(name: str) -> Optional[float]:
    raw = os.getenv(name, "").strip()
    try:
        return float(raw) if raw else None
    except ValueError:
        return None


def _origins() -> list:
    raw = os.getenv("FRONTEND_URL", "http://localhost:5173")
    return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]


@dataclass(frozen=True)
class Settings:
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    # No built-in default: model names get deprecated, so the deployment must choose one explicitly.
    model_id: str = field(default_factory=lambda: os.getenv("OPENAI_MODEL", "").strip())
    # Only sent when set - some newer models reject a custom temperature.
    temperature: Optional[float] = field(default_factory=lambda: _float_env("OPENAI_TEMPERATURE"))
    allowed_origins: list = field(default_factory=_origins)
    rate_limit: str = field(default_factory=lambda: os.getenv("RATE_LIMIT", "5/minute"))

    max_snippet_chars: int = 50_000
    max_repo_files: int = field(default_factory=lambda: _int_env("MAX_REPO_FILES", 20))
    max_file_bytes: int = field(default_factory=lambda: _int_env("MAX_FILE_BYTES", 30 * 1024))
    max_context_chars: int = field(default_factory=lambda: _int_env("MAX_CONTEXT_CHARS", 60_000))
    max_config_files: int = field(default_factory=lambda: _int_env("MAX_CONFIG_FILES", 10))
    clone_timeout: int = field(default_factory=lambda: _int_env("CLONE_TIMEOUT", 15))
    bandit_timeout: int = field(default_factory=lambda: _int_env("BANDIT_TIMEOUT", 10))


    # Dependency check (OSV.dev). Disabled automatically in tests; OSV_ENABLED=false turns it off.
    osv_enabled: bool = field(default_factory=lambda: os.getenv("OSV_ENABLED", "true").strip().lower() not in ("0", "false", "no"))
    osv_timeout: float = field(default_factory=lambda: float(_int_env("OSV_TIMEOUT", 8)))
    osv_budget: float = field(default_factory=lambda: float(_int_env("OSV_BUDGET", 15)))
    osv_max_packages: int = field(default_factory=lambda: _int_env("OSV_MAX_PACKAGES", 200))
    osv_max_vulns: int = field(default_factory=lambda: _int_env("OSV_MAX_VULNS", 30))


settings = Settings()
