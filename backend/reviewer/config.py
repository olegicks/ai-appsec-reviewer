import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _origins() -> list:
    raw = os.getenv("FRONTEND_URL", "http://localhost:5173")
    return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]


@dataclass(frozen=True)
class Settings:
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    model_id: str = field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
    allowed_origins: list = field(default_factory=_origins)
    rate_limit: str = field(default_factory=lambda: os.getenv("RATE_LIMIT", "5/minute"))

    max_snippet_chars: int = 50_000
    max_repo_files: int = field(default_factory=lambda: _int_env("MAX_REPO_FILES", 20))
    max_file_bytes: int = field(default_factory=lambda: _int_env("MAX_FILE_BYTES", 30 * 1024))
    max_context_chars: int = field(default_factory=lambda: _int_env("MAX_CONTEXT_CHARS", 60_000))
    clone_timeout: int = field(default_factory=lambda: _int_env("CLONE_TIMEOUT", 15))
    bandit_timeout: int = field(default_factory=lambda: _int_env("BANDIT_TIMEOUT", 10))


settings = Settings()
