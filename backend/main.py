import logging
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from reviewer.config import settings
from reviewer.llm import LLMError, run_ai_analysis
from reviewer.pipeline import PipelineError, build_repository_context, build_snippet_context
from reviewer.analysis import build_findings, build_response
from reviewer.schemas import AnalyzeRequest, AnalyzeResponse

__version__ = "2.0.0"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("appsec")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="AppSec Code Reviewer API",
    version=__version__,
    description="Hybrid SAST + AI security review pipeline for code snippets and public GitHub repositories.",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.exception_handler(PipelineError)
@app.exception_handler(LLMError)
async def pipeline_error_handler(_request: Request, exc):
    content = {"detail": exc.detail}
    if getattr(exc, "code", None):
        content["code"] = exc.code
    return JSONResponse(status_code=exc.status_code, content=content)


# A plain `def` endpoint runs in FastAPI's threadpool, so the blocking git/bandit/OpenAI
# calls below no longer stall the event loop for other requests.
@app.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit(settings.rate_limit)
def analyze_code(request: Request, payload: AnalyzeRequest):
    started = time.perf_counter()

    if payload.mode == "repo":
        ctx = build_repository_context(payload.repo_url)
    else:
        if not payload.code or len(payload.code.strip()) < 5:
            raise HTTPException(status_code=400, detail="Code snippet is empty or too short.")
        ctx = build_snippet_context(payload.code, payload.language)

    # Without a configured AI engine the deterministic engines still produce a full result.
    ai_ready = bool(settings.openai_api_key and settings.model_id)
    ai_result = run_ai_analysis(ctx.text, payload.paranoia_level) if ai_ready else None
    findings = build_findings(ctx, ai_result, payload.paranoia_level)
    duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info("scan mode=%s files=%d findings=%d ai=%s %dms", payload.mode, ctx.files_scanned,
                len(findings), ai_ready, duration_ms)

    return build_response(
        ctx,
        findings,
        mode=payload.mode,
        paranoia=payload.paranoia_level,
        model=settings.model_id,
        ai_status="used" if ai_ready else "not_configured",
        duration_ms=duration_ms,
    )


@app.get("/")
def read_root():
    return {"status": "ok", "service": "AppSec Code Reviewer API", "version": __version__}


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": __version__,
        "ai_configured": bool(settings.openai_api_key and settings.model_id),
        "model": settings.model_id or None,
    }
