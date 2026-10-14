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
from reviewer.schemas import SEVERITIES, AnalyzeRequest, AnalyzeResponse, ScanMeta

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
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


def summarize(vulnerabilities) -> dict:
    summary = {s: 0 for s in SEVERITIES}
    for v in vulnerabilities:
        summary[v.severity] = summary.get(v.severity, 0) + 1
    summary["TOTAL"] = len(vulnerabilities)
    return summary


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

    result = run_ai_analysis(ctx.text, payload.paranoia_level)
    duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info("scan mode=%s files=%d findings=%d %dms", payload.mode, ctx.files_scanned,
                len(result.vulnerabilities), duration_ms)

    return AnalyzeResponse(
        vulnerabilities=result.vulnerabilities,
        summary=summarize(result.vulnerabilities),
        meta=ScanMeta(
            mode=payload.mode,
            model=settings.model_id,
            paranoia_level=payload.paranoia_level,
            files_scanned=ctx.files_scanned,
            secrets_found=ctx.secrets_found,
            sast_findings=ctx.sast_findings,
            truncated=ctx.truncated,
            duration_ms=duration_ms,
        ),
    )


@app.get("/")
def read_root():
    return {"status": "ok", "service": "AppSec Code Reviewer API", "version": __version__}


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": __version__,
        "ai_configured": bool(settings.openai_api_key),
        "model": settings.model_id,
    }
