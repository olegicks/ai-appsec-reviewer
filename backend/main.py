from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from openai import OpenAI
import os
from dotenv import load_dotenv
import json
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

load_dotenv()
API_KEY = os.getenv("OPENAI_API_KEY")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

if not API_KEY:
    raise ValueError("OPENAI_API_KEY is missing")

client = OpenAI(api_key=API_KEY)
MODEL_ID = "gpt-4o-mini"

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="AppSec Code Reviewer API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

class CodeRequest(BaseModel):
    code: str = Field(..., min_length=5, max_length=10000)

SYSTEM_PROMPT = """
You are a cybersecurity expert (AppSec). Analyze the provided code. Find vulnerabilities from the OWASP Top 10 or other critical security flaws.
Your response MUST be a valid JSON object.
The JSON structure must be exactly as follows:
{
  "vulnerabilities": [
    {
      "line_number": 12,
      "vulnerability_type": "Name of the vulnerability",
      "risk_explanation": "Short explanation of the risk for the developer",
      "secure_code_snippet": "Fixed code"
    }
  ]
}
If there are no vulnerabilities, return {"vulnerabilities": []}.
"""

@app.post("/analyze")
@limiter.limit("5/minute")
async def analyze_code(request: Request, payload: CodeRequest):
    try:
        response = client.chat.completions.create(
            model=MODEL_ID,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": payload.code}
            ],
            response_format={"type": "json_object"},
            temperature=0.0
        )
        
        result_text = response.choices[0].message.content
        parsed_json = json.loads(result_text)
        
        return parsed_json

    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="AI response formatting error")
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/")
@limiter.limit("10/minute")
def read_root(request: Request):
    return {"status": "ok", "message": "AppSec API is secured and running!"}