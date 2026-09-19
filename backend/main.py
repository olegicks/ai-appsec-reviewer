from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from openai import OpenAI
import os
from dotenv import load_dotenv
import json
import re
import tempfile
import subprocess
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
    language: str = Field(default="python")

SYSTEM_PROMPT = """
You are a senior AppSec engineer. Analyze the provided source code and the raw findings from the static scanners.
Verify the static findings, eliminate false positives, and identify logical vulnerabilities (OWASP Top 10).
Your response MUST be a valid JSON object strictly matching this structure:
{
  "vulnerabilities": [
    {
      "line_number": 12,
      "vulnerability_type": "Vulnerability Name",
      "risk_explanation": "Technical explanation of the risk",
      "secure_code_snippet": "Fixed and secure code block"
    }
  ]
}
If the code is fully secure, return {"vulnerabilities": []}.
"""

def scan_secrets(code: str) -> str:
    patterns = {
        "AWS Access Key": r"(?i)AKIA[0-9A-Z]{16}",
        "Hardcoded Credential": r"(?i)(password|secret|token|api_key|apikey)[=:\s]+[\"'][a-zA-Z0-9_\-\.]+[\"']",
        "Bearer Token": r"Bearer\s+[A-Za-z0-9\-\._~]+"
    }
    
    findings = []
    lines = code.splitlines()
    
    for line_num, line in enumerate(lines, 1):
        for secret_type, pattern in patterns.items():
            if re.search(pattern, line):
                findings.append(f"Line {line_num}: Possible {secret_type} detected.")
    
    return json.dumps(findings) if findings else "No secrets detected."

def run_bandit(code: str) -> str:
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py", mode='w', encoding='utf-8') as temp_file:
            temp_file.write(code)
            temp_path = temp_file.name

        result = subprocess.run(
            ['bandit', '-f', 'json', '-q', temp_path],
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            bandit_data = json.loads(result.stdout)
            findings = bandit_data.get("results", [])
            return json.dumps(findings) if findings else "No Bandit findings."
        return "No Bandit findings."
    except Exception:
        return "Bandit scan failed."
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

@app.post("/analyze")
@limiter.limit("5/minute")
async def analyze_code(request: Request, payload: CodeRequest):
    try:
        static_analysis = f"SECRETS SCANNER:\n{scan_secrets(payload.code)}\n"
        
        if payload.language.lower() == "python":
            static_analysis += f"BANDIT SAST:\n{run_bandit(payload.code)}\n"
            
        prompt_content = f"LANGUAGE: {payload.language}\nCODE:\n{payload.code}\n\nSTATIC SCANNER FINDINGS:\n{static_analysis}"
        
        response = client.chat.completions.create(
            model=MODEL_ID,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt_content}
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
    return {"status": "ok", "message": "Hybrid multi-language AppSec API is running"}