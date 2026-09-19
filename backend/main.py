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
import shutil
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
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    code: str = Field(default="")
    language: str = Field(default="python")
    repo_url: str = Field(default="")
    paranoia_level: str = Field(default="standard")

def get_system_prompt(paranoia: str) -> str:
    base_prompt = (
        "You are a senior AppSec engineer. Analyze the provided code and static scanner findings. "
        "Your primary task is to VALIDATE findings and strictly ELIMINATE false positives. "
    )
    if paranoia == "aggressive":
        base_prompt += (
            "Report all potential risks, including low-severity warnings, best-practice violations "
            "(e.g., safe subprocess calls), and informational findings. "
        )
    else:
        base_prompt += (
            "Report ONLY definitively exploitable vulnerabilities (e.g., Command Injection with user-controlled input). "
            "You MUST ignore and filter out unexploitable warnings (e.g., subprocess calls with hardcoded strings and shell=False). "
        )
        
    base_prompt += (
        "For the 'line_number' field, NEVER output temporary system paths like /tmp/. "
        "Format it cleanly as 'Line X' for snippets, or 'filename:X' for repositories.\n"
        "Your response MUST be a valid JSON object strictly matching this structure:\n"
        "{\n  \"vulnerabilities\": [\n    {\n      \"line_number\": \"Clean location\",\n"
        "      \"vulnerability_type\": \"Vulnerability Name (Severity)\",\n      \"risk_explanation\": \"Technical explanation\",\n"
        "      \"secure_code_snippet\": \"Fixed code block\"\n    }\n  ]\n}\n"
        "If the code is fully secure, return {\"vulnerabilities\": []}."
    )
    return base_prompt

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
            
        result = subprocess.run(['bandit', '-f', 'json', '-q', temp_path], capture_output=True, text=True)
        
        if result.stdout:
            bandit_data = json.loads(result.stdout)
            findings = bandit_data.get("results", [])
            
            for finding in findings:
                if "filename" in finding:
                    finding["filename"] = "Snippet"
                    
            return json.dumps(findings) if findings else "No Bandit findings."
        return "No Bandit findings."
    except Exception:
        return "Bandit scan failed."
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

def clone_and_read_repo(repo_url: str) -> str:
    temp_dir = tempfile.mkdtemp()
    combined_code = ""
    try:
        subprocess.run(["git", "clone", "--depth", "1", repo_url, temp_dir], check=True, capture_output=True)
        for root, dirs, files in os.walk(temp_dir):
            if '.git' in dirs:
                dirs.remove('.git')
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.java', '.cpp', '.c', '.go')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            combined_code += f"\n--- FILE: {file} ---\n{content}\n"
                            if len(combined_code) > 50000:
                                return combined_code
                    except Exception:
                        continue
        return combined_code if combined_code else "No supported source files found."
    except Exception:
        return "Failed to clone repository. Check URL and visibility."
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.post("/analyze")
@limiter.limit("5/minute")
async def analyze_code(request: Request, payload: AnalyzeRequest):
    try:
        target_code = ""
        if payload.repo_url:
            target_code = clone_and_read_repo(payload.repo_url)
        else:
            target_code = payload.code

        if not target_code:
            raise HTTPException(status_code=400, detail="No code or valid repository provided.")

        static_analysis = f"SECRETS SCANNER:\n{scan_secrets(target_code)}\n"
        if payload.language.lower() == "python" and not payload.repo_url:
            static_analysis += f"BANDIT SAST:\n{run_bandit(target_code)}\n"
            
        prompt_content = f"TARGET CODE/REPO:\n{target_code}\n\nSTATIC SCANNER FINDINGS:\n{static_analysis}"
        system_prompt = get_system_prompt(payload.paranoia_level)

        response = client.chat.completions.create(
            model=MODEL_ID,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_content}
            ],
            response_format={"type": "json_object"},
            temperature=0.0
        )
        
        result_text = response.choices[0].message.content
        return json.loads(result_text)

    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="AI response formatting error")
    except HTTPException as he:
        raise he
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/")
def read_root():
    return {"status": "ok"}