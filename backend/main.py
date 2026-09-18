from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openai import OpenAI
import os
from dotenv import load_dotenv
import json

load_dotenv()
API_KEY = os.getenv("OPENAI_API_KEY")

if not API_KEY:
    raise ValueError("OPENAI_API_KEY not found in .env file")

client = OpenAI(api_key=API_KEY)
MODEL_ID = "gpt-4o-mini"

app = FastAPI(title="AppSec Code Reviewer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class CodeRequest(BaseModel):
    code: str

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
async def analyze_code(request: CodeRequest):
    try:
        response = client.chat.completions.create(
            model=MODEL_ID,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": request.code}
            ],
            response_format={"type": "json_object"},
            temperature=0.0
        )
        
        result_text = response.choices[0].message.content
        parsed_json = json.loads(result_text)
        
        return parsed_json

    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="AI response formatting error")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def read_root():
    return {"status": "ok", "message": "AppSec API is running with OpenAI!"}