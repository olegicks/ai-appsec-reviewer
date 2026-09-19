# AI AppSec Code Reviewer

A hybrid Application Security (AppSec) pipeline combining Static Application Security Testing (SAST) with AI-driven analysis to detect vulnerabilities in source code and GitHub repositories.

**Live Demo:** https://ai-appsec-reviewer-7qgg.vercel.app/  
**Backend API:** https://ai-appsec-reviewer.onrender.com/  
> Note: The backend is hosted on Render Free Tier and may take a few seconds to wake up after inactivity.

## Platforms & Cloud Infrastructure
* **Frontend Hosting:** Vercel
* **Backend Hosting:** Render (Free Tier)
* **AI Analysis:** OpenAI API (gpt-4o-mini)
* **Source Control Integration:** GitHub public repositories (via shallow Git clone)

## Project Structure
```text
ai-appsec-reviewer/
├── backend/
│   ├── main.py              # FastAPI application and pipeline logic
│   ├── requirements.txt     # Python dependencies
│   └── .env                 # Environment variables (OpenAI Key, CORS config)
├── frontend/
│   ├── src/
│   │   ├── App.jsx          # Main React application logic
│   │   ├── App.css          # Dark UI theme styles
│   │   └── main.jsx         # React entry point
│   ├── index.html           # HTML template with SVG favicon
│   └── package.json         # Node.js dependencies
└── README.md                # Project documentation
```

## Features
* Code snippet security analysis
* GitHub repository scanning
* Python SAST with Bandit
* AI-powered analysis for multiple languages
* Hardcoded secret detection and redaction
* Standard and aggressive analysis modes
* CWE and OWASP classification
* Severity and confidence assessment
* HTML security report export
* API rate limiting

## The Pipeline Architecture
1. **Input Validation:** Strict Pydantic schemas enforce URL structures, payload sizes, and supported languages.
2. **Safe Discovery:** Clones GitHub repositories into isolated temporary directories with strict resource limits (max files, max sizes, timeouts).
3. **Secret Scanner & Redaction:** Detects hardcoded credentials such as AWS keys, API keys, passwords, and Bearer tokens. Detected secrets are redacted as `[REDACTED]` before being sent to the LLM.
4. **Language-Aware SAST:** Dynamically routes Python files to **Bandit** for static analysis.
5. **Context Preparation:** Collects source code, static analysis findings, and secret scanner results while enforcing context size limits.
6. **AI Analysis:** OpenAI acts as a reviewer, analyzing the source code alongside SAST findings to identify complex logical flaws.
7. **Prompt Injection Protection:** The system prompt explicitly isolates user source code as untrusted data, preventing attackers from instructing the LLM to ignore vulnerabilities.
8. **Structured Output:** Validates AI responses against a Pydantic schema containing severity, confidence, CWE, OWASP category, source, and remediation.

## Tech Stack
* **Backend:** Python, FastAPI, Pydantic, Bandit, SlowAPI
* **Frontend:** React, Vite, Monaco Editor
* **AI:** OpenAI GPT-4o-mini

## Local Setup

**1. Clone the repository**
```bash
git clone https://github.com/yourusername/ai-appsec-reviewer.git
cd ai-appsec-reviewer
```

**2. Backend Setup**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```
Create a `.env` file in the `/backend` directory:
```env
OPENAI_API_KEY=your_openai_api_key_here
FRONTEND_URL=http://localhost:5173
```
Start the server:
```bash
uvicorn main:app --reload
```

**3. Frontend Setup**
```bash
cd ../frontend
npm install
npm run dev
```