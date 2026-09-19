import { useState } from 'react';
import Editor from '@monaco-editor/react';
import './App.css';

function App() {
  const [mode, setMode] = useState('snippet');
  const [code, setCode] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [language, setLanguage] = useState('python');
  const [paranoia, setParanoia] = useState('standard');
  const [vulnerabilities, setVulnerabilities] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const templates = {
    python_sqli: `import sqlite3\n\ndef get_user(username):\n    conn = sqlite3.connect('db.sqlite')\n    cursor = conn.cursor()\n    # SQL Injection Vulnerability\n    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")\n    return cursor.fetchall()`,
    javascript_xss: `const userInput = new URLSearchParams(window.location.search).get('name');\ndocument.getElementById('greeting').innerHTML = "Hello, " + userInput;`,
    java_secret: `public class Config {\n    // Dummy config\n    private static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n    private static final String DB_PASS = "super_secret_db_123";\n}`,
    cpp_buffer: `void copyData(char *input) {\n    char buffer[10];\n    // buffer overflow risk\n    strcpy(buffer, input);\n}`
  };

  const loadTemplate = (type) => {
    setMode('snippet');
    if (type === 'python') { setLanguage('python'); setCode(templates.python_sqli); }
    else if (type === 'javascript') { setLanguage('javascript'); setCode(templates.javascript_xss); }
    else if (type === 'java') { setLanguage('java'); setCode(templates.java_secret); }
    else if (type === 'cpp') { setLanguage('cpp'); setCode(templates.cpp_buffer); }
  };

  const handleAnalyze = async () => {
    setLoading(true);
    setError(null);
    setVulnerabilities(null);
    
    try {
      const response = await fetch('https://ai-appsec-reviewer.onrender.com/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode, code, language, repo_url: repoUrl, paranoia_level: paranoia })
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.detail || `HTTP Error ${response.status}`);
      }
      
      const data = await response.json();
      setVulnerabilities(data.vulnerabilities);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityClass = (sev) => {
    const s = sev.toLowerCase();
    if (s === 'critical' || s === 'high') return 'sev-high';
    if (s === 'medium') return 'sev-med';
    return 'sev-low';
  };

  return (
    <div className="app-container">
      <header className="header">
        <h1>🛡️ AppSec Code Reviewer</h1>
        <p>Advanced SAST and AI hybrid analysis pipeline</p>
      </header>

      <div className="controls-panel">
        <div className="config-group">
          <label>Mode:</label>
          <select value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="snippet">Code Snippet</option>
            <option value="repo">GitHub Repository</option>
          </select>
        </div>
        
        {mode === 'snippet' && (
          <div className="config-group">
            <label>Language:</label>
            <select value={language} onChange={(e) => setLanguage(e.target.value)}>
              <option value="python">Python</option>
              <option value="javascript">JavaScript</option>
              <option value="java">Java</option>
              <option value="cpp">C++</option>
            </select>
          </div>
        )}

        <div className="config-group">
          <label>Paranoia Level:</label>
          <select value={paranoia} onChange={(e) => setParanoia(e.target.value)}>
            <option value="standard">Standard (Exploitable only)</option>
            <option value="aggressive">Aggressive (All Warnings)</option>
          </select>
        </div>

        <button className="btn primary" onClick={handleAnalyze} disabled={loading}>
          {loading ? 'Processing...' : 'Run Analysis'}
        </button>
      </div>

      {mode === 'snippet' && (
        <div className="example-buttons">
          <button className="btn secondary outline" onClick={() => loadTemplate('python')}>SQLi (Py)</button>
          <button className="btn secondary outline" onClick={() => loadTemplate('javascript')}>XSS (JS)</button>
          <button className="btn secondary outline" onClick={() => loadTemplate('java')}>Secrets (Java)</button>
          <button className="btn secondary outline" onClick={() => loadTemplate('cpp')}>Buffer (C++)</button>
        </div>
      )}

      <div className="main-content">
        <div className="input-section">
          {mode === 'repo' ? (
            <div className="repo-input-container">
              <h3>Target Repository</h3>
              <input 
                type="text" 
                placeholder="https://github.com/owner/repo" 
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                className="repo-input"
              />
              <p className="helper-text">Only public GitHub repositories. Limited to 20 files (max 30KB each).</p>
            </div>
          ) : (
            <Editor
              height="100%"
              language={language}
              theme="vs-dark"
              value={code}
              onChange={(value) => setCode(value)}
              options={{ minimap: { enabled: false }, fontSize: 14, padding: { top: 16 } }}
            />
          )}
        </div>

        <div className="results-section">
          <div className="results-header">
            <h2>Audit Findings</h2>
          </div>
          
          <div className="results-body">
            {loading && <div className="status-message">Executing hybrid pipeline...</div>}
            {error && <div className="status-message error">❌ {error}</div>}
            
            {!loading && vulnerabilities?.length === 0 && (
              <div className="status-message success">✅ Zero vulnerabilities detected. Code passes security baseline.</div>
            )}

            {!loading && vulnerabilities?.map((vuln, index) => (
              <div key={index} className="vuln-card">
                <div className="vuln-card-header">
                  <div className="vuln-title">
                    <span className={`severity-badge ${getSeverityClass(vuln.severity)}`}>{vuln.severity}</span>
                    <h3>{vuln.vulnerability}</h3>
                  </div>
                  <span className="badge-file">{vuln.file} : {vuln.line}</span>
                </div>
                <div className="vuln-card-meta">
                  <span><strong>CWE:</strong> {vuln.cwe}</span>
                  <span><strong>OWASP:</strong> {vuln.owasp}</span>
                  <span><strong>Confidence:</strong> {vuln.confidence}</span>
                  <span><strong>Source:</strong> {vuln.source}</span>
                </div>
                <div className="vuln-card-body">
                  <p className="risk-text">{vuln.risk_explanation}</p>
                  <div className="code-block">
                    <span className="code-label">Remediation Snippet</span>
                    <pre>{vuln.secure_code_snippet}</pre>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;