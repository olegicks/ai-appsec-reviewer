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

  const handleAnalyze = async () => {
    setLoading(true);
    setError(null);
    setVulnerabilities(null);
    
    try {
      const response = await fetch('https://ai-appsec-reviewer.onrender.com/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          code: mode === 'snippet' ? code : '',
          language,
          repo_url: mode === 'repo' ? repoUrl : '',
          paranoia_level: paranoia
        })
      });
      
      if (!response.ok) throw new Error('Server error. Please verify backend status.');
      
      const data = await response.json();
      setVulnerabilities(data.vulnerabilities);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const exportReport = () => {
    if (!vulnerabilities) return;
    const htmlContent = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Security Audit Report</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; padding: 40px; color: #24292e; background: #f6f8fa; }
          h1 { color: #24292e; border-bottom: 1px solid #eaecef; padding-bottom: 10px; }
          .vuln { background: #ffffff; border: 1px solid #e1e4e8; border-left: 4px solid #d73a49; border-radius: 6px; padding: 20px; margin-bottom: 20px; }
          .vuln h3 { margin-top: 0; color: #d73a49; }
          pre { background: #f6f8fa; padding: 16px; border-radius: 6px; overflow-x: auto; color: #24292e; font-size: 14px; }
        </style>
      </head>
      <body>
        <h1>AppSec Security Audit Report</h1>
        <p><strong>Scan Type:</strong> ${mode === 'repo' ? 'Repository Scan' : 'Code Snippet Scan'}</p>
        <p><strong>Paranoia Level:</strong> ${paranoia}</p>
        <p><strong>Date:</strong> ${new Date().toLocaleString()}</p>
        <hr>
        ${vulnerabilities.length === 0 ? '<p>No vulnerabilities detected.</p>' : ''}
        ${vulnerabilities.map(v => `
          <div class="vuln">
            <h3>${v.vulnerability_type} (Location:${v.line_number})</h3>
            <p><strong>Risk Explanation:</strong> ${v.risk_explanation}</p>
            <p><strong>Remediation:</strong></p>
            <pre>${v.secure_code_snippet}</pre>
          </div>
        `).join('')}
      </body>
      </html>
    `;
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'appsec_audit_report.html';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="app-container">
      <header className="header">
        <h1>AppSec Code Reviewer</h1>
        <p>Enterprise-grade SAST and AI hybrid analysis</p>
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
            <option value="standard">Standard (Critical Risks)</option>
            <option value="aggressive">Aggressive (All Warnings)</option>
          </select>
        </div>

        <button className="btn primary" onClick={handleAnalyze} disabled={loading}>
          {loading ? 'Processing...' : 'Run Analysis'}
        </button>
      </div>

      <div className="main-content">
        <div className="input-section">
          {mode === 'repo' ? (
            <div className="repo-input-container">
              <h3>Target Repository</h3>
              <input 
                type="text" 
                placeholder="https://github.com/username/repo" 
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                className="repo-input"
              />
              <p className="helper-text">Only public repositories are supported. Scans primary branch source files.</p>
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
            {vulnerabilities && (
              <button className="btn secondary" onClick={exportReport}>Export HTML Report</button>
            )}
          </div>
          
          <div className="results-body">
            {loading && <div className="status-message">Initializing security analysis...</div>}
            {error && <div className="status-message error">{error}</div>}
            
            {!loading && vulnerabilities?.length === 0 && (
              <div className="status-message success">Zero vulnerabilities detected. Code passes standard baseline.</div>
            )}

            {!loading && vulnerabilities?.map((vuln, index) => (
              <div key={index} className="vuln-card">
                <div className="vuln-card-header">
                  <h3>{vuln.vulnerability_type}</h3>
                  <span className="badge">Location: {vuln.line_number}</span>
                </div>
                <div className="vuln-card-body">
                  <p className="risk-text">{vuln.risk_explanation}</p>
                  <div className="code-block">
                    <span className="code-label">Remediation</span>
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