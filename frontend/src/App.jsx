import { useState } from 'react';
import Editor from '@monaco-editor/react';
import './App.css';

function App() {
  const [code, setCode] = useState('// Paste your code here or select a template...\n');
  const [vulnerabilities, setVulnerabilities] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const templates = {
    sqli: `username = request.form['user']\nquery = "SELECT * FROM users WHERE username = '" + username + "'"\ncursor.execute(query)`,
    hardcode: `def connect_to_db():\n    password = "super_secret_db_password_123"\n    db.connect(user="admin", password=password)`,
  };

  const handleAnalyze = async () => {
    setLoading(true);
    setError(null);
    setVulnerabilities(null);
    
    try {
      const response = await fetch('http://127.0.0.1:8000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      });
      
      if (!response.ok) throw new Error('Server error. Please check if the backend is running.');
      
      const data = await response.json();
      setVulnerabilities(data.vulnerabilities);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-container">
      <header className="header">
        <h1>🛡️ AI Secure Code Reviewer</h1>
        <p>Find vulnerabilities in your code using AI</p>
      </header>

      <div className="toolbar">
        <button onClick={() => setCode(templates.sqli)}>Example: SQL Injection</button>
        <button onClick={() => setCode(templates.hardcode)}>Example: Hardcoded Secret</button>
        <button className="scan-btn" onClick={handleAnalyze} disabled={loading}>
          {loading ? 'Analyzing...' : '🚀 Scan Code'}
        </button>
      </div>

      <div className="main-content">
        <div className="editor-section">
          <Editor
            height="60vh"
            defaultLanguage="python"
            theme="vs-dark"
            value={code}
            onChange={(value) => setCode(value)}
            options={{ minimap: { enabled: false }, fontSize: 14 }}
          />
        </div>

        <div className="results-section">
          <h2>Analysis Results:</h2>
          
          {loading && <div className="loader">AI is analyzing the code... 🤖</div>}
          {error && <div className="error">❌ {error}</div>}
          
          {!loading && vulnerabilities?.length === 0 && (
            <div className="success">✅ No vulnerabilities found! The code is secure.</div>
          )}

          {!loading && vulnerabilities?.map((vuln, index) => (
            <div key={index} className="vuln-card">
              <h3>🚨 {vuln.vulnerability_type} (Line: {vuln.line_number})</h3>
              <p><strong>Risk:</strong> {vuln.risk_explanation}</p>
              <div className="fix-block">
                <strong>How to fix:</strong>
                <pre>{vuln.secure_code_snippet}</pre>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default App;