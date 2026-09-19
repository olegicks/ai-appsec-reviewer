import { useState } from 'react';
import Editor from '@monaco-editor/react';
import './App.css';

function App() {
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('python');
  const [vulnerabilities, setVulnerabilities] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const templates = {
    python_sqli: `username = request.form['user']\nquery = "SELECT * FROM users WHERE username = '" + username + "'"\ncursor.execute(query)`,
    javascript_xss: `const userInput = new URLSearchParams(window.location.search).get('name');\ndocument.getElementById('greeting').innerHTML = "Hello, " + userInput;`,
  };

  const loadTemplate = (type) => {
    if (type === 'python') {
      setLanguage('python');
      setCode(templates.python_sqli);
    } else {
      setLanguage('javascript');
      setCode(templates.javascript_xss);
    }
  };

  const handleAnalyze = async () => {
    setLoading(true);
    setError(null);
    setVulnerabilities(null);
    
    try {
      const response = await fetch('https://ai-appsec-reviewer.onrender.com/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, language })
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
        <p>Find vulnerabilities in your code using AI & SAST</p>
      </header>

      <div className="toolbar">
        <select value={language} onChange={(e) => setLanguage(e.target.value)} className="lang-select">
          <option value="python">Python</option>
          <option value="javascript">JavaScript</option>
          <option value="java">Java</option>
          <option value="cpp">C++</option>
        </select>
        
        <button onClick={() => loadTemplate('python')}>Example: Python SQLi</button>
        <button onClick={() => loadTemplate('javascript')}>Example: JS XSS</button>
        <button className="scan-btn" onClick={handleAnalyze} disabled={loading}>
          {loading ? 'Analyzing...' : '🚀 Scan Code'}
        </button>
      </div>

      <div className="main-content">
        <div className="editor-section">
          <Editor
            height="60vh"
            language={language}
            theme="vs-dark"
            value={code}
            onChange={(value) => setCode(value)}
            options={{ minimap: { enabled: false }, fontSize: 14 }}
          />
        </div>

        <div className="results-section">
          <h2>Analysis Results:</h2>
          
          {loading && <div className="loader">Analyzing code via AI & SAST... 🤖</div>}
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