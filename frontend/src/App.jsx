import { useCallback, useEffect, useRef, useState } from 'react';
import Editor from '@monaco-editor/react';
import Header from './components/Header';
import RepoPanel from './components/RepoPanel';
import ResultsPanel from './components/ResultsPanel';
import Toolbar from './components/Toolbar';
import { EXAMPLES, LANGUAGES } from './data/examples';
import { analyze, checkHealth } from './lib/api';
import { buildHtmlReport, downloadFile } from './lib/report';
import './App.css';

function defineEditorTheme(monaco) {
  monaco.editor.defineTheme('appsec-dark', {
    base: 'vs-dark',
    inherit: true,
    rules: [{ token: 'comment', foreground: '64748b', fontStyle: 'italic' }],
    colors: {
      'editor.background': '#0a1120',
      'editor.lineHighlightBackground': '#111c33',
      'editorLineNumber.foreground': '#334155',
      'editorLineNumber.activeForeground': '#94a3b8',
      'editor.selectionBackground': '#1e3a5f',
      'editorCursor.foreground': '#38bdf8',
    },
  });
}

// Render's free tier sleeps when idle: ping it silently on load so it is warm by the first scan.
function useWarmUpApi() {
  useEffect(() => {
    const controller = new AbortController();
    checkHealth({ signal: controller.signal }).catch(() => {});
    return () => controller.abort();
  }, []);
}

function App() {
  const [mode, setMode] = useState('snippet');
  const [code, setCode] = useState(EXAMPLES[0].code);
  const [repoUrl, setRepoUrl] = useState('');
  const [language, setLanguage] = useState(EXAMPLES[0].language);
  const [paranoia, setParanoia] = useState('standard');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [runId, setRunId] = useState(0);
  const controllerRef = useRef(null);
  useWarmUpApi();

  const target = mode === 'repo' ? repoUrl : `snippet.${LANGUAGES.find((l) => l.value === language)?.ext}`;

  const runAnalysis = useCallback(async () => {
    if (controllerRef.current) return;
    if (mode === 'snippet' && code.trim().length < 5) {
      setError('Paste at least a few lines of code to analyze.');
      return;
    }
    if (mode === 'repo' && !repoUrl.trim()) {
      setError('Enter a public GitHub repository URL.');
      return;
    }

    const controller = new AbortController();
    controllerRef.current = controller;
    setLoading(true);
    setError(null);
    setResult(null);
    setRunId((id) => id + 1);

    try {
      const data = await analyze(
        { mode, code, language, repo_url: repoUrl.trim(), paranoia_level: paranoia },
        { signal: controller.signal },
      );
      setResult(data);
    } catch (err) {
      if (err.name !== 'AbortError') setError(err.message);
    } finally {
      controllerRef.current = null;
      setLoading(false);
    }
  }, [mode, code, language, repoUrl, paranoia]);

  const cancelAnalysis = () => controllerRef.current?.abort();

  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        runAnalysis();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [runAnalysis]);

  const loadExample = (example) => {
    setMode('snippet');
    setLanguage(example.language);
    setCode(example.code);
    setResult(null);
    setError(null);
  };

  const exportReport = (format) => {
    if (!result) return;
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    if (format === 'json') {
      downloadFile(`security-report-${stamp}.json`, JSON.stringify({ target, ...result }, null, 2), 'application/json');
    } else {
      const html = buildHtmlReport({ findings: result.vulnerabilities, target, meta: result.meta });
      downloadFile(`security-report-${stamp}.html`, html, 'text/html');
    }
  };

  return (
    <div className="app">
      <div className="bg-grid" aria-hidden="true" />
      <div className="bg-glow" aria-hidden="true" />

      <Header />

      <Toolbar
        mode={mode}
        onModeChange={setMode}
        language={language}
        onLanguageChange={setLanguage}
        paranoia={paranoia}
        onParanoiaChange={setParanoia}
        onExample={loadExample}
        loading={loading}
        onRun={runAnalysis}
        onCancel={cancelAnalysis}
      />

      <main className="workspace">
        <section className={`panel editor-panel ${loading ? 'scanning' : ''}`} aria-label="Scan target">
          <div className="panel-head">
            <div className="tab">
              <span className={`lang-dot lang-${mode === 'repo' ? 'repo' : language}`} />
              {mode === 'repo' ? 'repository' : target}
            </div>
            {mode === 'snippet' && <span className="meta-line">{code.split('\n').length} lines</span>}
          </div>
          <div className="panel-body editor-body">
            {mode === 'repo' ? (
              <RepoPanel repoUrl={repoUrl} onChange={setRepoUrl} onSubmit={runAnalysis} />
            ) : (
              <Editor
                height="100%"
                language={language}
                theme="appsec-dark"
                beforeMount={defineEditorTheme}
                value={code}
                onChange={(value) => setCode(value ?? '')}
                loading={<div className="editor-loading">Loading editor…</div>}
                options={{
                  minimap: { enabled: false },
                  fontSize: 14,
                  fontFamily: "'JetBrains Mono', ui-monospace, Consolas, monospace",
                  fontLigatures: true,
                  padding: { top: 16 },
                  scrollBeyondLastLine: false,
                  smoothScrolling: true,
                  cursorBlinking: 'smooth',
                  renderLineHighlight: 'gutter',
                }}
              />
            )}
            {loading && <div className="scan-line" aria-hidden="true" />}
          </div>
        </section>

        <ResultsPanel
          key={runId}
          mode={mode}
          loading={loading}
          error={error}
          result={result}
          onExport={exportReport}
        />
      </main>
    </div>
  );
}

export default App;
