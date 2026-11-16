import { useCallback, useEffect, useRef, useState } from 'react';
import ComplianceView from './components/ComplianceView';
import EvaluationView from './components/EvaluationView';
import PageHeader from './components/PageHeader';
import ReportView from './components/ReportView';
import ResultsView from './components/ResultsView';
import RiskView from './components/RiskView';
import ScanView from './components/ScanView';
import Sidebar from './components/Sidebar';
import { EXAMPLES, LANGUAGES } from './data/examples';
import { analyze, checkHealth, requestReport } from './lib/api';
import { buildAssessment, renderAssessmentHtml, renderAssessmentMarkdown } from './lib/assessment';
import { EMPTY_FILTERS } from './lib/filters';
import { useTheme } from './lib/hooks';
import { buildHtmlReport, downloadFile } from './lib/report';
import { VIEWS } from './lib/ui';
import './App.css';

const IDLE_NARRATIVE = { status: 'idle', data: null, error: null };

// Render's free tier sleeps when idle: ping it silently on load so it is warm by the first scan.
function useWarmUpApi() {
  const [warm, setWarm] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    checkHealth({ signal: controller.signal })
      .then(() => setWarm(true))
      .catch(() => {});
    return () => controller.abort();
  }, []);
  return [warm, setWarm];
}

function App() {
  const [view, setView] = useState('scan');
  const [mode, setMode] = useState('snippet');
  const [code, setCode] = useState(EXAMPLES[0].code);
  const [language, setLanguage] = useState(EXAMPLES[0].language);
  const [repoUrl, setRepoUrl] = useState('');
  const [paranoia, setParanoia] = useState('standard');
  const [result, setResult] = useState(null);
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [focusId, setFocusId] = useState(null);
  const [narrative, setNarrative] = useState(IDLE_NARRATIVE);
  const [theme, toggleTheme] = useTheme();
  const [serverWarm, setServerWarm] = useWarmUpApi();
  const controllerRef = useRef(null);

  const target =
    mode === 'repo'
      ? repoUrl.trim()
      : mode === 'config'
        ? 'configuration snippet'
        : `snippet.${LANGUAGES.find((l) => l.value === language)?.ext}`;

  const runAnalysis = useCallback(async () => {
    if (controllerRef.current) return;
    if (mode !== 'repo' && code.trim().length < 5) {
      setError({ message: 'Paste at least a few lines of code to analyze.' });
      return;
    }
    if (mode === 'repo' && !repoUrl.trim()) {
      setError({ message: 'Enter a public GitHub repository URL.' });
      return;
    }

    const controller = new AbortController();
    controllerRef.current = controller;
    setLoading(true);
    setError(null);
    setResult(null);
    setNarrative(IDLE_NARRATIVE);
    setFilters(EMPTY_FILTERS);
    setFocusId(null);

    try {
      const data = await analyze(
        {
          mode: mode === 'repo' ? 'repo' : 'snippet',
          code,
          language: mode === 'config' ? 'config' : language,
          repo_url: repoUrl.trim(),
          paranoia_level: paranoia,
        },
        { signal: controller.signal },
      );
      setResult(data);
      setScan({ target, meta: data.meta, finishedAt: new Date() });
      setServerWarm(true);
      setView('results');
    } catch (err) {
      if (err.name !== 'AbortError') setError({ message: err.message, code: err.code });
    } finally {
      controllerRef.current = null;
      setLoading(false);
    }
  }, [mode, code, language, repoUrl, paranoia, target, setServerWarm]);

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

  const loadNarrative = useCallback(async () => {
    if (!result) return;
    setNarrative({ status: 'loading', data: null, error: null });
    try {
      const data = await requestReport(scan?.target || target, result);
      setNarrative({ status: 'ready', data, error: null });
    } catch (err) {
      setNarrative({ status: 'error', data: null, error: err.message });
    }
  }, [result, scan, target]);

  const navigate = (id) => {
    setFocusId(null);
    setView(id);
    // The report summary is requested once per scan, when the Report view is first opened.
    if (id === 'report' && result && narrative.status === 'idle') loadNarrative();
  };

  const loadExample = (example) => {
    if (example.language === 'config') {
      setMode('config');
    } else {
      setMode('snippet');
      setLanguage(example.language);
    }
    setCode(example.code);
    setError(null);
  };

  const openFinding = (id) => {
    setFilters(EMPTY_FILTERS);
    setFocusId(id);
    setView('results');
  };

  const selectCell = (cell) => {
    setFilters({ ...EMPTY_FILTERS, cell: { likelihood: cell.likelihood, impact: cell.impact } });
    setFocusId(null);
    setView('results');
  };

  const exportFile = (kind) => {
    if (!result) return;
    const name = scan?.target || target;
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    if (kind === 'findings-json') {
      downloadFile(`findings-${stamp}.json`, JSON.stringify({ target: name, ...result }, null, 2), 'application/json');
      return;
    }
    if (kind === 'findings-html') {
      const html = buildHtmlReport({ findings: result.vulnerabilities, target: name, meta: result.meta });
      downloadFile(`findings-${stamp}.html`, html, 'text/html');
      return;
    }
    const model = buildAssessment({ result, narrative: narrative.data, target: name });
    if (kind === 'report-html') downloadFile(`security-assessment-${stamp}.html`, renderAssessmentHtml(model), 'text/html');
    if (kind === 'report-md') downloadFile(`security-assessment-${stamp}.md`, renderAssessmentMarkdown(model), 'text/markdown');
    if (kind === 'report-json') {
      const json = { target: name, generated_at: new Date().toISOString(), narrative: narrative.data, result };
      downloadFile(`security-assessment-${stamp}.json`, JSON.stringify(json, null, 2), 'application/json');
    }
  };

  return (
    <div className="shell">
      <Sidebar
        view={view}
        onNavigate={navigate}
        findingCount={result ? result.vulnerabilities.length : null}
        theme={theme}
        onToggleTheme={toggleTheme}
      />
      <div className="main">
        <PageHeader title={VIEWS.find((v) => v.id === view)?.label} view={view} scan={scan} />
        <main className="content" key={view}>
          {view === 'scan' && (
            <ScanView
              mode={mode}
              onModeChange={setMode}
              code={code}
              onCodeChange={setCode}
              language={language}
              onLanguageChange={setLanguage}
              repoUrl={repoUrl}
              onRepoUrlChange={setRepoUrl}
              paranoia={paranoia}
              onParanoiaChange={setParanoia}
              onExample={loadExample}
              loading={loading}
              error={error}
              result={result}
              serverWarm={serverWarm}
              onRun={runAnalysis}
              onCancel={cancelAnalysis}
              theme={theme}
              onViewResults={() => navigate('results')}
            />
          )}
          {view === 'results' && (
            <ResultsView
              result={result}
              loading={loading}
              filters={filters}
              onFiltersChange={setFilters}
              focusId={focusId}
              onExport={exportFile}
              onNavigate={navigate}
            />
          )}
          {view === 'risk' && (
            <RiskView result={result} loading={loading} onSelectCell={selectCell} onOpenFinding={openFinding} onNavigate={navigate} />
          )}
          {view === 'compliance' && (
            <ComplianceView result={result} loading={loading} onOpenFinding={openFinding} onNavigate={navigate} />
          )}
          {view === 'report' && (
            <ReportView
              result={result}
              target={scan?.target || target}
              narrative={narrative}
              onRetryNarrative={loadNarrative}
              onExport={exportFile}
              onNavigate={navigate}
            />
          )}
          {view === 'evaluation' && <EvaluationView />}
        </main>
      </div>
    </div>
  );
}

export default App;
