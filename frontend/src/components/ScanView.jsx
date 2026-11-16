import { useEffect, useState } from 'react';
import Editor from '@monaco-editor/react';
import { Check, Code, FileCode, GitBranch, Play, Square, TriangleAlert } from 'lucide-react';
import { CONFIG_LANGUAGE, EXAMPLES, LANGUAGES } from '../data/examples';
import { AI_CONFIG_ERRORS, STAGES } from '../lib/ui';
import { Segmented } from './common';

const AI_STAGE = STAGES.indexOf('AI triage');

function defineEditorThemes(monaco) {
  monaco.editor.defineTheme('appsec-dark', {
    base: 'vs-dark',
    inherit: true,
    rules: [{ token: 'comment', foreground: '7f889b', fontStyle: 'italic' }],
    colors: {
      'editor.background': '#0e121a',
      'editor.lineHighlightBackground': '#151b27',
      'editorLineNumber.foreground': '#3a4559',
      'editorLineNumber.activeForeground': '#9aa3b2',
      'editorCursor.foreground': '#2dd4bf',
      'editor.selectionBackground': '#1f3b44',
    },
  });
  monaco.editor.defineTheme('appsec-light', {
    base: 'vs',
    inherit: true,
    rules: [{ token: 'comment', foreground: '6b7280', fontStyle: 'italic' }],
    colors: {
      'editor.background': '#fbfbfc',
      'editor.lineHighlightBackground': '#f1f3f6',
      'editorLineNumber.foreground': '#b6bdc8',
      'editorCursor.foreground': '#0f766e',
    },
  });
}

/** Stage states: the request is a single call, so stages advance on a timer and hold on AI triage. */
function stageStates({ loading, tick, result }) {
  if (loading) return STAGES.map((_, i) => (i < Math.min(tick, AI_STAGE) ? 'done' : i === Math.min(tick, AI_STAGE) ? 'active' : 'pending'));
  if (!result) return STAGES.map(() => 'pending');
  const meta = result.meta || {};
  const engines = meta.engines || [];
  return STAGES.map((stage) => {
    if (stage === 'SAST' && engines.length && !engines.includes('bandit')) return 'skipped';
    if (stage === 'Dependencies' && ['not_applicable', 'disabled', undefined].includes(result.dependencies?.status)) return 'skipped';
    if (stage === 'AI triage' && meta.ai_status === 'not_configured') return 'skipped';
    return 'done';
  });
}

function Stepper({ states }) {
  return (
    <ol className="stepper" aria-label="Pipeline stages">
      {STAGES.map((stage, i) => (
        <li key={stage} className={`step step-${states[i]}`} aria-current={states[i] === 'active' ? 'step' : undefined}>
          <span className="step-dot">{states[i] === 'done' ? <Check size={12} strokeWidth={3} aria-hidden="true" /> : i + 1}</span>
          {stage}
          {states[i] === 'skipped' && <span className="step-note">skipped</span>}
        </li>
      ))}
    </ol>
  );
}

function useElapsed(running) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (!running) return undefined;
    const started = performance.now();
    const id = setInterval(() => setElapsed(performance.now() - started), 100);
    return () => {
      clearInterval(id);
      setElapsed(0);
    };
  }, [running]);
  return elapsed;
}

function PipelineStatus({ loading, elapsed, error, result, serverWarm, onViewResults }) {
  if (loading) {
    return (
      <div className="pipeline-status">
        <div className="radar active" aria-hidden="true">
          <span className="radar-sweep" />
        </div>
        <div className="status-text" aria-live="polite">
          <b>
            Running pipeline <span className="timer">{(elapsed / 1000).toFixed(1)}s</span>
          </b>
          <p>{!serverWarm && elapsed > 3000 ? 'Waking up the server. Free-tier hosting can take up to a minute.' : 'Analysing the target…'}</p>
        </div>
      </div>
    );
  }
  if (error) {
    return (
      <div className="alert alert-error" role="alert">
        <TriangleAlert size={16} />
        <div>
          <b>{AI_CONFIG_ERRORS.has(error.code) ? 'AI engine unavailable' : 'Analysis failed'}</b>
          <p>{error.message}</p>
        </div>
      </div>
    );
  }
  if (result) {
    const total = result.vulnerabilities?.length ?? 0;
    return (
      <div className="pipeline-status">
        <div className="radar" aria-hidden="true">
          <span className="radar-sweep" />
        </div>
        <div className="status-text">
          <b>Scan complete</b>
          <p>
            {total} finding{total === 1 ? '' : 's'} ·{' '}
            <button type="button" className="link-btn" onClick={onViewResults}>
              view results
            </button>
          </p>
        </div>
      </div>
    );
  }
  return (
    <div className="pipeline-status">
      <div className="radar" aria-hidden="true">
        <span className="radar-sweep" />
      </div>
      <div className="status-text">
        <b>Ready to scan</b>
        <p>Secrets are redacted before any engine or the AI sees the code.</p>
      </div>
    </div>
  );
}

export default function ScanView({
  mode, onModeChange, code, onCodeChange, language, onLanguageChange, repoUrl, onRepoUrlChange,
  paranoia, onParanoiaChange, onExample, loading, error, result, serverWarm, onRun, onCancel, theme, onViewResults,
}) {
  const elapsed = useElapsed(loading);
  const tick = Math.floor(elapsed / (mode === 'repo' ? 1300 : 650));
  const states = stageStates({ loading, tick, result });
  const examples = EXAMPLES.filter((ex) => (mode === 'config' ? ex.language === 'config' : ex.language !== 'config'));
  const editorLanguage = mode === 'config' ? 'yaml' : language;

  return (
    <div className="scan-grid view">
      <section className="card editor-card" aria-label="Scan target">
        <div className="card-head">
          <Segmented
            label="Scan mode"
            value={mode}
            onChange={onModeChange}
            options={[
              { value: 'snippet', label: 'Snippet', icon: <Code size={14} aria-hidden="true" /> },
              { value: 'repo', label: 'Repository', icon: <GitBranch size={14} aria-hidden="true" /> },
              { value: 'config', label: 'Config', icon: <FileCode size={14} aria-hidden="true" /> },
            ]}
          />
        </div>

        <div className="toolbar">
          {mode === 'snippet' && (
            <label className="field">
              <span>Language</span>
              <select value={language} onChange={(e) => onLanguageChange(e.target.value)}>
                {LANGUAGES.map((l) => (
                  <option key={l.value} value={l.value}>
                    {l.label}
                  </option>
                ))}
              </select>
            </label>
          )}
          {mode !== 'repo' && (
            <label className="field">
              <span>Examples</span>
              <select
                value=""
                onChange={(e) => {
                  const example = EXAMPLES.find((ex) => ex.id === e.target.value);
                  if (example) onExample(example);
                }}
              >
                <option value="" disabled>
                  Load a sample…
                </option>
                {examples.map((ex) => (
                  <option key={ex.id} value={ex.id}>
                    {ex.language === 'config' ? CONFIG_LANGUAGE.label : LANGUAGES.find((l) => l.value === ex.language)?.label} · {ex.label}
                  </option>
                ))}
              </select>
            </label>
          )}
          <div className="field">
            <span>Paranoia</span>
            <Segmented
              label="Paranoia level"
              value={paranoia}
              onChange={onParanoiaChange}
              options={[
                { value: 'standard', label: 'Standard' },
                { value: 'aggressive', label: 'Aggressive' },
              ]}
            />
          </div>
        </div>

        <div className={`editor-wrap ${loading ? 'scanning' : ''}`}>
          {mode === 'repo' ? (
            <div className="repo-pane">
              <h3>Public GitHub repository</h3>
              <p className="muted">
                Shallow-cloned into an isolated temporary directory. Source, Dockerfiles, compose and Kubernetes
                manifests, and dependency manifests are analysed; secrets are redacted first.
              </p>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  onRun();
                }}
              >
                <input
                  className="input"
                  type="url"
                  aria-label="Repository URL"
                  placeholder="https://github.com/owner/repo"
                  value={repoUrl}
                  onChange={(e) => onRepoUrlChange(e.target.value)}
                  spellCheck={false}
                  autoComplete="off"
                />
              </form>
              <ul className="limits">
                <li>
                  <b>20</b> source files
                </li>
                <li>
                  <b>10</b> config / manifest files
                </li>
                <li>
                  <b>30 KB</b> per file
                </li>
              </ul>
            </div>
          ) : (
            <Editor
              height="100%"
              language={editorLanguage}
              theme={theme === 'dark' ? 'appsec-dark' : 'appsec-light'}
              beforeMount={defineEditorThemes}
              value={code}
              onChange={(value) => onCodeChange(value ?? '')}
              loading={<div className="editor-loading">Loading editor…</div>}
              options={{
                minimap: { enabled: false },
                fontSize: 13.5,
                fontFamily: "'IBM Plex Mono', ui-monospace, Consolas, monospace",
                padding: { top: 14 },
                scrollBeyondLastLine: false,
                renderLineHighlight: 'gutter',
                smoothScrolling: true,
              }}
            />
          )}
          {loading && <div className="scan-beam" aria-hidden="true" />}
        </div>
      </section>

      <aside className="card pipeline-card" aria-label="Pipeline">
        <div className="card-head">
          <h2>Pipeline</h2>
        </div>
        <div className="pipeline-body">
          <Stepper states={states} />
          <PipelineStatus
            loading={loading}
            elapsed={elapsed}
            error={error}
            result={result}
            serverWarm={serverWarm}
            onViewResults={onViewResults}
          />
          {loading ? (
            <button type="button" className="btn btn-danger btn-block" onClick={onCancel}>
              <Square size={13} aria-hidden="true" /> Cancel
            </button>
          ) : (
            <button type="button" className="btn btn-primary btn-block" onClick={onRun} title="Ctrl + Enter">
              <Play size={14} aria-hidden="true" /> Run analysis <kbd>Ctrl ↵</kbd>
            </button>
          )}
        </div>
      </aside>
    </div>
  );
}
