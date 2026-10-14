import { EXAMPLES, LANGUAGES } from '../data/examples';
import { CodeIcon, PlayIcon, RepoIcon, StopIcon } from './Icons';

function Segmented({ value, onChange, options, label }) {
  return (
    <div className="segmented" role="radiogroup" aria-label={label}>
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          role="radio"
          aria-checked={value === opt.value}
          className={value === opt.value ? 'active' : ''}
          onClick={() => onChange(opt.value)}
        >
          {opt.icon}
          {opt.label}
        </button>
      ))}
    </div>
  );
}

export default function Toolbar({
  mode,
  onModeChange,
  language,
  onLanguageChange,
  paranoia,
  onParanoiaChange,
  onExample,
  loading,
  onRun,
  onCancel,
}) {
  return (
    <div className="toolbar">
      <Segmented
        label="Scan mode"
        value={mode}
        onChange={onModeChange}
        options={[
          { value: 'snippet', label: 'Snippet', icon: <CodeIcon /> },
          { value: 'repo', label: 'Repository', icon: <RepoIcon /> },
        ]}
      />

      {mode === 'snippet' && (
        <>
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

          <label className="field field-highlight">
            <span>Examples</span>
            <select
              value=""
              onChange={(e) => {
                const example = EXAMPLES.find((ex) => ex.id === e.target.value);
                if (example) onExample(example);
              }}
            >
              <option value="" disabled>
                Load vulnerable code…
              </option>
              {EXAMPLES.map((ex) => (
                <option key={ex.id} value={ex.id}>
                  {LANGUAGES.find((l) => l.value === ex.language)?.label} · {ex.label}
                </option>
              ))}
            </select>
          </label>
        </>
      )}

      <Segmented
        label="Paranoia level"
        value={paranoia}
        onChange={onParanoiaChange}
        options={[
          { value: 'standard', label: 'Standard' },
          { value: 'aggressive', label: 'Aggressive' },
        ]}
      />

      <div className="toolbar-spacer" />

      {loading ? (
        <button type="button" className="btn btn-ghost" onClick={onCancel}>
          <StopIcon /> Cancel
        </button>
      ) : (
        <button type="button" className="btn btn-primary" onClick={onRun} title="Ctrl + Enter">
          <PlayIcon /> Run analysis
          <kbd>Ctrl ↵</kbd>
        </button>
      )}
    </div>
  );
}
