import { useMemo, useState } from 'react';
import { countBySeverity, sortBySeverity } from '../lib/severity';
import { AlertIcon, CheckIcon, DownloadIcon, SparkIcon } from './Icons';
import ScanProgress from './ScanProgress';
import SummaryBar from './SummaryBar';
import VulnCard from './VulnCard';

function EmptyState() {
  return (
    <div className="empty-state">
      <div className="empty-orb" aria-hidden="true">
        <SparkIcon width={26} height={26} />
      </div>
      <h3>Ready to scan</h3>
      <p className="muted">
        Paste code or load an example, then hit <b>Run analysis</b>. Findings are validated by Bandit, a secret scanner
        and an AI reviewer.
      </p>
      <ul className="feature-list">
        <li>OWASP Top 10 &amp; CWE mapping</li>
        <li>Secrets redacted before AI</li>
        <li>Prompt-injection hardened</li>
      </ul>
    </div>
  );
}

export default function ResultsPanel({ mode, loading, error, result, onExport }) {
  const [filter, setFilter] = useState(null);

  const findings = useMemo(() => sortBySeverity(result?.vulnerabilities), [result]);
  const counts = useMemo(() => countBySeverity(findings), [findings]);
  const visible = filter ? findings.filter((f) => f.severity?.toUpperCase() === filter) : findings;

  let body;
  if (loading) body = <ScanProgress mode={mode} />;
  else if (error)
    body = (
      <div className="alert alert-error" role="alert">
        <AlertIcon width={18} height={18} />
        <div>
          <b>Analysis failed</b>
          <p>{error}</p>
        </div>
      </div>
    );
  else if (!result) body = <EmptyState />;
  else if (findings.length === 0)
    body = (
      <div className="alert alert-success" role="status">
        <CheckIcon width={18} height={18} />
        <div>
          <b>No vulnerabilities detected</b>
          <p>The code passes the security baseline for the selected paranoia level.</p>
        </div>
      </div>
    );
  else
    body = (
      <>
        <SummaryBar counts={counts} filter={filter} onFilter={setFilter} />
        <div className="vuln-list" key={filter || 'all'}>
          {visible.map((vuln, i) => (
            <VulnCard key={`${vuln.file}-${vuln.line}-${vuln.vulnerability}-${i}`} vuln={vuln} index={i} defaultOpen={i === 0} />
          ))}
        </div>
      </>
    );

  const meta = result?.meta;

  return (
    <section className="panel results-panel" aria-label="Audit findings">
      <div className="panel-head">
        <h2>Audit findings</h2>
        {meta && !loading && (
          <span className="meta-line">
            {meta.files_scanned} file{meta.files_scanned === 1 ? '' : 's'} · {(meta.duration_ms / 1000).toFixed(1)}s ·{' '}
            {meta.model}
          </span>
        )}
        {result && !loading && (
          <div className="panel-actions">
            <button type="button" className="btn-icon" onClick={() => onExport('html')}>
              <DownloadIcon /> HTML
            </button>
            <button type="button" className="btn-icon" onClick={() => onExport('json')}>
              <DownloadIcon /> JSON
            </button>
          </div>
        )}
      </div>
      <div className="panel-body">{body}</div>
    </section>
  );
}
