import { useMemo } from 'react';
import { FileDown, FileJson, FileText, RotateCcw } from 'lucide-react';
import { buildAssessment, LIMITATIONS } from '../lib/assessment';
import { SEVERITIES } from '../lib/severity';
import { EmptyState, RiskPill, SeverityBadge } from './common';

function MiniMatrix({ cells }) {
  const at = (l, i) => cells.find((c) => c.likelihood === l && c.impact === i);
  return (
    <div className="mini-matrix" aria-label="Risk matrix">
      {[5, 4, 3, 2, 1].flatMap((l) =>
        [1, 2, 3, 4, 5].map((i) => {
          const cell = at(l, i);
          const n = cell?.findings.length || 0;
          return (
            <span key={`${l}-${i}`} className={`band-${(cell?.band || 'Low').toLowerCase()} ${n ? 'hit' : ''}`}>
              {n || ''}
            </span>
          );
        }),
      )}
    </div>
  );
}

export default function ReportView({ result, target, narrative, onRetryNarrative, onExport, onNavigate }) {
  const model = useMemo(
    () => (result ? buildAssessment({ result, narrative: narrative.data, target }) : null),
    [result, narrative.data, target],
  );

  if (!result) {
    return (
      <EmptyState
        icon={FileText}
        title="No report yet"
        action={
          <button type="button" className="btn btn-primary" onClick={() => onNavigate('scan')}>
            Start a scan
          </button>
        }
      >
        After a scan, the Security Assessment Report can be exported as HTML, Markdown or JSON.
      </EmptyState>
    );
  }

  return (
    <div className="view" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="results-head" style={{ marginBottom: 0 }}>
        <span className="small muted">Security Assessment Report · {model.total} finding(s)</span>
        <div className="actions report-actions">
          <button type="button" className="btn btn-sm" onClick={() => onExport('report-html')}>
            <FileDown size={13} aria-hidden="true" /> HTML
          </button>
          <button type="button" className="btn btn-sm" onClick={() => onExport('report-md')}>
            <FileText size={13} aria-hidden="true" /> Markdown
          </button>
          <button type="button" className="btn btn-sm" onClick={() => onExport('report-json')}>
            <FileJson size={13} aria-hidden="true" /> JSON
          </button>
        </div>
      </div>

      <article className="card report-doc" aria-label="Report preview">
        <section>
          <h2>1. Executive summary</h2>
          {narrative.status === 'loading' ? (
            <div style={{ display: 'grid', gap: 8 }} aria-label="Writing summary">
              <div className="skeleton skeleton-line" />
              <div className="skeleton skeleton-line" style={{ width: '92%' }} />
              <div className="skeleton skeleton-line" style={{ width: '70%' }} />
            </div>
          ) : narrative.status === 'error' ? (
            <p className="muted">
              The summary could not be generated ({narrative.error}).{' '}
              <button type="button" className="link-btn" onClick={onRetryNarrative}>
                <RotateCcw size={11} /> retry
              </button>
            </p>
          ) : (
            <>
              <p>{model.summary}</p>
              <p className="small dim" style={{ marginTop: 6 }}>
                {model.summarySource === 'ai'
                  ? 'Written by the AI engine from the computed results; ids and numbers were validated.'
                  : 'Deterministic summary.'}{' '}
                {model.summaryNote}
              </p>
            </>
          )}
        </section>

        <section>
          <h2>2. Scope and method</h2>
          <p>
            {model.meta.files_scanned} file(s) in <span className="mono">{target}</span> · engines{' '}
            {(model.meta.engines || []).join(', ')} · paranoia {model.meta.paranoia_level}
            {model.meta.truncated ? ' · limits reached, partial coverage' : ''}.
          </p>
        </section>

        <section>
          <h2>3. Risk matrix</h2>
          <MiniMatrix cells={model.matrix} />
          <p className="small dim" style={{ marginTop: 8 }}>
            {model.formula}
          </p>
        </section>

        <section>
          <h2>4. Top risks with mitigations</h2>
          {model.top.length ? (
            <ol>
              {model.top.map(({ finding: f, mitigation }) => (
                <li key={f.id || f.vulnerability}>
                  <RiskPill risk={f.risk} /> <b>{f.title || f.vulnerability}</b>{' '}
                  <span className="mono small dim">
                    {f.file}:{f.line_number}
                  </span>
                  <p className="muted">{mitigation}</p>
                </li>
              ))}
            </ol>
          ) : (
            <p className="muted">No risks identified.</p>
          )}
        </section>

        <section>
          <h2>5. Findings by STRIDE category</h2>
          <div className="tags">
            {model.stride.map((s) => (
              <span key={s.category} className="tag">
                {s.category} <b className="num">{s.findings.length}</b>
              </span>
            ))}
          </div>
        </section>

        <section>
          <h2>6. Indicative IEC 62443 / ISO 27001 mapping</h2>
          <p className="small">
            <b>{model.compliance.disclaimer}</b>
          </p>
          <div className="tags" style={{ marginTop: 8 }}>
            {[...(model.compliance.iec62443 || []), ...(model.compliance.iso27001 || [])]
              .filter((c) => c.findings.length)
              .map((c) => (
                <span key={c.id} className="tag mono">
                  {c.id} · {c.findings.length}
                </span>
              ))}
          </div>
        </section>

        <section>
          <h2>7. Dependency and configuration results</h2>
          <p>
            Dependency check: <b>{model.dependencies.status || 'not_applicable'}</b>
            {model.dependencies.note ? ` · ${model.dependencies.note}` : ''}
          </p>
          <p className="muted">
            {model.configFindings.length} configuration finding(s) in {model.configFiles.length} file(s);{' '}
            {model.dependencyFindings.length} vulnerable dependency finding(s).
          </p>
        </section>

        <section>
          <h2>8. Limitations</h2>
          <ul className="small muted" style={{ margin: 0, paddingLeft: 18 }}>
            {LIMITATIONS.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </section>

        <section>
          <h2>9. Appendix</h2>
          <div className="tags">
            {SEVERITIES.map((s) => (
              <span key={s} style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                <SeverityBadge severity={s} /> <b className="num">{model.counts[s]}</b>
              </span>
            ))}
          </div>
          <p className="small dim" style={{ marginTop: 8 }}>
            The exported report lists every finding with location, CWE, STRIDE tags, explanation and remediation.
          </p>
        </section>
      </article>
    </div>
  );
}
