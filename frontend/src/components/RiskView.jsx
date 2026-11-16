import { useMemo, useState } from 'react';
import { Grid3x3 } from 'lucide-react';
import { orderFindings } from '../lib/filters';
import { EmptyState, RiskPill, SeverityBadge, SkeletonList } from './common';

const BANDS = ['Low', 'Medium', 'High', 'Critical'];

function Heatmap({ cells, byId, selected, onSelect, onHover }) {
  const at = (l, i) => cells.find((c) => c.likelihood === l && c.impact === i) || { likelihood: l, impact: i, score: l * i, band: 'Low', findings: [] };
  let index = 0;
  return (
    <div>
      <div className="heatmap" role="grid" aria-label="Risk matrix: likelihood by impact">
        {[5, 4, 3, 2, 1].map((l) => (
          <div key={l} role="row" style={{ display: 'contents' }}>
            <span className="axis" role="rowheader">
              L{l}
            </span>
            {[1, 2, 3, 4, 5].map((i) => {
              const cell = at(l, i);
              const n = cell.findings.length;
              const isSelected = selected?.likelihood === l && selected?.impact === i;
              const titles = cell.findings.map((id) => byId[id]?.title || byId[id]?.vulnerability).filter(Boolean);
              return (
                <button
                  key={i}
                  type="button"
                  role="gridcell"
                  className={`cell band-${cell.band.toLowerCase()} ${n ? 'hit' : ''}`}
                  style={{ '--i': index++ }}
                  disabled={!n}
                  aria-pressed={isSelected}
                  aria-label={`Likelihood ${l}, impact ${i}, score ${cell.score} (${cell.band}): ${n} finding${n === 1 ? '' : 's'}`}
                  title={titles.join('\n')}
                  onMouseEnter={() => onHover(cell)}
                  onFocus={() => onHover(cell)}
                  onClick={() => onSelect(cell)}
                >
                  <b>{n || '·'}</b>
                  <small>{cell.score}</small>
                </button>
              );
            })}
          </div>
        ))}
        <span />
        {[1, 2, 3, 4, 5].map((i) => (
          <span key={i} className="axis">
            I{i}
          </span>
        ))}
      </div>
      <div className="axis-title">
        <span>↑ Likelihood</span>
        <span>Impact →</span>
      </div>
      <div className="legend" aria-label="Risk bands">
        {BANDS.map((b) => (
          <span key={b} className={`band-${b.toLowerCase()}`}>
            <i />
            {b}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function RiskView({ result, loading, onSelectCell, onOpenFinding, onNavigate }) {
  const [hovered, setHovered] = useState(null);
  const findings = useMemo(() => orderFindings(result?.vulnerabilities), [result]);
  const byId = useMemo(() => Object.fromEntries(findings.map((f) => [f.id, f])), [findings]);
  const cells = result?.risk_matrix?.cells || [];

  if (loading) return <SkeletonList count={3} />;
  if (!result) {
    return (
      <EmptyState
        icon={Grid3x3}
        title="No risk assessment yet"
        action={
          <button type="button" className="btn btn-primary" onClick={() => onNavigate('scan')}>
            Start a scan
          </button>
        }
      >
        Every finding is scored deterministically: likelihood × impact, with an uplift for OT/ICS code.
      </EmptyState>
    );
  }
  if (!cells.length) {
    return <EmptyState icon={Grid3x3} title="No risk data">This result was produced by an older API version without risk scoring.</EmptyState>;
  }

  const top = (result.top_risks || []).map((id) => byId[id]).filter(Boolean);

  return (
    <div className="risk-grid view">
      <section className="card">
        <div className="card-head">
          <h2>Risk matrix</h2>
          <span className="small dim">Click a cell to filter the results</span>
        </div>
        <div className="card-body">
          <Heatmap cells={cells} byId={byId} onHover={setHovered} onSelect={onSelectCell} />
          <div className="cell-detail" aria-live="polite">
            {hovered && hovered.findings.length ? (
              <>
                <b>
                  L{hovered.likelihood} × I{hovered.impact} = {hovered.score} · {hovered.band}
                </b>
                <ul>
                  {hovered.findings.map((id) => (
                    <li key={id}>
                      <span className="mono dim">{byId[id]?.risk?.id}</span> {byId[id]?.title || byId[id]?.vulnerability}
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <span className="dim">Hover or focus a cell to list its findings.</span>
            )}
          </div>
          <p className="formula">{result.risk_matrix.formula}</p>
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Top 5 risks</h2>
        </div>
        <div className="card-body">
          {top.length ? (
            <ol className="top-list">
              {top.map((f, i) => (
                <li key={f.id}>
                  <button type="button" className="top-item" style={{ '--i': i }} onClick={() => onOpenFinding(f.id)}>
                    <span className="top-rank">{String(i + 1).padStart(2, '0')}</span>
                    <span style={{ flex: 1, minWidth: 0 }}>
                      <span className="top-title">{f.title || f.vulnerability}</span>
                      <span className="small dim mono">
                        {f.file}:{f.line_number}
                      </span>
                    </span>
                    <SeverityBadge severity={f.severity} />
                    <RiskPill risk={f.risk} />
                  </button>
                </li>
              ))}
            </ol>
          ) : (
            <p className="muted">No risks identified.</p>
          )}
        </div>
      </section>
    </div>
  );
}
