import { useMemo } from 'react';
import { Info, Scale } from 'lucide-react';
import { DISCLAIMER } from '../lib/assessment';
import { EmptyState, SkeletonList } from './common';

function ControlTable({ title, controls, byId, onOpenFinding }) {
  return (
    <section className="card">
      <div className="card-head">
        <h2>{title}</h2>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Control</th>
              <th>Title</th>
              <th style={{ textAlign: 'right' }}>Findings</th>
              <th>Linked risks</th>
            </tr>
          </thead>
          <tbody>
            {controls.map((c) => (
              <tr key={c.id} className={c.findings.length ? '' : 'inactive'}>
                <td className="mono">{c.id}</td>
                <td>{c.title}</td>
                <td className="num">{c.findings.length}</td>
                <td>
                  {c.findings.slice(0, 8).map((id) => (
                    <button key={id} type="button" className="link-btn" style={{ marginRight: 8 }} onClick={() => onOpenFinding(id)}>
                      {byId[id]?.risk?.id || id.slice(0, 6)}
                    </button>
                  ))}
                  {c.findings.length > 8 && <span className="small dim">+{c.findings.length - 8}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default function ComplianceView({ result, loading, onOpenFinding, onNavigate }) {
  const byId = useMemo(() => Object.fromEntries((result?.vulnerabilities || []).map((f) => [f.id, f])), [result]);
  if (loading) return <SkeletonList count={3} />;
  if (!result) {
    return (
      <EmptyState
        icon={Scale}
        title="No compliance mapping yet"
        action={
          <button type="button" className="btn btn-primary" onClick={() => onNavigate('scan')}>
            Start a scan
          </button>
        }
      >
        Findings are mapped to IEC 62443-3-3 foundational requirements and ISO/IEC 27001:2022 Annex A controls from
        a curated table.
      </EmptyState>
    );
  }
  const summary = result.compliance_summary;
  if (!summary?.iec62443) {
    return <EmptyState icon={Scale} title="No compliance data">This result was produced by an older API version.</EmptyState>;
  }

  return (
    <div className="view">
      <div className="alert alert-info disclaimer" role="note">
        <Info size={16} aria-hidden="true" />
        <div>
          <b>{summary.disclaimer || DISCLAIMER}</b>
          <p>
            The mapping comes from a static table in code (rule, then CWE, then STRIDE category). It helps prioritise
            and document findings; it is not produced by the AI.
          </p>
        </div>
      </div>
      <div className="two-col">
        <ControlTable title="IEC 62443-3-3 foundational requirements" controls={summary.iec62443} byId={byId} onOpenFinding={onOpenFinding} />
        <ControlTable title="ISO/IEC 27001:2022 Annex A" controls={summary.iso27001} byId={byId} onOpenFinding={onOpenFinding} />
      </div>
    </div>
  );
}
