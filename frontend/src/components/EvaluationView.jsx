import { FlaskConical } from 'lucide-react';
import evaluation from '../data/evaluation.json';

const ENGINE_LABELS = { sast: 'SAST only (Bandit)', rules: 'Rule engine', llm: 'LLM only', hybrid: 'Hybrid pipeline' };
const CATEGORY_LABELS = { ot: 'OT / ICS', config: 'Config', appsec: 'AppSec', secrets: 'Secrets' };

const fmt = (v) => (v === null || v === undefined ? 'n/a' : v.toFixed(2));

export default function EvaluationView({ data = evaluation }) {
  const engines = Object.values(data.engines || {});
  const measured = engines.filter((e) => e.status !== 'not_run');
  const categories = Object.keys(measured[0]?.by_category || {});

  return (
    <div className="view" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <section className="card">
        <div className="card-head">
          <h2>Overall</h2>
          <span className="small dim">
            Generated {data.generated_at} · line tolerance ±{data.line_tolerance}
          </span>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Engine</th>
                <th style={{ textAlign: 'right' }}>Samples</th>
                <th style={{ textAlign: 'right' }}>Precision</th>
                <th style={{ textAlign: 'right' }}>Recall</th>
                <th style={{ textAlign: 'right' }}>F1</th>
                <th style={{ textAlign: 'right' }}>FP rate (safe)</th>
              </tr>
            </thead>
            <tbody>
              {engines.map((e) =>
                e.status === 'not_run' ? (
                  <tr key={e.engine} className="inactive">
                    <td>{ENGINE_LABELS[e.engine] || e.engine}</td>
                    <td colSpan={5}>Not measured yet: no recorded model responses. Numbers are never estimated.</td>
                  </tr>
                ) : (
                  <tr key={e.engine}>
                    <td>{ENGINE_LABELS[e.engine] || e.engine}</td>
                    <td className="num">{e.samples}</td>
                    <td className="num">{fmt(e.precision)}</td>
                    <td className="num">{fmt(e.recall)}</td>
                    <td className="num">{fmt(e.f1)}</td>
                    <td className="num">{fmt(e.fp_rate_safe)}</td>
                  </tr>
                ),
              )}
            </tbody>
          </table>
        </div>
      </section>

      {measured.length > 0 && (
        <section className="card">
          <div className="card-head">
            <h2>Recall by category</h2>
          </div>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Engine</th>
                  {categories.map((c) => (
                    <th key={c} style={{ textAlign: 'right' }}>
                      {CATEGORY_LABELS[c] || c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {measured.map((e) => (
                  <tr key={e.engine}>
                    <td>{ENGINE_LABELS[e.engine] || e.engine}</td>
                    {categories.map((c) => (
                      <td key={c} className="num">
                        {fmt(e.by_category[c]?.recall)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <div className="alert alert-info">
        <FlaskConical size={16} aria-hidden="true" />
        <div>
          <b>How to read this</b>
          <p>
            The rule samples were written alongside the rules, so their scores show the rules work as specified rather
            than how they generalise. Full method and interpretation: docs/EVALUATION.md.
          </p>
        </div>
      </div>
    </div>
  );
}
