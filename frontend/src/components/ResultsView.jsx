import { useMemo } from 'react';
import { CircleCheck, Download, Info, ListChecks, X } from 'lucide-react';
import { useCountUp } from '../lib/hooks';
import {
  applyFilters, ENGINE_LABELS, facetCounts, isFiltered, orderFindings, PACK_LABELS, STRIDE, toggle,
} from '../lib/filters';
import { SEVERITIES } from '../lib/severity';
import { EmptyState, SeverityIcon, SkeletonList } from './common';
import { sevClass } from '../lib/ui';
import FindingCard from './FindingCard';

function Counter({ severity, count, active, onClick }) {
  const value = useCountUp(count);
  return (
    <button
      type="button"
      className={`counter ${sevClass(severity)} ${count === 0 ? 'zero' : ''}`}
      aria-pressed={active}
      onClick={onClick}
      title={`Show ${severity.toLowerCase()} findings`}
    >
      <span className="counter-label">
        <SeverityIcon severity={severity} size={12} />
        {severity}
      </span>
      <b className="num">{value}</b>
    </button>
  );
}

function ChipRow({ label, values, labels, counts, selected, onToggle }) {
  const visible = values.filter((v) => counts[v] > 0);
  if (!visible.length) return null;
  return (
    <div className="filter-row" role="group" aria-label={`Filter by ${label}`}>
      <span className="filter-label">{label}</span>
      {visible.map((v) => (
        <button key={v} type="button" className="chip" aria-pressed={selected.includes(v)} onClick={() => onToggle(v)}>
          {labels ? labels[v] : v}
          <span className="count">{counts[v]}</span>
        </button>
      ))}
    </div>
  );
}

export default function ResultsView({ result, loading, filters, onFiltersChange, focusId, onExport, onNavigate }) {
  const findings = useMemo(() => orderFindings(result?.vulnerabilities), [result]);
  const counts = useMemo(() => facetCounts(findings), [findings]);
  const visible = applyFilters(findings, filters);
  const meta = result?.meta;

  if (loading) {
    return (
      <div className="view">
        <div className="counters" aria-hidden="true">
          {SEVERITIES.map((s) => (
            <div key={s} className="skeleton" style={{ height: 66 }} />
          ))}
        </div>
        <SkeletonList count={5} />
      </div>
    );
  }

  if (!result) {
    return (
      <EmptyState
        icon={ListChecks}
        title="No scan yet"
        action={
          <button type="button" className="btn btn-primary" onClick={() => onNavigate('scan')}>
            Start a scan
          </button>
        }
      >
        Run an analysis to see de-duplicated findings from Bandit, the rule packs, OSV and the AI reviewer.
      </EmptyState>
    );
  }

  const set = (key, value) => onFiltersChange({ ...filters, [key]: value });

  return (
    <div className="view">
      <div className="results-head">
        {meta && (
          <span className="small muted mono">
            {meta.files_scanned} file{meta.files_scanned === 1 ? '' : 's'} · {(meta.duration_ms / 1000).toFixed(1)}s ·{' '}
            {meta.ai_status === 'not_configured' ? 'no AI' : meta.model}
          </span>
        )}
        <div className="actions">
          <button type="button" className="btn btn-sm" onClick={() => onExport('findings-html')}>
            <Download size={13} aria-hidden="true" /> Findings HTML
          </button>
          <button type="button" className="btn btn-sm" onClick={() => onExport('findings-json')}>
            <Download size={13} aria-hidden="true" /> JSON
          </button>
        </div>
      </div>

      {meta?.ai_status === 'not_configured' && (
        <div className="alert alert-info banner">
          <Info size={16} aria-hidden="true" />
          <div>
            <b>Deterministic results only</b>
            <p>The AI engine is not configured on this server, so findings were not reviewed by the AI.</p>
          </div>
        </div>
      )}

      {findings.length === 0 ? (
        <div className="alert alert-ok">
          <CircleCheck size={16} aria-hidden="true" />
          <div>
            <b>No vulnerabilities detected</b>
            <p>The target passes the security baseline for the selected paranoia level.</p>
          </div>
        </div>
      ) : (
        <>
          <div className="counters">
            {SEVERITIES.map((s) => (
              <Counter
                key={s}
                severity={s}
                count={counts.severity[s]}
                active={filters.severity.includes(s)}
                onClick={() => set('severity', toggle(filters.severity, s))}
              />
            ))}
          </div>

          <div className="filters">
            <ChipRow label="STRIDE" values={STRIDE} counts={counts.stride} selected={filters.stride} onToggle={(v) => set('stride', toggle(filters.stride, v))} />
            <ChipRow label="Engine" values={Object.keys(ENGINE_LABELS)} labels={ENGINE_LABELS} counts={counts.engine} selected={filters.engine} onToggle={(v) => set('engine', toggle(filters.engine, v))} />
            <ChipRow label="Rule pack" values={Object.keys(PACK_LABELS)} labels={PACK_LABELS} counts={counts.pack} selected={filters.pack} onToggle={(v) => set('pack', toggle(filters.pack, v))} />
            {isFiltered(filters) && (
              <div className="filter-row">
                <span className="filter-label">Showing</span>
                <span className="small muted">
                  {visible.length} of {findings.length}
                  {filters.cell && ` · risk cell L${filters.cell.likelihood} × I${filters.cell.impact}`}
                </span>
                <button
                  type="button"
                  className="chip"
                  onClick={() => onFiltersChange({ severity: [], stride: [], engine: [], pack: [], cell: null })}
                >
                  <X size={12} aria-hidden="true" /> Clear filters
                </button>
              </div>
            )}
          </div>

          {visible.length ? (
            <div className="finding-list" key={JSON.stringify(filters)}>
              {visible.map((f, i) => (
                <FindingCard
                  key={f.id || `${f.file}-${f.line}-${f.vulnerability}-${i}`}
                  finding={f}
                  index={i}
                  defaultOpen={i === 0 && !focusId}
                  focused={Boolean(focusId) && f.id === focusId}
                />
              ))}
            </div>
          ) : (
            <EmptyState title="No findings match these filters">Clear one or more filters to see more results.</EmptyState>
          )}
        </>
      )}
    </div>
  );
}
