const SUBTITLES = {
  scan: 'Static analysis, OT/ICS rules, dependency checks and AI triage in one pipeline',
  results: 'Findings from every engine, de-duplicated and ordered by risk',
  risk: 'Deterministic likelihood × impact scoring on a 5 × 5 matrix',
  compliance: 'Indicative mapping to IEC 62443-3-3 and ISO/IEC 27001:2022',
  report: 'Security Assessment Report: preview and export',
  evaluation: 'Measured precision and recall of each engine on a labelled dataset',
};

function Chip({ label, value }) {
  return (
    <span className="meta-chip">
      {label}
      <b title={String(value)}>{value}</b>
    </span>
  );
}

export default function PageHeader({ title, view, scan }) {
  return (
    <header className="page-header">
      <div className="page-title">
        <h1>{title}</h1>
        <p>{SUBTITLES[view]}</p>
      </div>
      {scan && (
        <div className="scan-meta" aria-label="Last scan">
          <Chip label="Target" value={scan.target} />
          <Chip label="Time" value={scan.finishedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} />
          <Chip label="Engines" value={(scan.meta?.engines || []).join(' · ') || 'n/a'} />
          <Chip label="Duration" value={`${((scan.meta?.duration_ms || 0) / 1000).toFixed(1)} s`} />
        </div>
      )}
    </header>
  );
}
