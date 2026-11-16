import { CircleAlert, CircleArrowDown, Info, OctagonAlert, TriangleAlert } from 'lucide-react';
import { normalizeSeverity } from '../lib/severity';
import { sevClass } from '../lib/ui';

const SEVERITY_ICON = {
  CRITICAL: OctagonAlert,
  HIGH: TriangleAlert,
  MEDIUM: CircleAlert,
  LOW: CircleArrowDown,
  INFO: Info,
};

/** Severity is never colour-only: icon + label + colour. */
export function SeverityIcon({ severity, size = 13 }) {
  const Icon = SEVERITY_ICON[normalizeSeverity(severity)];
  return <Icon size={size} aria-hidden="true" strokeWidth={2.2} />;
}

export function SeverityBadge({ severity }) {
  const sev = normalizeSeverity(severity);
  return (
    <span className={`sev-badge ${sevClass(sev)}`}>
      <SeverityIcon severity={sev} size={12} />
      {sev}
    </span>
  );
}

export function RiskPill({ risk }) {
  if (!risk) return null;
  return (
    <span className={`risk-pill band-${risk.band.toLowerCase()}`} title={`Likelihood ${risk.likelihood} x impact ${risk.impact}`}>
      {risk.id} · {risk.score}
    </span>
  );
}

export function Segmented({ label, value, onChange, options }) {
  return (
    <div className="segmented" role="radiogroup" aria-label={label}>
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          role="radio"
          aria-checked={value === opt.value}
          onClick={() => onChange(opt.value)}
        >
          {opt.icon}
          {opt.label}
        </button>
      ))}
    </div>
  );
}

export function EmptyState({ icon: Icon, title, children, action }) {
  return (
    <div className="empty">
      {Icon && (
        <div className="empty-icon">
          <Icon size={22} aria-hidden="true" />
        </div>
      )}
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function SkeletonList({ count = 4 }) {
  return (
    <div className="finding-list" aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="skeleton skeleton-card" />
      ))}
    </div>
  );
}
