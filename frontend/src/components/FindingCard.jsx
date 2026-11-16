import { useEffect, useRef, useState } from 'react';
import { Bot, Check, ChevronDown, Copy, ShieldCheck, ShieldQuestion } from 'lucide-react';
import { ENGINE_LABELS, engineGroups } from '../lib/filters';
import { RiskPill, SeverityBadge } from './common';
import { sevClass } from '../lib/ui';

const VERDICTS = {
  confirmed: { label: 'AI confirmed', icon: ShieldCheck },
  disputed: { label: 'AI disputes this finding', icon: ShieldQuestion },
  ai_only: { label: 'Reported by AI only', icon: Bot },
};

export default function FindingCard({ finding: f, index, defaultOpen = false, focused = false }) {
  const [open, setOpen] = useState(defaultOpen || focused);
  const [copied, setCopied] = useState(false);
  const ref = useRef(null);
  const verdict = VERDICTS[f.ai_verdict];
  const lineNumber = f.line_number || String(f.line || '').replace(/^line\s*/i, '');

  useEffect(() => {
    if (focused) ref.current?.scrollIntoView?.({ block: 'center', behavior: 'smooth' });
  }, [focused]);

  const copyFix = async () => {
    try {
      await navigator.clipboard.writeText(f.secure_code_snippet);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard can be unavailable on insecure origins */
    }
  };

  const tags = [f.cwe, f.owasp].filter((t) => t && t !== 'N/A');

  return (
    <article
      ref={ref}
      className={`finding ${sevClass(f.severity)} ${open ? 'open' : ''} ${focused ? 'focused' : ''}`}
      style={{ '--i': Math.min(index, 12) }}
    >
      <button type="button" className="finding-head" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <SeverityBadge severity={f.severity} />
        <h3>{f.title || f.vulnerability}</h3>
        {f.rule_id && f.rule_id !== 'AI' && <span className="tag mono">{f.rule_id}</span>}
        <RiskPill risk={f.risk} />
        <span className="finding-loc">
          {f.file}:{lineNumber}
        </span>
        <ChevronDown size={16} className="chevron" aria-hidden="true" />
      </button>

      <div className="finding-collapse">
        <div className="finding-inner">
          <div className="finding-body">
            <div className="tags">
              {tags.map((t) => (
                <span key={t} className="tag mono">
                  {t}
                </span>
              ))}
              {(f.stride || []).map((s) => (
                <span key={s} className="tag">
                  {s}
                </span>
              ))}
              {engineGroups(f).map((e) => (
                <span key={e} className="tag">
                  {ENGINE_LABELS[e]}
                </span>
              ))}
              <span className="tag">Confidence {String(f.confidence).toLowerCase()}</span>
              {verdict && (
                <span className={`verdict verdict-${f.ai_verdict}`}>
                  <verdict.icon size={13} aria-hidden="true" />
                  {verdict.label}
                </span>
              )}
            </div>

            <p className="finding-text">{f.risk_explanation}</p>

            {f.excerpt && <pre className="code">{f.excerpt}</pre>}

            {f.dependency && (
              <div className="dep-grid">
                <div>
                  <span>Package</span>
                  <b className="mono">
                    {f.dependency.package} {f.dependency.version}
                  </b>
                </div>
                <div>
                  <span>Advisory</span>
                  <b className="mono">{[f.dependency.vuln_id, ...(f.dependency.aliases || [])].join(' · ')}</b>
                </div>
                <div>
                  <span>Fixed in</span>
                  <b className="mono">{f.dependency.fixed_version || 'not yet'}</b>
                </div>
              </div>
            )}

            <div className="fix">
              <div className="fix-head">
                <span>Remediation</span>
                <button type="button" className="btn btn-sm" onClick={copyFix} aria-label="Copy remediation">
                  {copied ? <Check size={13} /> : <Copy size={13} />}
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
              <pre className="code">{f.secure_code_snippet}</pre>
            </div>

            {f.risk?.factors?.length > 0 && (
              <p className="small muted">
                Risk {f.risk.id}: likelihood {f.risk.likelihood} × impact {f.risk.impact} = {f.risk.score} ({f.risk.band}).{' '}
                {f.risk.factors.join('; ')}.
              </p>
            )}

            {f.references?.length > 0 && (
              <div className="refs">
                {f.references.map((r) => (
                  <a key={r} href={r} target="_blank" rel="noreferrer">
                    {r.replace(/^https?:\/\//, '')}
                  </a>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </article>
  );
}
