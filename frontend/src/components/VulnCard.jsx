import { useState } from 'react';
import { normalizeSeverity } from '../lib/severity';
import { CheckIcon, ChevronIcon, CopyIcon } from './Icons';

export default function VulnCard({ vuln, index, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  const [copied, setCopied] = useState(false);
  const severity = normalizeSeverity(vuln.severity);

  const copyFix = async () => {
    try {
      await navigator.clipboard.writeText(vuln.secure_code_snippet);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* clipboard can be unavailable on insecure origins */
    }
  };

  return (
    <article className={`vuln-card sev-${severity.toLowerCase()} ${open ? 'open' : ''}`} style={{ '--i': index }}>
      <button type="button" className="vuln-head" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <span className="sev-badge">{severity}</span>
        <h3>{vuln.vulnerability}</h3>
        <code className="vuln-loc">
          {vuln.file}
          <span>:{String(vuln.line).replace(/^line\s*/i, '')}</span>
        </code>
        <ChevronIcon className="chevron" />
      </button>

      <div className="vuln-collapse">
        <div className="vuln-inner">
          <ul className="tags">
            <li>{vuln.cwe}</li>
            <li>{vuln.owasp}</li>
            <li>
              Confidence <b>{vuln.confidence}</b>
            </li>
            <li>{vuln.source}</li>
          </ul>

          <p className="risk">{vuln.risk_explanation}</p>

          <div className="fix">
            <div className="fix-head">
              <span>Remediation</span>
              <button type="button" className="btn-icon" onClick={copyFix} aria-label="Copy remediation snippet">
                {copied ? <CheckIcon /> : <CopyIcon />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre>{vuln.secure_code_snippet}</pre>
          </div>
        </div>
      </div>
    </article>
  );
}
