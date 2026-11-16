import { orderFindings, STRIDE } from './filters';
import { escapeHtml } from './report';
import { countBySeverity, normalizeSeverity, SEVERITIES } from './severity';

export const DISCLAIMER = 'Indicative mapping, not a certification or audit result.';
const BAND_COLORS = { Low: '#2563eb', Medium: '#b7791f', High: '#c2410c', Critical: '#b42318' };
const SEV_COLORS = { CRITICAL: '#b42318', HIGH: '#c2410c', MEDIUM: '#b7791f', LOW: '#2563eb', INFO: '#475569' };

export const LIMITATIONS = [
  'Static analysis only: no code is executed and runtime configuration is not observed.',
  'Rule packs are heuristic. OT/ICS rules recognise common libraries and configuration literals; they do not '
    + 'inspect protocol traffic or device firmware.',
  'AI triage can miss issues or misjudge them. Its verdicts are shown next to, never instead of, the '
    + 'deterministic findings, and it never sets risk scores or compliance mappings.',
  'Repository scans are capped (source files, file size and context length); large projects are only partly covered.',
  'The compliance mapping is indicative and does not replace an IEC 62443 or ISO/IEC 27001 assessment.',
];

function riskOf(f) {
  return f.risk || null;
}

/** Everything the report needs, derived only from the API result and the (optional) narrative. */
export function buildAssessment({ result, narrative, target, generatedAt = new Date() }) {
  const findings = orderFindings(result?.vulnerabilities || []);
  const byId = Object.fromEntries(findings.map((f) => [f.id, f]));
  const top = (result?.top_risks?.length ? result.top_risks.map((id) => byId[id]).filter(Boolean) : findings).slice(0, 5);
  const mitigations = Object.fromEntries((narrative?.mitigations || []).map((m) => [m.risk_id, m.text]));
  const stride = STRIDE.map((category) => ({
    category,
    findings: findings.filter((f) => (f.stride || []).includes(category)),
  }));
  const meta = result?.meta || {};

  return {
    target,
    generatedAt,
    meta,
    counts: countBySeverity(findings),
    total: findings.length,
    findings,
    summary: narrative?.executive_summary || '',
    summarySource: narrative?.generated_by || 'none',
    summaryNote: narrative?.note || '',
    matrix: result?.risk_matrix?.cells || [],
    formula: result?.risk_matrix?.formula || '',
    top: top.map((f) => ({ finding: f, mitigation: mitigations[riskOf(f)?.id] || f.secure_code_snippet })),
    stride,
    compliance: result?.compliance_summary || { iec62443: [], iso27001: [], disclaimer: DISCLAIMER },
    dependencies: result?.dependencies || {},
    configFiles: meta.config_files || [],
    configFindings: findings.filter((f) => f.category === 'config'),
    dependencyFindings: findings.filter((f) => f.category === 'dependency'),
  };
}

function riskLabel(f) {
  const r = riskOf(f);
  return r ? `${r.id} · ${r.band} (${r.score})` : normalizeSeverity(f.severity);
}

// ---------------------------------------------------------------------------------------------
// HTML (standalone, print-friendly; every value escaped)

function cellHtml(cell) {
  const n = cell?.findings?.length || 0;
  const color = BAND_COLORS[cell?.band] || '#94a3b8';
  return `<td style="--c:${color}" class="${n ? 'hit' : ''}">${n || ''}</td>`;
}

function matrixHtml(cells) {
  if (!cells.length) return '<p class="muted">No risk matrix available.</p>';
  const at = (l, i) => cells.find((c) => c.likelihood === l && c.impact === i);
  const rows = [5, 4, 3, 2, 1]
    .map((l) => `<tr><th>L${l}</th>${[1, 2, 3, 4, 5].map((i) => cellHtml(at(l, i))).join('')}</tr>`)
    .join('');
  return `<table class="matrix"><tbody>${rows}<tr><th></th>${[1, 2, 3, 4, 5]
    .map((i) => `<th>I${i}</th>`)
    .join('')}</tr></tbody></table>`;
}

function findingHtml(f) {
  const sev = normalizeSeverity(f.severity);
  const tags = [f.rule_id, f.cwe, f.owasp, ...(f.stride || [])].filter((t) => t && t !== 'N/A');
  return `<article style="--c:${SEV_COLORS[sev]}">
<header><span class="sev">${sev}</span><h4>${escapeHtml(f.title || f.vulnerability)}</h4><span class="mono">${escapeHtml(riskLabel(f))}</span></header>
<p class="mono muted">${escapeHtml(f.file)}:${escapeHtml(f.line_number || f.line)} · ${escapeHtml(f.source)}</p>
<p>${tags.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join(' ')}</p>
<p>${escapeHtml(f.risk_explanation)}</p>
${f.excerpt ? `<pre>${escapeHtml(f.excerpt)}</pre>` : ''}
<p><b>Remediation:</b> ${escapeHtml(f.secure_code_snippet)}</p>
</article>`;
}

function controlsHtml(list) {
  return `<table><thead><tr><th>Control</th><th>Title</th><th>Linked findings</th></tr></thead><tbody>${list
    .map((c) => `<tr><td class="mono">${escapeHtml(c.id)}</td><td>${escapeHtml(c.title)}</td><td>${c.findings.length}</td></tr>`)
    .join('')}</tbody></table>`;
}

export function renderAssessmentHtml(model) {
  const m = model.meta;
  const date = model.generatedAt.toISOString().slice(0, 10);
  const counts = SEVERITIES.map((s) => `<div class="stat" style="--c:${SEV_COLORS[s]}"><b>${model.counts[s]}</b><span>${s}</span></div>`).join('');
  const summary = model.summary
    ? `<p>${escapeHtml(model.summary)}</p><p class="muted small">Written by ${model.summarySource === 'ai' ? 'the AI engine from the computed results (numbers validated)' : 'deterministic templates'}.${model.summaryNote ? ` ${escapeHtml(model.summaryNote)}` : ''}</p>`
    : '<p class="muted">Executive summary not available.</p>';
  const top = model.top
    .map(({ finding: f, mitigation }) => `<li><b>${escapeHtml(riskLabel(f))}</b> ${escapeHtml(f.title || f.vulnerability)} <span class="mono muted">${escapeHtml(f.file)}:${escapeHtml(f.line_number || f.line)}</span><br>${escapeHtml(mitigation)}</li>`)
    .join('');
  const stride = model.stride
    .map((s) => `<tr><td>${s.category}</td><td>${s.findings.length}</td><td>${s.findings.map((f) => escapeHtml(f.risk?.id || f.rule_id || '')).join(', ')}</td></tr>`)
    .join('');
  const dep = model.dependencies;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Assessment Report - ${escapeHtml(model.target)}</title>
<style>
:root{color-scheme:light}body{margin:0;background:#fff;color:#111827;font:14px/1.6 "IBM Plex Sans",system-ui,sans-serif;padding:40px 16px}
main{max-width:900px;margin:0 auto}h1{font-size:26px;margin:0}h2{font-size:18px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid #e5e7eb}
h4{margin:0;font-size:15px;flex:1}.mono{font-family:"IBM Plex Mono",ui-monospace,monospace;font-size:12.5px}.muted{color:#6b7280}.small{font-size:12px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}.stat{border:1px solid #e5e7eb;border-top:3px solid var(--c);border-radius:6px;padding:10px;text-align:center}
.stat b{display:block;font-size:22px;color:var(--c);font-variant-numeric:tabular-nums}.stat span{font-size:11px;letter-spacing:.06em;color:#4b5563}
table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top}
.matrix{width:auto}.matrix td{width:44px;height:36px;text-align:center;font-weight:600;background:color-mix(in srgb,var(--c) 10%,#fff)}
.matrix td.hit{background:color-mix(in srgb,var(--c) 45%,#fff)}article{border:1px solid #e5e7eb;border-left:4px solid var(--c);border-radius:6px;padding:12px 14px;margin:10px 0;break-inside:avoid}
article header{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.sev{font-size:11px;font-weight:700;color:var(--c);border:1px solid var(--c);border-radius:999px;padding:1px 8px}
.tag{display:inline-block;border:1px solid #e5e7eb;border-radius:4px;padding:0 6px;font-size:12px;margin:2px 0}pre{background:#f6f8fa;border:1px solid #e5e7eb;border-radius:6px;padding:10px;white-space:pre-wrap;font-size:12.5px}
.note{background:#f8fafc;border:1px solid #e5e7eb;border-radius:6px;padding:8px 12px}
@media print{body{padding:0}h2{break-after:avoid}}@media(max-width:600px){.stats{grid-template-columns:repeat(3,1fr)}}
</style></head><body><main>
<h1>Security Assessment Report</h1>
<p class="muted">${escapeHtml(model.target)} · ${date}</p>
<section class="stats">${counts}</section>
<h2>1. Executive summary</h2>${summary}
<h2>2. Scope and method</h2>
<table><tbody>
<tr><th>Target</th><td>${escapeHtml(model.target)} (${escapeHtml(m.mode || '')})</td></tr>
<tr><th>Files analysed</th><td>${escapeHtml(m.files_scanned ?? '')}${m.truncated ? ' (limits reached; partial coverage)' : ''}</td></tr>
<tr><th>Engines</th><td>${escapeHtml((m.engines || []).join(', '))}</td></tr>
<tr><th>Paranoia level</th><td>${escapeHtml(m.paranoia_level || '')}</td></tr>
<tr><th>AI engine</th><td>${m.ai_status === 'used' ? escapeHtml(m.model) : 'not used'}</td></tr>
<tr><th>Method</th><td>Secret redaction, then Bandit SAST, rule packs (OT/ICS, configuration), OSV dependency check, AI triage and deterministic risk scoring.</td></tr>
</tbody></table>
<h2>3. Risk matrix</h2>${matrixHtml(model.matrix)}<p class="small muted">${escapeHtml(model.formula)}</p>
<h2>4. Top risks and mitigations</h2>${top ? `<ol>${top}</ol>` : '<p>No risks identified.</p>'}
<h2>5. Findings by STRIDE category</h2><table><thead><tr><th>Category</th><th>Findings</th><th>Risk ids</th></tr></thead><tbody>${stride}</tbody></table>
<h2>6. Indicative IEC 62443 / ISO 27001 mapping</h2><p class="note"><b>${escapeHtml(model.compliance.disclaimer || DISCLAIMER)}</b></p>
<h3>IEC 62443-3-3 foundational requirements</h3>${controlsHtml(model.compliance.iec62443 || [])}
<h3>ISO/IEC 27001:2022 Annex A</h3>${controlsHtml(model.compliance.iso27001 || [])}
<h2>7. Dependency and configuration results</h2>
<p>Dependency check (${escapeHtml(dep.source || 'OSV.dev')}): <b>${escapeHtml(dep.status || 'not_applicable')}</b>${dep.note ? ` · ${escapeHtml(dep.note)}` : ''}</p>
<p>Configuration files: ${model.configFiles.length ? model.configFiles.map((c) => `<span class="mono">${escapeHtml(c.file)}</span> (${escapeHtml(c.kind)})`).join(', ') : 'none'}</p>
<p>${model.configFindings.length} configuration finding(s), ${model.dependencyFindings.length} vulnerable dependency finding(s).</p>
<h2>8. Limitations</h2><ul>${LIMITATIONS.map((l) => `<li>${escapeHtml(l)}</li>`).join('')}</ul>
<h2>9. Appendix: all findings</h2>${model.findings.map(findingHtml).join('\n') || '<p>No findings.</p>'}
</main></body></html>`;
}

// ---------------------------------------------------------------------------------------------
// Markdown

export function mdEscape(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\r?\n/g, ' ');
}

function mdTable(header, rows) {
  return [`| ${header.join(' | ')} |`, `|${header.map(() => '---').join('|')}|`, ...rows.map((r) => `| ${r.join(' | ')} |`)].join('\n');
}

export function renderAssessmentMarkdown(model) {
  const m = model.meta;
  const at = (l, i) => model.matrix.find((c) => c.likelihood === l && c.impact === i)?.findings.length || 0;
  const lines = [
    '# Security Assessment Report',
    '',
    `**Target:** ${mdEscape(model.target)}  `,
    `**Date:** ${model.generatedAt.toISOString().slice(0, 10)}`,
    '',
    mdTable(SEVERITIES, [SEVERITIES.map((s) => String(model.counts[s]))]),
    '',
    '## 1. Executive summary',
    '',
    model.summary ? mdEscape(model.summary) : '_Executive summary not available._',
    model.summaryNote ? `\n> ${mdEscape(model.summaryNote)}` : '',
    '',
    '## 2. Scope and method',
    '',
    mdTable(['Item', 'Value'], [
      ['Mode', mdEscape(m.mode)],
      ['Files analysed', `${m.files_scanned ?? ''}${m.truncated ? ' (partial)' : ''}`],
      ['Engines', mdEscape((m.engines || []).join(', '))],
      ['Paranoia level', mdEscape(m.paranoia_level)],
      ['AI engine', m.ai_status === 'used' ? mdEscape(m.model) : 'not used'],
    ]),
    '',
    '## 3. Risk matrix',
    '',
    mdTable(['Likelihood \\ Impact', '1', '2', '3', '4', '5'], [5, 4, 3, 2, 1].map((l) => [`**${l}**`, ...[1, 2, 3, 4, 5].map((i) => String(at(l, i) || '·'))])),
    '',
    model.formula ? `_${mdEscape(model.formula)}_` : '',
    '',
    '## 4. Top risks and mitigations',
    '',
    ...model.top.map(({ finding: f, mitigation }, i) => `${i + 1}. **${mdEscape(riskLabel(f))}** ${mdEscape(f.title || f.vulnerability)} (\`${mdEscape(f.file)}:${f.line_number || ''}\`)  \n   ${mdEscape(mitigation)}`),
    '',
    '## 5. Findings by STRIDE category',
    '',
    mdTable(['Category', 'Findings'], model.stride.map((s) => [s.category, String(s.findings.length)])),
    '',
    '## 6. Indicative IEC 62443 / ISO 27001 mapping',
    '',
    `> **${mdEscape(model.compliance.disclaimer || DISCLAIMER)}**`,
    '',
    mdTable(['IEC 62443-3-3', 'Title', 'Findings'], (model.compliance.iec62443 || []).map((c) => [c.id, mdEscape(c.title), String(c.findings.length)])),
    '',
    mdTable(['ISO/IEC 27001:2022', 'Title', 'Findings'], (model.compliance.iso27001 || []).map((c) => [c.id, mdEscape(c.title), String(c.findings.length)])),
    '',
    '## 7. Dependency and configuration results',
    '',
    `- Dependency check: **${mdEscape(model.dependencies.status || 'not_applicable')}**${model.dependencies.note ? ` (${mdEscape(model.dependencies.note)})` : ''}`,
    `- Configuration files: ${model.configFiles.map((c) => `\`${mdEscape(c.file)}\``).join(', ') || 'none'}`,
    `- ${model.configFindings.length} configuration finding(s), ${model.dependencyFindings.length} dependency finding(s)`,
    '',
    '## 8. Limitations',
    '',
    ...LIMITATIONS.map((l) => `- ${l}`),
    '',
    '## 9. Appendix: all findings',
    '',
    mdTable(['Risk', 'Severity', 'Finding', 'Location', 'CWE', 'Source'], model.findings.map((f) => [
      mdEscape(f.risk?.id || ''),
      normalizeSeverity(f.severity),
      mdEscape(f.title || f.vulnerability),
      `\`${mdEscape(f.file)}:${f.line_number || mdEscape(f.line)}\``,
      mdEscape(f.cwe),
      mdEscape(f.source),
    ])),
    '',
  ];
  return lines.filter((l, i, arr) => !(l === '' && arr[i - 1] === '')).join('\n');
}
