import { normalizeSeverity, SEVERITIES } from './severity';

export const STRIDE = [
  'Spoofing',
  'Tampering',
  'Repudiation',
  'Information Disclosure',
  'Denial of Service',
  'Elevation of Privilege',
];

export const ENGINE_LABELS = { rules: 'Rule engine', bandit: 'Bandit', secrets: 'Secrets', osv: 'OSV', ai: 'AI' };
const ENGINE_OF = { python_ast: 'rules', text: 'rules', config: 'rules', bandit: 'bandit', secrets: 'secrets', deps: 'osv', llm: 'ai' };

export const PACK_LABELS = { ot_ics: 'OT / ICS', config: 'Config', deps: 'Dependencies', core: 'Core' };

export const EMPTY_FILTERS = { severity: [], stride: [], engine: [], pack: [], cell: null };

/** Engine groups that reported a finding. v1 findings only carry a `source` string. */
export function engineGroups(finding) {
  const raw = finding.engines?.length ? finding.engines : finding.engine ? [finding.engine] : [];
  if (raw.length) return [...new Set(raw.map((e) => ENGINE_OF[e]).filter(Boolean))];
  const source = String(finding.source || '');
  const groups = [];
  if (/bandit/i.test(source)) groups.push('bandit');
  if (/secret/i.test(source)) groups.push('secrets');
  if (/ai/i.test(source)) groups.push('ai');
  return groups.length ? groups : ['ai'];
}

export function packOf(finding) {
  return finding.pack && PACK_LABELS[finding.pack] ? finding.pack : 'core';
}

export function isFiltered(filters) {
  return Boolean(
    filters.severity.length || filters.stride.length || filters.engine.length || filters.pack.length || filters.cell,
  );
}

export function applyFilters(findings = [], filters = EMPTY_FILTERS) {
  return findings.filter((f) => {
    if (filters.severity.length && !filters.severity.includes(normalizeSeverity(f.severity))) return false;
    if (filters.stride.length && !(f.stride || []).some((s) => filters.stride.includes(s))) return false;
    if (filters.engine.length && !engineGroups(f).some((e) => filters.engine.includes(e))) return false;
    if (filters.pack.length && !filters.pack.includes(packOf(f))) return false;
    if (filters.cell) {
      if (!f.risk || f.risk.likelihood !== filters.cell.likelihood || f.risk.impact !== filters.cell.impact) return false;
    }
    return true;
  });
}

export function toggle(list, value) {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

/** Counts per facet value, used to label filter chips and hide empty ones. */
export function facetCounts(findings = []) {
  const counts = {
    severity: Object.fromEntries(SEVERITIES.map((s) => [s, 0])),
    stride: Object.fromEntries(STRIDE.map((s) => [s, 0])),
    engine: Object.fromEntries(Object.keys(ENGINE_LABELS).map((e) => [e, 0])),
    pack: Object.fromEntries(Object.keys(PACK_LABELS).map((p) => [p, 0])),
  };
  for (const f of findings) {
    counts.severity[normalizeSeverity(f.severity)] += 1;
    for (const s of f.stride || []) if (s in counts.stride) counts.stride[s] += 1;
    for (const e of engineGroups(f)) counts.engine[e] += 1;
    counts.pack[packOf(f)] += 1;
  }
  return counts;
}

/** Findings in display order: by risk id when present (v2), otherwise by severity (v1). */
export function orderFindings(findings = []) {
  const rank = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
  return [...findings].sort((a, b) => {
    if (a.risk?.id && b.risk?.id) return a.risk.id.localeCompare(b.risk.id);
    return rank[normalizeSeverity(a.severity)] - rank[normalizeSeverity(b.severity)];
  });
}
