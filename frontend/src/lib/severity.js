export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

export function normalizeSeverity(sev) {
  const s = String(sev || '').trim().toUpperCase();
  return RANK[s] === undefined ? 'INFO' : s;
}

export function sortBySeverity(findings = []) {
  return [...findings].sort(
    (a, b) => RANK[normalizeSeverity(a.severity)] - RANK[normalizeSeverity(b.severity)],
  );
}

export function countBySeverity(findings = []) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of findings) counts[normalizeSeverity(f.severity)] += 1;
  return counts;
}

/** 0-100 risk score weighted by severity; used for the header gauge. */
export function riskScore(findings = []) {
  const weights = { CRITICAL: 40, HIGH: 20, MEDIUM: 8, LOW: 3, INFO: 0 };
  const total = findings.reduce((acc, f) => acc + weights[normalizeSeverity(f.severity)], 0);
  return Math.min(100, total);
}
