import { describe, expect, it } from 'vitest';
import { countBySeverity, normalizeSeverity, riskScore, sortBySeverity } from './severity';

describe('severity helpers', () => {
  it('normalizes case and unknown values', () => {
    expect(normalizeSeverity('high')).toBe('HIGH');
    expect(normalizeSeverity(' Critical ')).toBe('CRITICAL');
    expect(normalizeSeverity('whatever')).toBe('INFO');
    expect(normalizeSeverity(undefined)).toBe('INFO');
  });

  it('sorts findings from critical to info without mutating input', () => {
    const input = [{ severity: 'LOW' }, { severity: 'critical' }, { severity: 'MEDIUM' }, { severity: 'INFO' }];
    const sorted = sortBySeverity(input);

    expect(sorted.map((f) => f.severity)).toEqual(['critical', 'MEDIUM', 'LOW', 'INFO']);
    expect(input[0].severity).toBe('LOW');
  });

  it('counts findings per severity', () => {
    const counts = countBySeverity([{ severity: 'HIGH' }, { severity: 'high' }, { severity: 'LOW' }]);
    expect(counts).toEqual({ CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 1, INFO: 0 });
  });

  it('caps the risk score at 100', () => {
    expect(riskScore([])).toBe(0);
    expect(riskScore([{ severity: 'HIGH' }, { severity: 'LOW' }])).toBe(23);
    expect(riskScore(Array(5).fill({ severity: 'CRITICAL' }))).toBe(100);
  });
});
