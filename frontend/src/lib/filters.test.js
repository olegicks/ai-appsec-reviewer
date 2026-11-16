import { describe, expect, it } from 'vitest';
import { V2_RESULT } from '../test/fixtures';
import { applyFilters, EMPTY_FILTERS, engineGroups, facetCounts, isFiltered, orderFindings, packOf, toggle } from './filters';

const findings = V2_RESULT.vulnerabilities;
const ids = (list) => list.map((f) => f.id);

describe('filters', () => {
  it('returns everything without filters', () => {
    expect(applyFilters(findings, EMPTY_FILTERS)).toHaveLength(3);
    expect(isFiltered(EMPTY_FILTERS)).toBe(false);
  });

  it('filters by STRIDE category, engine and rule pack', () => {
    expect(ids(applyFilters(findings, { ...EMPTY_FILTERS, stride: ['Spoofing'] }))).toEqual(['f-modbus']);
    expect(ids(applyFilters(findings, { ...EMPTY_FILTERS, engine: ['ai'] }))).toEqual(['f-sqli']);
    expect(ids(applyFilters(findings, { ...EMPTY_FILTERS, pack: ['deps', 'core'] }))).toEqual(['f-sqli', 'f-dep']);
  });

  it('combines facets with AND and values within a facet with OR', () => {
    const f = { ...EMPTY_FILTERS, severity: ['HIGH', 'MEDIUM'], stride: ['Information Disclosure'] };
    expect(ids(applyFilters(findings, f))).toEqual(['f-modbus', 'f-sqli']);
  });

  it('filters by a risk matrix cell', () => {
    expect(ids(applyFilters(findings, { ...EMPTY_FILTERS, cell: { likelihood: 3, impact: 3 } }))).toEqual(['f-sqli']);
  });

  it('derives engine groups for v1 findings from the source label', () => {
    expect(engineGroups({ source: 'Bandit / AI Analysis' })).toEqual(['bandit', 'ai']);
    expect(engineGroups({ source: '' })).toEqual(['ai']);
    expect(packOf({ pack: 'unknown' })).toBe('core');
  });

  it('counts facet values', () => {
    const counts = facetCounts(findings);
    expect(counts.severity).toMatchObject({ HIGH: 1, MEDIUM: 1, LOW: 1 });
    expect(counts.stride.Tampering).toBe(2);
    expect(counts.engine).toMatchObject({ rules: 1, bandit: 1, ai: 1, osv: 1 });
  });

  it('orders by risk id when present, otherwise by severity', () => {
    expect(ids(orderFindings([findings[2], findings[0], findings[1]]))).toEqual(['f-modbus', 'f-sqli', 'f-dep']);
    expect(orderFindings([{ severity: 'LOW' }, { severity: 'CRITICAL' }]).map((f) => f.severity)).toEqual(['CRITICAL', 'LOW']);
  });

  it('toggles values', () => {
    expect(toggle(['a'], 'b')).toEqual(['a', 'b']);
    expect(toggle(['a', 'b'], 'a')).toEqual(['b']);
  });
});
