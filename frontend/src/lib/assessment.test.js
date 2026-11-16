import { describe, expect, it } from 'vitest';
import { NARRATIVE, V2_RESULT } from '../test/fixtures';
import { buildAssessment, DISCLAIMER, mdEscape, renderAssessmentHtml, renderAssessmentMarkdown } from './assessment';

const generatedAt = new Date('2026-11-16T10:00:00Z');
const model = buildAssessment({ result: V2_RESULT, narrative: NARRATIVE, target: '<repo>', generatedAt });

describe('buildAssessment', () => {
  it('collects counts, top risks with AI mitigations and STRIDE groups', () => {
    expect(model.total).toBe(3);
    expect(model.top[0].finding.id).toBe('f-modbus');
    expect(model.top[0].mitigation).toBe('Use Modbus/TCP Security.');
    expect(model.top[1].mitigation).toBe('Fix it.'); // falls back to the rule remediation
    expect(model.stride.find((s) => s.category === 'Tampering').findings).toHaveLength(2);
    expect(model.dependencyFindings).toHaveLength(1);
  });

  it('works without a narrative', () => {
    const plain = buildAssessment({ result: V2_RESULT, narrative: null, target: 'x', generatedAt });
    expect(plain.summary).toBe('');
    expect(plain.summarySource).toBe('none');
  });
});

describe('renderAssessmentHtml', () => {
  const html = renderAssessmentHtml(model);

  it('contains all nine sections and the indicative disclaimer', () => {
    for (const heading of [
      '1. Executive summary', '2. Scope and method', '3. Risk matrix', '4. Top risks and mitigations',
      '5. Findings by STRIDE category', '6. Indicative IEC 62443 / ISO 27001 mapping',
      '7. Dependency and configuration results', '8. Limitations', '9. Appendix: all findings',
    ]) {
      expect(html).toContain(heading);
    }
    expect(html).toContain(DISCLAIMER);
    expect(html).toContain('2026-11-16');
  });

  it('escapes every value', () => {
    expect(html).not.toContain('<b>SQL</b>');
    expect(html).toContain('&lt;b&gt;SQL&lt;/b&gt;');
    expect(html).toContain('&lt;repo&gt;');
  });

  it('is print friendly', () => {
    expect(html).toContain('@media print');
  });
});

describe('renderAssessmentMarkdown', () => {
  const md = renderAssessmentMarkdown(model);

  it('renders sections, tables and the disclaimer', () => {
    expect(md).toMatch(/^# Security Assessment Report/);
    expect(md).toContain('## 9. Appendix: all findings');
    expect(md).toContain(`> **${DISCLAIMER}**`);
    expect(md).toContain('| CRITICAL | HIGH | MEDIUM | LOW | INFO |');
  });

  it('escapes table-breaking characters and HTML', () => {
    expect(md).toContain('&lt;b&gt;SQL&lt;/b&gt; \\| injection');
    expect(mdEscape('a|b\nc')).toBe('a\\|b c');
  });
});
