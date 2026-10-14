import { describe, expect, it } from 'vitest';
import { buildHtmlReport, escapeHtml } from './report';

const finding = (overrides = {}) => ({
  file: 'app.js',
  line: 'Line 3',
  vulnerability: 'DOM XSS',
  severity: 'HIGH',
  confidence: 'HIGH',
  cwe: 'CWE-79',
  owasp: 'A03:2021',
  source: 'AI Analysis',
  risk_explanation: 'Untrusted data flows into innerHTML.',
  secure_code_snippet: 'el.textContent = name;',
  ...overrides,
});

describe('escapeHtml', () => {
  it('escapes all HTML-significant characters', () => {
    expect(escapeHtml(`<img src=x onerror="alert('1')">&`)).toBe(
      '&lt;img src=x onerror=&quot;alert(&#39;1&#39;)&quot;&gt;&amp;',
    );
  });

  it('handles nullish values', () => {
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
  });
});

describe('buildHtmlReport', () => {
  it('renders summary counts and findings sorted by severity', () => {
    const html = buildHtmlReport({
      findings: [finding({ severity: 'LOW', vulnerability: 'Weak hash' }), finding({ severity: 'CRITICAL', vulnerability: 'RCE' })],
      target: 'snippet.py',
    });

    expect(html).toContain('<title>Security Report - snippet.py</title>');
    expect(html.indexOf('RCE')).toBeLessThan(html.indexOf('Weak hash'));
    expect(html).toMatch(/<b>1<\/b><span>CRITICAL<\/span>/);
  });

  it('never injects raw markup from AI output', () => {
    const html = buildHtmlReport({
      findings: [finding({ vulnerability: '<script>alert(1)</script>', secure_code_snippet: '</pre><script>x()</script>' })],
      target: '<b>repo</b>',
    });

    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).toContain('&lt;b&gt;repo&lt;/b&gt;');
  });

  it('includes scan metadata when available', () => {
    const html = buildHtmlReport({
      findings: [],
      target: 'x',
      meta: { files_scanned: 4, paranoia_level: 'aggressive', model: 'gpt-4o-mini', duration_ms: 2500 },
    });

    expect(html).toContain('4 file(s) scanned');
    expect(html).toContain('2.5s');
    expect(html).toContain('No vulnerabilities detected');
  });
});
