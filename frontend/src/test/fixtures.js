// A v2 /analyze response (trimmed) used by component and integration tests.
const finding = (overrides) => ({
  file: 'gateway.py',
  line: 'Line 1',
  line_number: 1,
  vulnerability: 'Finding',
  title: 'Finding',
  severity: 'HIGH',
  confidence: 'HIGH',
  cwe: 'CWE-319',
  owasp: 'A02:2021',
  source: 'Rule engine',
  risk_explanation: 'Explanation.',
  secure_code_snippet: 'Fix it.',
  category: 'ot_ics',
  pack: 'ot_ics',
  engine: 'python_ast',
  engines: ['python_ast'],
  stride: ['Tampering'],
  excerpt: 'client = ModbusTcpClient(host)',
  references: [],
  ai_verdict: 'not_reviewed',
  compliance: { iec62443: ['FR3'], iso27001: ['A.8.24'] },
  ...overrides,
});

export const V2_RESULT = {
  vulnerabilities: [
    finding({
      id: 'f-modbus',
      rule_id: 'OT-001',
      title: 'Modbus/TCP without TLS',
      vulnerability: 'Modbus/TCP without TLS',
      line: 'Line 16',
      line_number: 16,
      stride: ['Spoofing', 'Tampering', 'Information Disclosure'],
      ai_verdict: 'confirmed',
      risk: { id: 'R-001', likelihood: 4, impact: 5, score: 20, band: 'Critical', factors: ['Exposure +1'] },
    }),
    finding({
      id: 'f-sqli',
      rule_id: 'B608',
      title: '<b>SQL</b> | injection',
      vulnerability: '<b>SQL</b> | injection',
      severity: 'MEDIUM',
      cwe: 'CWE-89',
      category: 'sast',
      pack: '',
      engine: 'bandit',
      engines: ['bandit', 'llm'],
      source: 'Bandit + AI Analysis',
      stride: ['Tampering', 'Information Disclosure'],
      line: 'Line 30',
      line_number: 30,
      risk: { id: 'R-002', likelihood: 3, impact: 3, score: 9, band: 'Medium', factors: [] },
    }),
    finding({
      id: 'f-dep',
      rule_id: 'DEP-001',
      title: 'Vulnerable dependency requests 2.19.0 (GHSA-x84v-xcm2-53pg)',
      vulnerability: 'Vulnerable dependency requests 2.19.0 (GHSA-x84v-xcm2-53pg)',
      severity: 'LOW',
      file: 'requirements.txt',
      cwe: 'CWE-1395',
      category: 'dependency',
      pack: 'deps',
      engine: 'deps',
      engines: ['deps'],
      source: 'OSV',
      stride: ['Elevation of Privilege'],
      dependency: { package: 'requests', version: '2.19.0', vuln_id: 'GHSA-x84v-xcm2-53pg', aliases: ['CVE-2018-18074'], fixed_version: '2.20.0' },
      risk: { id: 'R-003', likelihood: 3, impact: 2, score: 6, band: 'Medium', factors: [] },
    }),
  ],
  summary: { CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 1, INFO: 0, TOTAL: 3 },
  meta: {
    mode: 'snippet', model: 'test-model', paranoia_level: 'standard', files_scanned: 2, secrets_found: 0,
    sast_findings: 1, truncated: false, duration_ms: 2300, engines: ['bandit', 'deps', 'llm', 'rules', 'secrets'],
    ai_status: 'used', rule_findings: 2, config_files: [{ file: 'requirements.txt', kind: 'REQUIREMENTS' }],
  },
  risk_matrix: {
    formula: 'Risk = Likelihood x Impact',
    bands: { Low: '1-4', Medium: '5-9', High: '10-16', Critical: '20-25' },
    cells: [1, 2, 3, 4, 5].flatMap((l) =>
      [1, 2, 3, 4, 5].map((i) => {
        const score = l * i;
        const band = score >= 20 ? 'Critical' : score >= 10 ? 'High' : score >= 5 ? 'Medium' : 'Low';
        const ids = { '4-5': ['f-modbus'], '3-3': ['f-sqli'], '3-2': ['f-dep'] }[`${l}-${i}`] || [];
        return { likelihood: l, impact: i, score, band, findings: ids };
      }),
    ),
  },
  top_risks: ['f-modbus', 'f-sqli', 'f-dep'],
  stride_summary: { Spoofing: 1, Tampering: 2, Repudiation: 0, 'Information Disclosure': 2, 'Denial of Service': 0, 'Elevation of Privilege': 1 },
  compliance_summary: {
    disclaimer: 'Indicative mapping, not a certification or audit result.',
    iec62443: [
      { id: 'FR1', title: 'Identification and authentication control', findings: ['f-modbus'] },
      { id: 'FR3', title: 'System integrity', findings: ['f-modbus', 'f-sqli', 'f-dep'] },
      { id: 'FR7', title: 'Resource availability', findings: [] },
    ],
    iso27001: [
      { id: 'A.8.24', title: 'Use of cryptography', findings: ['f-modbus'] },
      { id: 'A.8.8', title: 'Management of technical vulnerabilities', findings: ['f-dep'] },
    ],
  },
  dependencies: { status: 'ok', source: 'OSV.dev', checked: 1, vulnerable: 1, note: '' },
};

export const NARRATIVE = {
  executive_summary: 'R-001 needs attention first.',
  mitigations: [{ risk_id: 'R-001', finding_id: 'f-modbus', title: 'Modbus/TCP without TLS', text: 'Use Modbus/TCP Security.' }],
  generated_by: 'ai',
  note: '',
  model: 'test-model',
};
