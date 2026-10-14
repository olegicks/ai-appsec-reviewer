import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';

const RESULT = {
  vulnerabilities: [
    {
      file: 'snippet.py',
      line: 'Line 12',
      vulnerability: 'SQL Injection',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      cwe: 'CWE-89',
      owasp: 'A03:2021',
      source: 'AI Analysis',
      risk_explanation: 'User input reaches a raw SQL query.',
      secure_code_snippet: 'cursor.execute("SELECT * FROM users WHERE name = ?", (username,))',
    },
    {
      file: 'snippet.py',
      line: 'Line 9',
      vulnerability: 'Debug mode enabled',
      severity: 'LOW',
      confidence: 'MEDIUM',
      cwe: 'CWE-489',
      owasp: 'A05:2021',
      source: 'Bandit',
      risk_explanation: 'Debug mode leaks stack traces.',
      secure_code_snippet: 'app.run(debug=False)',
    },
  ],
  summary: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 1, INFO: 0, TOTAL: 2 },
  meta: { mode: 'snippet', model: 'gpt-4o-mini', paranoia_level: 'standard', files_scanned: 1, duration_ms: 1800 },
};

function mockApi({ analyze = () => ({ ok: true, status: 200, json: async () => RESULT }) } = {}) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    if (String(url).endsWith('/health')) return { ok: true, status: 200, json: async () => ({ status: 'ok' }) };
    return analyze();
  });
}

describe('App', () => {
  beforeEach(() => {
    vi.useRealTimers();
  });

  it('renders the empty state and reports API status', async () => {
    mockApi();
    render(<App />);

    expect(screen.getByText('Ready to scan')).toBeInTheDocument();
    expect(await screen.findByText('API online')).toBeInTheDocument();
  });

  it('runs an analysis and renders findings sorted by severity', async () => {
    const fetchSpy = mockApi();
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole('button', { name: /run analysis/i }));

    const cards = await screen.findAllByRole('article');
    expect(cards).toHaveLength(2);
    expect(within(cards[0]).getByText('SQL Injection')).toBeInTheDocument();
    expect(screen.getByText(/1 file · 1.8s · gpt-4o-mini/)).toBeInTheDocument();

    const body = JSON.parse(fetchSpy.mock.calls.find(([url]) => url.endsWith('/analyze'))[1].body);
    expect(body).toMatchObject({ mode: 'snippet', language: 'python', paranoia_level: 'standard' });
  });

  it('filters findings by clicking a severity counter', async () => {
    mockApi();
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole('button', { name: /run analysis/i }));
    await screen.findAllByRole('article');

    await user.click(screen.getByTitle('Show low findings'));
    const cards = screen.getAllByRole('article');
    expect(cards).toHaveLength(1);
    expect(within(cards[0]).getByText('Debug mode enabled')).toBeInTheDocument();
  });

  it('expands and collapses a finding card', async () => {
    mockApi();
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole('button', { name: /run analysis/i }));
    const [, second] = await screen.findAllByRole('article');
    const toggle = within(second).getByRole('button', { expanded: false });

    await user.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
  });

  it('shows the server error message', async () => {
    mockApi({ analyze: () => ({ ok: false, status: 502, json: async () => ({ detail: 'AI engine request failed.' }) }) });
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole('button', { name: /run analysis/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent('AI engine request failed.');
  });

  it('shows a success message when nothing is found', async () => {
    mockApi({ analyze: () => ({ ok: true, status: 200, json: async () => ({ ...RESULT, vulnerabilities: [] }) }) });
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole('button', { name: /run analysis/i }));

    expect(await screen.findByText('No vulnerabilities detected')).toBeInTheDocument();
  });

  it('validates the repository URL before calling the API', async () => {
    const fetchSpy = mockApi();
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole('radio', { name: /repository/i }));
    await user.click(screen.getByRole('button', { name: /run analysis/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Enter a public GitHub repository URL.');
    expect(fetchSpy.mock.calls.some(([url]) => url.endsWith('/analyze'))).toBe(false);
  });

  it('loads an example into the editor', async () => {
    mockApi();
    const user = userEvent.setup();
    render(<App />);

    await user.selectOptions(screen.getByLabelText('Examples'), 'js-xss');

    expect(screen.getByLabelText('Code editor').value).toContain('innerHTML');
    expect(screen.getByLabelText('Language')).toHaveValue('javascript');
  });

  it('runs a scan with Ctrl+Enter', async () => {
    const fetchSpy = mockApi();
    const user = userEvent.setup();
    render(<App />);

    await user.keyboard('{Control>}{Enter}{/Control}');

    await waitFor(() => expect(fetchSpy.mock.calls.some(([url]) => url.endsWith('/analyze'))).toBe(true));
  });
});
