import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import ResultsView from './components/ResultsView';
import EvaluationView from './components/EvaluationView';
import { EMPTY_FILTERS } from './lib/filters';
import { NARRATIVE, V2_RESULT } from './test/fixtures';

function mockApi() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    const path = String(url);
    if (path.endsWith('/health')) return { ok: true, status: 200, json: async () => ({ status: 'ok' }) };
    if (path.endsWith('/report')) return { ok: true, status: 200, json: async () => NARRATIVE };
    return { ok: true, status: 200, json: async () => V2_RESULT };
  });
}

async function scanned() {
  const fetchSpy = mockApi();
  const user = userEvent.setup();
  render(<App />);
  await user.click(screen.getByRole('button', { name: /run analysis/i }));
  await screen.findAllByRole('article');
  return { user, fetchSpy };
}

const nav = (name) => screen.getByRole('button', { name, exact: true });

describe('v2 workspace', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('shows scan metadata and a findings count in the navigation', async () => {
    await scanned();

    const meta = screen.getByLabelText('Last scan');
    expect(meta).toHaveTextContent('snippet.py');
    expect(meta).toHaveTextContent('2.3 s');
    expect(within(nav('Results')).getByText('3')).toBeInTheDocument();
  });

  it('filters results by STRIDE, engine and rule pack chips', async () => {
    const { user } = await scanned();

    await user.click(within(screen.getByRole('group', { name: 'Filter by STRIDE' })).getByRole('button', { name: /Spoofing/ }));
    expect(screen.getAllByRole('article')).toHaveLength(1);

    await user.click(screen.getByRole('button', { name: /clear filters/i }));
    await user.click(within(screen.getByRole('group', { name: 'Filter by Rule pack' })).getByRole('button', { name: /Dependencies/ }));
    const [card] = screen.getAllByRole('article');
    expect(card).toHaveTextContent('requests 2.19.0');
  });

  it('expands rule metadata, AI verdict and dependency details on a card', async () => {
    await scanned();
    const [first] = screen.getAllByRole('article');

    expect(within(first).getByText('OT-001')).toBeInTheDocument();
    expect(within(first).getByText('AI confirmed')).toBeInTheDocument();
    expect(within(first).getByText('R-001 · 20')).toBeInTheDocument();
  });

  it('lists findings when hovering a heatmap cell and filters results on click', async () => {
    const { user } = await scanned();
    await user.click(nav('Risk'));

    const cell = screen.getByRole('gridcell', { name: /Likelihood 3, impact 3/ });
    await user.hover(cell);
    expect(screen.getByText('L3 × I3 = 9 · Medium')).toBeInTheDocument();

    await user.click(cell);
    expect(screen.getAllByRole('article')).toHaveLength(1);
    expect(screen.getByText(/risk cell L3 × I3/)).toBeInTheDocument();
  });

  it('empty heatmap cells are disabled', async () => {
    const { user } = await scanned();
    await user.click(nav('Risk'));
    expect(screen.getByRole('gridcell', { name: /Likelihood 1, impact 1/ })).toBeDisabled();
  });

  it('opens a top risk in the results list', async () => {
    const { user } = await scanned();
    await user.click(nav('Risk'));

    await user.click(screen.getByRole('button', { name: /SQL.*injection/ }));

    const focused = document.querySelector('article.focused');
    expect(focused).toHaveTextContent('B608');
    expect(within(focused).getByRole('button', { expanded: true })).toBeInTheDocument();
  });

  it('shows the compliance tables with the indicative label', async () => {
    const { user } = await scanned();
    await user.click(nav('Compliance'));

    expect(screen.getByText('Indicative mapping, not a certification or audit result.')).toBeInTheDocument();
    const fr3 = screen.getByText('System integrity').closest('tr');
    expect(within(fr3).getByText('3')).toBeInTheDocument();
  });

  it('requests the report narrative once and exports HTML and Markdown', async () => {
    const { user, fetchSpy } = await scanned();
    const blobs = [];
    globalThis.URL.createObjectURL = vi.fn((blob) => {
      blobs.push(blob);
      return 'blob:x';
    });
    globalThis.URL.revokeObjectURL = vi.fn();

    await user.click(nav('Report'));
    expect(await screen.findByText('R-001 needs attention first.')).toBeInTheDocument();
    await user.click(nav('Results'));
    await user.click(nav('Report'));
    expect(fetchSpy.mock.calls.filter(([u]) => String(u).endsWith('/report'))).toHaveLength(1);

    await user.click(screen.getByRole('button', { name: 'HTML' }));
    await user.click(screen.getByRole('button', { name: 'Markdown' }));

    const [html, md] = await Promise.all(blobs.map((b) => b.text()));
    expect(html).toContain('Security Assessment Report');
    expect(html).toContain('R-001 needs attention first.');
    expect(md).toContain('## 4. Top risks and mitigations');
    expect(md).toContain('Use Modbus/TCP Security.');
  });

  it('sends config snippets with the config language', async () => {
    const fetchSpy = mockApi();
    const user = userEvent.setup();
    render(<App />);

    await user.click(screen.getByRole('radio', { name: /config/i }));
    await user.selectOptions(screen.getByLabelText('Examples'), 'dockerfile');
    await user.click(screen.getByRole('button', { name: /run analysis/i }));

    await waitFor(() => expect(fetchSpy.mock.calls.some(([u]) => String(u).endsWith('/analyze'))).toBe(true));
    const body = JSON.parse(fetchSpy.mock.calls.find(([u]) => String(u).endsWith('/analyze'))[1].body);
    expect(body).toMatchObject({ mode: 'snippet', language: 'config' });
    expect(body.code).toContain('FROM python:latest');
  });

  it('offers the fictional smart grid sample', () => {
    mockApi();
    render(<App />);
    expect(screen.getByRole('option', { name: /Smart grid gateway \(fictional\)/ })).toBeInTheDocument();
  });

  it('toggles and remembers the theme', async () => {
    mockApi();
    const user = userEvent.setup();
    render(<App />);
    expect(document.documentElement.dataset.theme).toBe('dark');

    await user.click(screen.getByRole('button', { name: 'Switch to light theme' }));

    expect(document.documentElement.dataset.theme).toBe('light');
    expect(localStorage.getItem('appsec-theme')).toBe('light');
  });
});

describe('reduced motion', () => {
  let original;
  beforeEach(() => {
    original = window.matchMedia;
  });
  afterEach(() => {
    window.matchMedia = original;
  });

  const renderCounters = () =>
    render(<ResultsView result={V2_RESULT} filters={EMPTY_FILTERS} onFiltersChange={() => {}} onExport={() => {}} onNavigate={() => {}} />);

  it('shows final counter values immediately when the user prefers reduced motion', () => {
    window.matchMedia = () => ({ matches: true, addEventListener() {}, removeEventListener() {} });
    renderCounters();
    expect(within(screen.getByTitle('Show high findings')).getByText('1')).toBeInTheDocument();
  });

  it('animates counters from zero otherwise', async () => {
    window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
    vi.useFakeTimers({ toFake: ['requestAnimationFrame', 'cancelAnimationFrame', 'performance'] });
    try {
      renderCounters();
      expect(within(screen.getByTitle('Show high findings')).getByText('0')).toBeInTheDocument();
      await act(async () => {
        vi.advanceTimersByTime(1000);
      });
      expect(within(screen.getByTitle('Show high findings')).getByText('1')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('EvaluationView', () => {
  it('shows measured engines and never invents numbers for unmeasured ones', () => {
    render(
      <EvaluationView
        data={{
          generated_at: '2026-11-16',
          line_tolerance: 2,
          engines: {
            rules: { engine: 'rules', status: 'ok', samples: 51, precision: 1, recall: 0.8, f1: 0.889, fp_rate_safe: 0, by_category: { ot: { recall: 1 } } },
            llm: { engine: 'llm', status: 'not_run', by_category: {} },
          },
        }}
      />,
    );
    expect(screen.getByText('0.80')).toBeInTheDocument();
    expect(screen.getByText(/Not measured yet/)).toBeInTheDocument();
  });
});

it('keyboard users can operate the heatmap', async () => {
  mockApi();
  const user = userEvent.setup();
  render(<App />);
  await user.click(screen.getByRole('button', { name: /run analysis/i }));
  await screen.findAllByRole('article');
  fireEvent.click(nav('Risk'));
  const cell = screen.getByRole('gridcell', { name: /Likelihood 4, impact 5/ });
  act(() => cell.focus());
  expect(screen.getByText('L4 × I5 = 20 · Critical')).toBeInTheDocument();
});
