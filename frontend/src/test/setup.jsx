import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, vi } from 'vitest';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

// Monaco needs a real browser; a textarea is enough to exercise the app logic.
vi.mock('@monaco-editor/react', () => ({
  default: ({ value, onChange }) => (
    <textarea aria-label="Code editor" value={value} onChange={(e) => onChange(e.target.value)} />
  ),
}));

if (!window.matchMedia) {
  window.matchMedia = () => ({ matches: true, addEventListener() {}, removeEventListener() {} });
}
