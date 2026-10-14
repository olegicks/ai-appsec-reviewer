import { useEffect, useState } from 'react';
import { CheckIcon } from './Icons';

const STEPS = {
  snippet: ['Validating input', 'Scanning for secrets', 'Running static analysis', 'AI security triage', 'Validating findings'],
  repo: [
    'Cloning repository',
    'Discovering source files',
    'Scanning for secrets',
    'Running static analysis',
    'AI security triage',
    'Validating findings',
  ],
};

// The API is a single request, so the steps advance on a timer and the last one
// stays active until the response arrives.
const STEP_MS = { snippet: 700, repo: 1400 };

export default function ScanProgress({ mode }) {
  const steps = STEPS[mode];
  const [active, setActive] = useState(0);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const stepTimer = setInterval(() => setActive((a) => Math.min(a + 1, steps.length - 1)), STEP_MS[mode]);
    const clock = setInterval(() => setElapsed((e) => e + 100), 100);
    return () => {
      clearInterval(stepTimer);
      clearInterval(clock);
    };
  }, [mode, steps.length]);

  return (
    <div className="scan-progress" aria-live="polite">
      <div className="radar" aria-hidden="true">
        <span className="radar-sweep" />
        <span className="radar-ring" />
        <span className="radar-ring delay" />
        <span className="radar-blip" />
      </div>

      <p className="scan-title">
        Running hybrid pipeline <span className="scan-timer">{(elapsed / 1000).toFixed(1)}s</span>
      </p>

      <ol className="steps">
        {steps.map((step, i) => {
          const state = i < active ? 'done' : i === active ? 'active' : 'pending';
          return (
            <li key={step} className={`step step-${state}`} style={{ '--i': i }}>
              <span className="step-marker">{state === 'done' ? <CheckIcon width={12} height={12} /> : i + 1}</span>
              {step}
            </li>
          );
        })}
      </ol>
      {mode === 'repo' && elapsed > 20000 && (
        <p className="muted small">Large repositories and a cold server can take up to a minute.</p>
      )}
    </div>
  );
}
