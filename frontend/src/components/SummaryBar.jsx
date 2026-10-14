import { useEffect, useState } from 'react';
import { SEVERITIES } from '../lib/severity';

function useCountUp(target, duration = 700) {
  const [value, setValue] = useState(0);

  useEffect(() => {
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    const total = reduced ? 0 : duration;
    let frame;
    const start = performance.now();
    const tick = (now) => {
      const t = total ? Math.min(1, (now - start) / total) : 1;
      setValue(Math.round(target * (1 - Math.pow(1 - t, 3))));
      if (t < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target, duration]);

  return value;
}

function Stat({ severity, count, active, onClick }) {
  const value = useCountUp(count);
  return (
    <button
      type="button"
      className={`stat sev-${severity.toLowerCase()} ${active ? 'active' : ''} ${count === 0 ? 'empty' : ''}`}
      onClick={onClick}
      aria-pressed={active}
      title={`Show ${severity.toLowerCase()} findings`}
    >
      <b>{value}</b>
      <span>{severity}</span>
    </button>
  );
}

export default function SummaryBar({ counts, filter, onFilter }) {
  return (
    <div className="summary">
      {SEVERITIES.map((s) => (
        <Stat
          key={s}
          severity={s}
          count={counts[s]}
          active={filter === s}
          onClick={() => onFilter(filter === s ? null : s)}
        />
      ))}
    </div>
  );
}
