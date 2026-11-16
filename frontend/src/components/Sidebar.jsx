import { Github, Moon, ShieldCheck, Sun } from 'lucide-react';
import { VIEWS } from '../lib/ui';

export default function Sidebar({ view, onNavigate, findingCount, theme, onToggleTheme }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">
          <ShieldCheck size={18} aria-hidden="true" />
        </div>
        <div>
          <b>AppSec Reviewer</b>
          <span>SAST · OT/ICS · AI triage</span>
        </div>
      </div>

      <nav className="nav" aria-label="Sections">
        {VIEWS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            className="nav-item"
            aria-current={view === id ? 'page' : undefined}
            aria-label={label}
            onClick={() => onNavigate(id)}
          >
            <Icon size={16} aria-hidden="true" />
            <span>{label}</span>
            {id === 'results' && findingCount !== null && <span className="nav-count">{findingCount}</span>}
          </button>
        ))}
      </nav>

      <div className="sidebar-foot">
        <button
          type="button"
          className="icon-btn"
          onClick={onToggleTheme}
          aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          title={theme === 'dark' ? 'Light theme' : 'Dark theme'}
        >
          {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
        </button>
        <a
          className="icon-btn"
          href="https://github.com/olegicks/ai-appsec-reviewer"
          target="_blank"
          rel="noreferrer"
          aria-label="Source code on GitHub"
        >
          <Github size={15} />
        </a>
      </div>
    </aside>
  );
}
