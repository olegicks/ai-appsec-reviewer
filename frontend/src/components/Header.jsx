import { GithubIcon, ShieldIcon } from './Icons';

const STATUS_LABEL = {
  checking: 'Connecting',
  online: 'API online',
  waking: 'Waking server',
  offline: 'API offline',
};

export default function Header({ apiStatus }) {
  return (
    <header className="header">
      <div className="brand">
        <div className="brand-logo">
          <ShieldIcon width={22} height={22} />
        </div>
        <div>
          <h1>
            AppSec <span className="gradient-text">Code Reviewer</span>
          </h1>
          <p>Hybrid SAST + AI security analysis pipeline</p>
        </div>
      </div>

      <div className="header-actions">
        <span className={`status-pill status-${apiStatus}`} role="status">
          <span className="status-dot" />
          {STATUS_LABEL[apiStatus]}
        </span>
        <a
          className="icon-link"
          href="https://github.com/olegicks/ai-appsec-reviewer"
          target="_blank"
          rel="noreferrer"
          aria-label="Source code on GitHub"
        >
          <GithubIcon width={18} height={18} />
        </a>
      </div>
    </header>
  );
}
