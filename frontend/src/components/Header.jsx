import { GithubIcon, ShieldIcon } from './Icons';

export default function Header() {
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
