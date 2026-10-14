import { RepoIcon } from './Icons';

const SUGGESTIONS = ['https://github.com/olegicks/ai-appsec-reviewer', 'https://github.com/OWASP/NodeGoat'];

export default function RepoPanel({ repoUrl, onChange, onSubmit }) {
  return (
    <div className="repo-panel">
      <div className="repo-icon">
        <RepoIcon width={28} height={28} />
      </div>
      <h3>Scan a public GitHub repository</h3>
      <p className="muted">
        The repository is shallow-cloned into an isolated sandbox. Secrets are redacted before anything reaches the AI.
      </p>

      <form
        className="repo-form"
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit();
        }}
      >
        <input
          type="url"
          aria-label="Repository URL"
          placeholder="https://github.com/owner/repo"
          value={repoUrl}
          onChange={(e) => onChange(e.target.value)}
          spellCheck={false}
          autoComplete="off"
        />
      </form>

      <div className="repo-suggestions">
        <span className="muted">Try:</span>
        {SUGGESTIONS.map((url) => (
          <button key={url} type="button" className="chip" onClick={() => onChange(url)}>
            {url.replace('https://github.com/', '')}
          </button>
        ))}
      </div>

      <ul className="repo-limits">
        <li>
          <b>20</b> source files max
        </li>
        <li>
          <b>30 KB</b> per file
        </li>
        <li>
          <b>60K</b> chars of AI context
        </li>
      </ul>
    </div>
  );
}
