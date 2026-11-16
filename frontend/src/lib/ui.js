import { FileText, FlaskConical, Grid3x3, ListChecks, Scale, ScanLine } from 'lucide-react';
import { normalizeSeverity } from './severity';

export const VIEWS = [
  { id: 'scan', label: 'Scan', icon: ScanLine },
  { id: 'results', label: 'Results', icon: ListChecks },
  { id: 'risk', label: 'Risk', icon: Grid3x3 },
  { id: 'compliance', label: 'Compliance', icon: Scale },
  { id: 'report', label: 'Report', icon: FileText },
  { id: 'evaluation', label: 'Evaluation', icon: FlaskConical },
];

export const STAGES = ['Redaction', 'SAST', 'Rules', 'Dependencies', 'AI triage', 'Risk scoring'];

// Server-side configuration problems (missing key, deprecated model, quota) - not the user's input.
export const AI_CONFIG_ERRORS = new Set([
  'ai_not_configured',
  'model_unavailable',
  'model_access_denied',
  'model_parameter_unsupported',
  'ai_auth_failed',
  'ai_quota_exceeded',
]);

export function sevClass(severity) {
  return `sev-${normalizeSeverity(severity).toLowerCase()}`;
}
