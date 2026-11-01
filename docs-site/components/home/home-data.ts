import matrix from '@/data/capability-matrix.json';
import type { OsId } from '@/data/downloads';
import { connectorById } from '@/data/support-matrix';

/**
 * Landing-page connector facts, derived from data/capability-matrix.json so
 * the count and names can't drift from the connector pages.
 *
 * Proxy-family connectors (OpenClaw, ZeptoClaw) are not featured on the
 * landing page; everything else in the matrix is a hook connector.
 */

export type OsStatus = 'supported' | 'preview' | 'unsupported';

export interface HomeConnector {
  id: string;
  label: string;
  short: string;
  os: Record<OsId, OsStatus>;
  windowsNote: string;
}

// Display order: most-installed agents first (matches the docs connector nav).
const ORDER = [
  'claudecode', 'codex', 'copilot', 'cursor', 'devin', 'antigravity',
  'kiro', 'opencode', 'amp', 'hermes',
];

const SHORT: Record<string, string> = { copilot: 'Copilot' };

function displayedStatus(value: string): OsStatus {
  if (value === 'supported') return 'supported';
  if (value === 'unsupported') return 'unsupported';
  // A preview or an unlisted cell does not claim live certification.
  return 'preview';
}

const rank = (id: string) => {
  const index = ORDER.indexOf(id);
  return index === -1 ? ORDER.length : index;
};

export const HOME_CONNECTORS: HomeConnector[] = matrix.connectors
  .filter((connector) => connector.family !== 'proxy')
  .sort((a, b) => rank(a.id) - rank(b.id))
  .map((connector) => {
    const support = connectorById(connector.id);
    return {
      id: connector.id,
      label: connector.label,
      short: SHORT[connector.id] ?? connector.label,
      os: {
        linux: displayedStatus(support?.oss.linux.status ?? 'preview'),
        macos: displayedStatus(support?.oss.macos.status ?? 'preview'),
        windows: displayedStatus(support?.oss.windows.status ?? connector.windowsSupport),
      },
      windowsNote: connector.windowsNote,
    };
  });

export const AGENT_COUNT = HOME_CONNECTORS.length;

/** "Claude Code, Codex, Copilot, Cursor and 8 more". */
export function agentSummary(named = 4) {
  const names = HOME_CONNECTORS.slice(0, named).map((connector) => connector.short);
  const rest = AGENT_COUNT - names.length;
  return rest > 0 ? `${names.join(', ')} and ${rest} more` : names.join(', ');
}
