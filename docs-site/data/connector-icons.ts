export interface ConnectorIconDefinition {
  source: string;
  target: string;
  accent: string;
  monochrome?: boolean;
}

export const connectorIconDefinitions: Record<string, ConnectorIconDefinition> = {
  amp: { source: 'amp-color.svg', target: 'amp.svg', accent: '#f34e3f' },
  antigravity: { source: 'antigravity-color.svg', target: 'antigravity.svg', accent: '#7767e8' },
  claudecode: { source: 'claudecode-color.svg', target: 'claudecode.svg', accent: '#d97757' },
  codex: { source: 'codex-color.svg', target: 'codex.svg', accent: '#10a37f' },
  copilot: { source: 'githubcopilot.svg', target: 'copilot.svg', accent: '#7657d6', monochrome: true },
  cursor: { source: 'cursor.svg', target: 'cursor.svg', accent: '#57636d', monochrome: true },
  devin: { source: 'devin.svg', target: 'devin.svg', accent: '#0f172a', monochrome: true },
  hermes: { source: 'hermesagent.svg', target: 'hermes.svg', accent: '#ad7a1f', monochrome: true },
  openclaw: { source: 'openclaw-color.svg', target: 'openclaw.svg', accent: '#ff4d4d' },
  opencode: { source: 'opencode.svg', target: 'opencode.svg', accent: '#52616b', monochrome: true },
  openhands: { source: 'openhands-color.svg', target: 'openhands.svg', accent: '#16a34a' },
};
