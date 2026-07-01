import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { ConnectorBrand } from '@/components/connector-brand';
import matrix from '@/data/capability-matrix.json';

const ORDER = [
  'openclaw',
  'zeptoclaw',
  'claudecode',
  'codex',
  'cursor',
  'windsurf',
  'geminicli',
  'copilot',
  'openhands',
  'antigravity',
  'hermes',
  'opencode',
  'omnigent',
];

const SUMMARIES: Record<string, string> = {
  openclaw: 'Reference proxy with bundled fetch interception and before-tool-call enforcement.',
  zeptoclaw: 'API base redirect through the DefenseClaw proxy with response scanning.',
  claudecode: 'Native lifecycle hooks, native approval, and OpenTelemetry export.',
  codex: 'Config hooks, native OpenTelemetry, and an agent-turn completion bridge.',
  cursor: 'Pre-execution shell and MCP hooks with native ask support.',
  windsurf: 'Cascade hooks across prompts, commands, code access, and MCP tools.',
  geminicli: 'Settings hooks with a native OTLP exporter pointed at the gateway.',
  copilot: 'Global or workspace hooks with native approval on pre-tool-use.',
  openhands: 'Global command hooks with optional workspace-local discovery surfaces.',
  antigravity: 'Five lifecycle hooks with an unbypassable native ask decision.',
  hermes: 'Configuration hooks across the Hermes agent runtime lifecycle.',
  opencode: 'Auto-loaded bridge plugin with tool-execution blocking.',
  omnigent: 'Custom policy bridge with allow, ask, and deny enforcement.',
};

const connectors = new Map(matrix.connectors.map((connector) => [connector.id, connector]));

export function ConnectorCatalog() {
  return (
    <div className="connector-catalog not-prose">
      {ORDER.map((id) => {
        const connector = connectors.get(id);
        if (!connector) return null;
        return (
          <Link className="connector-catalog-item" href={`/docs/connectors/${id}`} key={id}>
            <ConnectorBrand id={id} />
            <span className="connector-catalog-copy">
              <strong>{connector.label}</strong>
              <span>{SUMMARIES[id]}</span>
            </span>
            <ArrowRight aria-hidden />
          </Link>
        );
      })}
    </div>
  );
}
