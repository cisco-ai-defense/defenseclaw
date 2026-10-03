import Link from 'next/link';
import { Check, CircleDashed, Minus } from 'lucide-react';
import { ConnectorBrand } from '@/components/connector-brand';
import { HOME_CONNECTORS, type OsStatus } from './home-data';
import styles from './home.module.css';

const OS_LABELS = [
  ['linux', 'Linux'],
  ['macos', 'macOS'],
  ['windows', 'Windows'],
] as const;

const STATUS_TEXT: Record<OsStatus, string> = {
  supported: 'supported',
  preview: 'preview',
  unsupported: 'not supported',
};

function StatusIcon({ status }: { status: OsStatus }) {
  if (status === 'supported') return <Check aria-hidden />;
  if (status === 'preview') return <CircleDashed aria-hidden />;
  return <Minus aria-hidden />;
}

/** Logo grid of the hook connectors with per-OS marks. */
export function ConnectorGrid() {
  return (
    <ul className={styles.agents} aria-label="Supported AI agents">
      {HOME_CONNECTORS.map((connector) => (
        <li key={connector.id}>
          <Link href={`/docs/connectors/${connector.id}`} className={styles.agent}>
            <ConnectorBrand id={connector.id} />
            <span className={styles.agentName}>{connector.label}</span>
            <ul className={styles.agentOs}>
              {OS_LABELS.map(([os, label]) => {
                const status = connector.os[os];
                return (
                  <li
                    key={os}
                    data-status={status}
                    title={os === 'windows' && status !== 'supported' ? connector.windowsNote : `${label}: ${STATUS_TEXT[status]}`}
                  >
                    <StatusIcon status={status} />
                    <span>{label}</span>
                    <span className={styles.srOnly}>: {STATUS_TEXT[status]}</span>
                  </li>
                );
              })}
            </ul>
          </Link>
        </li>
      ))}
    </ul>
  );
}

export function ConnectorLegend() {
  return (
    <p className={styles.legend}>
      <span data-status="supported"><Check aria-hidden /> Supported</span>
      <span data-status="preview"><CircleDashed aria-hidden /> Preview</span>
      <span data-status="unsupported"><Minus aria-hidden /> Not supported</span>
    </p>
  );
}
