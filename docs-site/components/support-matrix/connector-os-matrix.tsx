import Link from 'next/link';
import { Activity } from 'lucide-react';
import { ConnectorBrand } from '@/components/connector-brand';
import {
  OS_IDS,
  supportMatrix,
  type ConnectorOsCell,
  type ConnectorRow,
  type Edition,
  type OsId,
  type Route,
} from '@/data/support-matrix';
import { EditionTabs } from './edition-tabs';
import { MatrixFooter } from './matrix-footer';
import { StatusBadge } from './status-badge';
import styles from './support-matrix.module.css';

const ROUTE_LABEL: Record<Route, string> = {
  'machine policy': 'Machine policy',
  'per-user': 'Per-user',
  unsupported: '',
};

function osHeader(os: OsId, edition: Edition) {
  const platform = supportMatrix.platforms[os];
  const sub =
    edition === 'enterprise'
      ? { linux: '.rpm', macos: '.pkg', windows: 'Setup.exe' }[os]
      : platform.arch;
  return (
    <>
      <span>{platform.label}</span>
      <span className={styles.thSub}>{sub}</span>
    </>
  );
}

function AgentCell({ row }: { row: ConnectorRow }) {
  return (
    <Link href={`/docs/connectors/${row.id}`} className={styles.agent}>
      <ConnectorBrand id={row.id} size="sm" />
      <span className={styles.agentText}>
        <span className={styles.agentName}>{row.label}</span>
        <span className={styles.agentSub}>{row.integration}</span>
      </span>
    </Link>
  );
}

// The badge says whether the agent's hooks and a pre-execution block were
// verified on that OS. A second line appears only when something is limited.
function OssCell({ cell }: { cell: ConnectorOsCell }) {
  const limited = cell.status !== 'unsupported' && (cell.observability !== 'supported' || !cell.block);
  return (
    <div className={styles.cell}>
      <StatusBadge status={cell.status} />
      {limited ? (
        <span className={styles.facts}>
          {!cell.block ? <span className={styles.fact}>Observe only</span> : null}
          {cell.observability !== 'supported' ? (
            <span className={styles.fact} data-status={cell.observability}>
              <Activity aria-hidden className={styles.factIcon} />
              Telemetry: preview
            </span>
          ) : null}
        </span>
      ) : null}
    </div>
  );
}

function EnterpriseCell({ cell }: { cell: ConnectorRow['enterprise'][OsId] }) {
  return (
    <div className={styles.cell}>
      <StatusBadge status={cell.status} />
      {cell.route !== 'unsupported' ? <span className={styles.fact}>{ROUTE_LABEL[cell.route]}</span> : null}
    </div>
  );
}

function Version({ row }: { row: ConnectorRow }) {
  return (
    <Link href="/docs/connectors/compatibility" className={styles.version}>
      {row.minVersion}
    </Link>
  );
}

function MatrixView({ edition }: { edition: Edition }) {
  const rows = supportMatrix.connectors;
  return (
    <>
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <caption className={styles.srOnly}>
            {edition === 'oss'
              ? 'AI coding agents by operating system, open-source edition'
              : 'AI coding agents by operating system, enterprise edition, with the route DefenseClaw uses'}
          </caption>
          <thead>
            <tr>
              <th scope="col">Agent</th>
              {OS_IDS.map((os) => (
                <th key={os} scope="col">
                  {osHeader(os, edition)}
                </th>
              ))}
              {edition === 'oss' ? (
                <th scope="col">
                  <span>Min version</span>
                  <span className={styles.thSub}>lowest tested</span>
                </th>
              ) : null}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <th scope="row">
                  <AgentCell row={row} />
                </th>
                {OS_IDS.map((os) => (
                  <td key={os}>
                    {edition === 'oss' ? <OssCell cell={row.oss[os]} /> : <EnterpriseCell cell={row.enterprise[os]} />}
                  </td>
                ))}
                {edition === 'oss' ? (
                  <td>
                    <Version row={row} />
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ul className={styles.cards} aria-label={edition === 'oss' ? 'Agents, open source' : 'Agents, enterprise'}>
        {rows.map((row) => (
          <li key={row.id} className={styles.card}>
            <div className={styles.cardHead}>
              <AgentCell row={row} />
              {edition === 'oss' ? <Version row={row} /> : null}
            </div>
            <dl className={styles.cardRows}>
              {OS_IDS.map((os) => (
                <div key={os} className={styles.cardRow}>
                  <dt>{supportMatrix.platforms[os].label}</dt>
                  <dd>
                    {edition === 'oss' ? <OssCell cell={row.oss[os]} /> : <EnterpriseCell cell={row.enterprise[os]} />}
                  </dd>
                </div>
              ))}
            </dl>
          </li>
        ))}
      </ul>
    </>
  );
}

function Notes({ edition }: { edition: Edition }) {
  const items = supportMatrix.connectors
    .map((row) => {
      const parts: string[] = [];
      if (edition === 'oss') {
        if (row.versionNote) parts.push(row.versionNote);
        for (const os of OS_IDS) {
          const note = row.oss[os].note;
          if (note) parts.push(`${supportMatrix.platforms[os].label}: ${note}`);
        }
      } else if (row.routeNote) {
        parts.push(row.routeNote);
      }
      return { row, parts };
    })
    .filter((item) => item.parts.length > 0);
  if (items.length === 0) return null;
  return (
    <details className={styles.notes}>
      <summary>{edition === 'oss' ? 'Version and platform notes' : 'Route notes'}</summary>
      <dl>
        {items.map(({ row, parts }) => (
          <div key={row.id} className={styles.noteRow}>
            <dt>{row.label}</dt>
            <dd>{parts.join(' ')}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

interface ConnectorOsMatrixProps {
  // Fix the view to one edition; by default readers can switch.
  edition?: Edition;
  showNotes?: boolean;
}

export function ConnectorOsMatrix({ edition, showNotes = true }: ConnectorOsMatrixProps) {
  const view = (which: Edition) => (
    <>
      <MatrixView edition={which} />
      {showNotes ? <Notes edition={which} /> : null}
      <MatrixFooter edition={which} />
    </>
  );
  return (
    <div className={`not-prose ${styles.matrix}`}>
      {edition ? view(edition) : <EditionTabs label="Edition" oss={view('oss')} enterprise={view('enterprise')} />}
    </div>
  );
}
