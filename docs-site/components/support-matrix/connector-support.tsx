import Link from 'next/link';
import { CircleCheck, CircleDashed, CircleSlash } from 'lucide-react';
import { OS_IDS, connectorById, supportMatrix, STATUS_LABEL, type OsId, type Route, type Status } from '@/data/support-matrix';
import styles from './support-matrix.module.css';

const ICONS = { supported: CircleCheck, preview: CircleDashed, unsupported: CircleSlash } as const;

function OsChip({ os, status }: { os: OsId; status: Status }) {
  const shown = status === 'not-offered' ? 'unsupported' : status;
  const Icon = ICONS[shown];
  const label = supportMatrix.platforms[os].label;
  const suffix = shown === 'supported' ? '' : shown === 'preview' ? ' (preview)' : ': not supported';
  return (
    <span className={styles.chip} data-status={shown} title={`${label}: ${STATUS_LABEL[status]}`}>
      <Icon aria-hidden className={styles.badgeIcon} strokeWidth={2.25} />
      <span>
        {label}
        {suffix}
      </span>
      {shown === 'supported' ? <span className={styles.srOnly}>: supported</span> : null}
    </span>
  );
}

function joinOs(list: OsId[]) {
  const names = list.map((os) => supportMatrix.platforms[os].label);
  if (names.length <= 1) return names.join('');
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

function enterpriseSummary(id: string) {
  const row = connectorById(id);
  if (!row) return '';
  const byRoute = new Map<Route, OsId[]>();
  for (const os of OS_IDS) {
    const route = row.enterprise[os].route;
    if (route === 'unsupported') continue;
    byRoute.set(route, [...(byRoute.get(route) ?? []), os]);
  }
  if (byRoute.size === 0) return 'not supported';
  const parts = [...byRoute.entries()].map(([route, list]) =>
    list.length === OS_IDS.length ? route : `${route} on ${joinOs(list)}`,
  );
  const routed = OS_IDS.filter((os) => row.enterprise[os].route !== 'unsupported');
  const preview = routed.filter((os) => row.enterprise[os].status === 'preview');
  if (preview.length === 0) return parts.join('; ');
  // Every routed OS is a preview: say so once instead of repeating the OS list.
  if (preview.length === routed.length) return `${parts.join('; ')}, preview`;
  return `${parts.join('; ')} (preview on ${joinOs(preview)})`;
}

// One-line support strip for the top of a connector page's "Platform
// support" section. Reads the same data as /docs/support-matrix.
export function ConnectorSupport({ id }: { id: string }) {
  const row = connectorById(id);
  if (!row) throw new Error(`ConnectorSupport: unknown connector ${id}`);
  return (
    <div className={`not-prose ${styles.strip}`} role="group" aria-label={`${row.label} support summary`}>
      <div className={styles.stripOs}>
        {OS_IDS.map((os) => (
          <OsChip key={os} os={os} status={row.oss[os].status} />
        ))}
      </div>
      <dl className={styles.stripFacts}>
        <div>
          <dt>Min version</dt>
          <dd>
            <Link href="/docs/connectors/compatibility" className={styles.version}>
              {row.minVersion}
            </Link>
          </dd>
        </div>
        <div>
          <dt>Block</dt>
          <dd>{row.oss.linux.block ? 'Yes' : 'No'}</dd>
        </div>
        <div>
          <dt>Native ask</dt>
          <dd>{row.canAskNative ? 'Yes' : 'No'}</dd>
        </div>
        <div>
          <dt>Fail closed</dt>
          <dd>{row.supportsFailClosed ? 'Yes' : 'No'}</dd>
        </div>
        <div>
          <dt>Enterprise</dt>
          <dd>{enterpriseSummary(id)}</dd>
        </div>
      </dl>
      <Link href="/docs/support-matrix" className={styles.stripLink}>
        Support matrix <span aria-hidden>→</span>
      </Link>
    </div>
  );
}
