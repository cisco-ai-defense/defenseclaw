import { CircleCheck, CircleDashed, CircleSlash, Minus } from 'lucide-react';
import { STATUS_LABEL, type Status } from '@/data/support-matrix';
import styles from './support-matrix.module.css';

const ICONS = {
  supported: CircleCheck,
  preview: CircleDashed,
  unsupported: CircleSlash,
  'not-offered': Minus,
} as const;

// Short labels for dense tables; the legend explains them.
const COMPACT_LABEL: Record<Status, string> = {
  supported: 'Supported',
  preview: 'Preview',
  unsupported: 'No',
  'not-offered': '',
};

interface StatusBadgeProps {
  status: Status;
  compact?: boolean;
  // Replaces the visible text (the icon and the screen-reader status stay).
  label?: string;
}

// Icon plus text, never color alone. "Not offered" renders as an em dash with
// the status spelled out for screen readers.
export function StatusBadge({ status, compact = false, label }: StatusBadgeProps) {
  const Icon = ICONS[status];
  const full = STATUS_LABEL[status];
  const text = label ?? (compact ? COMPACT_LABEL[status] : full);
  if (status === 'not-offered' && !label) {
    return (
      <span className={styles.badge} data-status={status} title={full}>
        <span aria-hidden>—</span>
        <span className={styles.srOnly}>{full}</span>
      </span>
    );
  }
  return (
    <span className={styles.badge} data-status={status} title={full}>
      <Icon aria-hidden className={styles.badgeIcon} strokeWidth={2.25} />
      <span>{text}</span>
      {text !== full ? <span className={styles.srOnly}>{`: ${full}`}</span> : null}
    </span>
  );
}

const LEGEND: { status: Status; text: string }[] = [
  { status: 'supported', text: 'Verified by live tests in this release' },
  { status: 'preview', text: 'In the code, not verified live in this release' },
  { status: 'unsupported', text: 'The code refuses it on that OS or edition' },
  { status: 'not-offered', text: 'Not part of that edition' },
];

export function StatusLegend() {
  return (
    <dl className={`not-prose ${styles.legend}`} aria-label="Status legend">
      {LEGEND.map(({ status, text }) => (
        <div key={status} className={styles.legendItem}>
          <dt>
            <StatusBadge status={status} label={status === 'not-offered' ? 'Not offered' : undefined} />
          </dt>
          <dd>{text}</dd>
        </div>
      ))}
    </dl>
  );
}
