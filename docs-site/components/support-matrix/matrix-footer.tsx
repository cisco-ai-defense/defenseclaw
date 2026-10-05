import { supportMatrix, type Edition } from '@/data/support-matrix';
import styles from './support-matrix.module.css';

function formatDate(iso: string) {
  const date = new Date(`${iso}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
}

// The "what was verified, and when" line under every support table.
export function MatrixFooter({ edition }: { edition?: Edition }) {
  const where =
    edition === 'enterprise'
      ? 'the enterprise packages on RHEL (.rpm), macOS on Apple silicon (.pkg) and Windows x64 (Setup.exe)'
      : edition === 'oss'
        ? 'RHEL, macOS on Apple silicon and Windows x64'
        : 'RHEL, macOS on Apple silicon and Windows x64, per-user and with the enterprise packages';
  return (
    <p className={styles.footer}>
      Verified for DefenseClaw {supportMatrix.release} by live tests on {where}, as of{' '}
      <time dateTime={supportMatrix.asOf}>{formatDate(supportMatrix.asOf)}</time>. Preview means it is in the
      code but wasn’t verified live in this release.
    </p>
  );
}
