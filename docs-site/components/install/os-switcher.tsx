'use client';

import { cn } from '@/lib/utils';
import { DOWNLOADS, OS_ORDER, type OsId } from '@/data/downloads';
import { useOs } from './use-os';
import styles from './install.module.css';

interface OsSwitcherProps {
  className?: string;
  /** Controlled use (download tabs pass their own state). Defaults to the shared choice. */
  value?: OsId;
  onChange?: (os: OsId) => void;
}

export function OsSwitcher({ className, value, onChange }: OsSwitcherProps) {
  const [shared, setShared] = useOs();
  const selected = value ?? shared;
  const select = onChange ?? setShared;

  return (
    <div className={cn(styles.switcher, className)} role="group" aria-label="Operating system">
      {OS_ORDER.map((os) => (
        <button
          key={os}
          type="button"
          className={styles.switcherButton}
          aria-pressed={selected === os}
          onClick={() => select(os)}
        >
          {DOWNLOADS[os].label}
        </button>
      ))}
    </div>
  );
}
