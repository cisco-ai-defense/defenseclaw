'use client';

import { cn } from '@/lib/utils';
import { DOWNLOADS, OS_ORDER, type OsId } from '@/data/downloads';
import { InstallCommand } from './install-command';
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

/** Switcher plus the matching one-liner and the next command. Used in the landing hero. */
export function OsInstall({ className }: { className?: string }) {
  const [os] = useOs();
  const download = DOWNLOADS[os];
  return (
    <div className={cn(styles.osInstall, className)}>
      <div className={styles.osInstallHead}>
        <span className={styles.osInstallLabel}>Install</span>
        <OsSwitcher />
      </div>
      <InstallCommandFor os={os} size="lg" />
      <p className={styles.osInstallNext}>
        <span>then <code>defenseclaw init</code></span>
        <span className={styles.osInstallArch}>{download.label} · {download.arch}</span>
      </p>
    </div>
  );
}

/** The one-liner for the shared OS choice, without a switcher. */
export function OsInstallCommand({ size = 'md' }: { size?: 'md' | 'lg' }) {
  const [os] = useOs();
  return <InstallCommandFor os={os} size={size} />;
}


function InstallCommandFor({ os, size }: { os: OsId; size: 'md' | 'lg' }) {
  const download = DOWNLOADS[os];
  return (
    <InstallCommand
      command={download.install}
      prompt={download.shell === 'powershell' ? 'PS>' : '$'}
      size={size}
      copyLabel={`Copy the ${download.label} install command`}
    />
  );
}
