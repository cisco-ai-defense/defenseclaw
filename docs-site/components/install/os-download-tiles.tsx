'use client';

import type { ReactNode } from 'react';
import { DOWNLOADS, type OsId } from '@/data/downloads';
import { OsSwitcher } from './os-switcher';
import { useOs } from './use-os';
import styles from './install.module.css';

/** OS tabs for MDX pages: <OsTabs><OsPanel os="macos">…</OsPanel>…</OsTabs>. */
export function OsTabs({ children }: { children: ReactNode }) {
  return (
    <div className={styles.osTabs}>
      <OsSwitcher className={styles.osTabsSwitcher} />
      {children}
    </div>
  );
}

export function OsPanel({ os, children }: { os: OsId; children: ReactNode }) {
  const [selected] = useOs();
  return (
    <section
      className={styles.osPanel}
      aria-label={`${DOWNLOADS[os].label} (${DOWNLOADS[os].arch})`}
      hidden={selected !== os}
    >
      {children}
    </section>
  );
}
