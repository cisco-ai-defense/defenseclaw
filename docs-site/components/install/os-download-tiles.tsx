'use client';

import Link from 'next/link';
import { ArrowRight, ArrowUpRight } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { DOWNLOADS, OS_ORDER, RELEASES_LATEST_URL, type OsId } from '@/data/downloads';
import { InstallCommand } from './install-command';
import { OsSwitcher } from './os-switcher';
import { useDetectedOs, useOs } from './use-os';
import styles from './install.module.css';

/** Three download tiles (macOS, Linux, Windows); the visitor's own OS is marked. */
export function OsDownloadTiles({ className }: { className?: string }) {
  const detected = useDetectedOs();
  return (
    <ul className={cn(styles.tiles, className)} aria-label="Downloads by operating system">
      {OS_ORDER.map((os) => {
        const download = DOWNLOADS[os];
        const mine = detected === os;
        return (
          <li key={os} className={styles.tile} data-mine={mine ? 'true' : undefined}>
            <div className={styles.tileHead}>
              <h3 className={styles.tileTitle}>{download.label}</h3>
              {mine ? <span className={styles.tileMine}>Your system</span> : null}
            </div>
            <p className={styles.tileArch}>{download.arch}</p>
            <InstallCommand
              command={download.install}
              prompt={download.shell === 'powershell' ? 'PS>' : '$'}
              copyLabel={`Copy the ${download.label} install command`}
            />
            <ul className={styles.tileFacts}>
              {download.facts.map((fact) => <li key={fact}>{fact}</li>)}
              {download.extra ? (
                <li>
                  <strong>{download.extra.label}</strong>
                  {download.extra.preview ? <span className={styles.preview}>Preview</span> : null}
                  {': '}
                  <code>{download.extra.value}</code>
                  {download.extra.note ? <> {download.extra.note}</> : null}
                </li>
              ) : null}
            </ul>
            <div className={styles.tileLinks}>
              <a href={RELEASES_LATEST_URL} rel="noreferrer" target="_blank">
                Release notes <ArrowUpRight aria-hidden />
              </a>
              <Link href="/docs/get-started/download#enterprise">
                Enterprise package <ArrowRight aria-hidden />
              </Link>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

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
