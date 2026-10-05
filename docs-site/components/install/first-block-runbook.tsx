'use client';

import Link from 'next/link';
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { DOWNLOADS, INIT_COMMAND } from '@/data/downloads';
import { InstallCommand } from './install-command';
import { OsSwitcher } from './os-switcher';
import { useOs } from './use-os';
import styles from './install.module.css';

const ACTION_COMMAND = 'defenseclaw guardrail mode action --connector claudecode';

interface RunbookStep {
  title: string;
  body: ReactNode;
  command: string;
  copyLabel: string;
}

/**
 * The landing page's one install surface: the OS-aware one-liner followed by
 * the two commands that lead to the first block, in one terminal panel.
 * Facts follow content/docs/get-started/quickstart.mdx.
 */
export function FirstBlockRunbook({ className }: { className?: string }) {
  const [os] = useOs();
  const download = DOWNLOADS[os];
  const prompt = download.shell === 'powershell' ? 'PS>' : '$';

  const steps: RunbookStep[] = [
    {
      title: 'Install',
      body: <>For your user on {download.label} ({download.arch}). Every download is checked against the release checksums.</>,
      command: download.install,
      copyLabel: `Copy the ${download.label} install command`,
    },
    {
      title: 'Set up',
      body: 'Finds the agents you have and starts them in observe mode, so nothing is blocked yet.',
      command: INIT_COMMAND,
      copyLabel: 'Copy defenseclaw init',
    },
    {
      title: 'Turn on blocking',
      body: (
        <>
          Switches Claude Code to action mode. The{' '}
          <Link href="/docs/get-started/quickstart#turn-on-blocking-for-claude-code">5-minute quickstart</Link>{' '}
          adds a demo rule so you can watch a block.
        </>
      ),
      command: ACTION_COMMAND,
      copyLabel: 'Copy the action-mode command',
    },
  ];

  return (
    <div className={cn(styles.runbook, className)}>
      <div className={styles.runbookHead}>
        <h2 id="runbook-heading" className={styles.runbookTitle}>Three commands to your first block</h2>
        <OsSwitcher className={styles.runbookOs} />
      </div>
      <ol className={styles.runbookSteps} aria-labelledby="runbook-heading">
        {steps.map((step, index) => (
          <li key={step.title} className={styles.runbookStep}>
            <span className={styles.runbookNum} aria-hidden>{index + 1}</span>
            <div className={styles.runbookBody}>
              <p className={styles.runbookText}>
                <strong>{step.title}.</strong> {step.body}
              </p>
              <InstallCommand
                className={styles.runbookCmd}
                command={step.command}
                prompt={prompt}
                copyLabel={step.copyLabel}
              />
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
