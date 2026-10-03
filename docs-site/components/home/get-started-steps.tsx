import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { InstallCommand } from '@/components/install/install-command';
import { OsInstallCommand } from '@/components/install/os-switcher';
import { INIT_COMMAND } from '@/data/downloads';
import styles from './home.module.css';

const QUICKSTART = '/docs/get-started/quickstart';

/** Install → init → first block, each with its command and a link into the quickstart. */
export function GetStartedSteps() {
  return (
    <ol className={styles.steps} aria-label="Get started in three steps">
      <li className={styles.step}>
        <span className={styles.stepNumber}>01</span>
        <h3>Install</h3>
        <p>One command per user. It checks every download against the release checksums.</p>
        <OsInstallCommand />
        <Link href="/docs/get-started/download" className={styles.stepLink}>
          All downloads <ArrowRight aria-hidden />
        </Link>
      </li>
      <li className={styles.step}>
        <span className={styles.stepNumber}>02</span>
        <h3>Initialize</h3>
        <p>Picks up the agents you have and starts them in observe mode, so nothing is blocked yet.</p>
        <InstallCommand command={INIT_COMMAND} prompt="$" copyLabel="Copy defenseclaw init" />
        <Link href={QUICKSTART} className={styles.stepLink}>
          What init sets up <ArrowRight aria-hidden />
        </Link>
      </li>
      <li className={styles.step}>
        <span className={styles.stepNumber}>03</span>
        <h3>See the first block</h3>
        <p>Switch one agent to action mode, add the demo rule and ask the agent to run it.</p>
        <InstallCommand
          command="defenseclaw guardrail mode action --connector claudecode"
          prompt="$"
          copyLabel="Copy the action-mode command"
        />
        <Link href={QUICKSTART} className={styles.stepLink}>
          5-minute quickstart <ArrowRight aria-hidden />
        </Link>
      </li>
    </ol>
  );
}
