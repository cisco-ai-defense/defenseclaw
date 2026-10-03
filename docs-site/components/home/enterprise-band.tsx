import Link from 'next/link';
import { ArrowRight, Building2 } from 'lucide-react';
import styles from './home.module.css';

// Facts from content/docs/enterprise (index, machine-policy, mdm). Keep them
// to what those pages state; the per-OS status lives in the support matrix.
const FACTS = [
  {
    label: 'Admin-owned',
    body: 'Services, policy and program files belong to the administrator. Users and their agents can’t turn protection off.',
  },
  {
    label: 'Machine policy',
    body: 'Hooks installed at machine level for Claude Code, Codex, Copilot, Cursor, and OpenCode with the managed plugin.',
  },
  {
    label: 'Your MDM',
    body: 'Recipes for Intune, Jamf, Iru (formerly Kandji), Workspace ONE, ConfigMgr and Linux configuration management.',
  },
];

export function EnterpriseBand() {
  return (
    <section className={`editorial-install ${styles.enterprise}`} aria-labelledby="enterprise-heading">
      <div className={`editorial-shell ${styles.enterpriseGrid}`}>
        <div>
          <p className="editorial-kicker"><Building2 aria-hidden /> Enterprise</p>
          <h2 id="enterprise-heading">Roll it out to every endpoint.</h2>
          <div className="editorial-actions">
            <Link className="editorial-button editorial-button-primary" href="/docs/enterprise/get-started">
              Enterprise deployment guide <ArrowRight aria-hidden />
            </Link>
            <Link className="editorial-button" href="/docs/support-matrix#features">
              Compare editions
            </Link>
          </div>
        </div>
        <dl className={styles.enterpriseFacts}>
          {FACTS.map((fact) => (
            <div key={fact.label}>
              <dt>{fact.label}</dt>
              <dd>{fact.body}</dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  );
}
