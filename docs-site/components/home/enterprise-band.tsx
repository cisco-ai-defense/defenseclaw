import Link from 'next/link';
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

/** The enterprise section; the hero's "Enterprise?" link is the way in, this is the detail. */
export function EnterpriseBand() {
  return (
    <section id="enterprise" className={styles.enterprise} aria-labelledby="enterprise-heading">
      <div className={`editorial-shell ${styles.enterpriseGrid}`}>
        <div>
          <h2 id="enterprise-heading">Protection your users can’t turn off.</h2>
          <div className="editorial-actions">
            <Link className="editorial-button editorial-button-primary" href="/docs/enterprise/get-started">
              Read the enterprise deployment guide
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
