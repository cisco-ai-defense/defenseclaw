import Link from 'next/link';
import { Building2 } from 'lucide-react';
import { SoftwareApplicationSchema } from '@/components/structured-data';
import { DefenseClawDemo } from '@/components/feature-demo';
import { FirstBlockRunbook } from '@/components/install/first-block-runbook';
import { ConnectorGrid, ConnectorLegend } from '@/components/home/connector-grid';
import { EnterpriseBand } from '@/components/home/enterprise-band';
import { FeatureGrid } from '@/components/home/feature-grid';
import { AGENT_COUNT, agentSummary } from '@/components/home/home-data';
import styles from '@/components/home/home.module.css';

const STORIES = [
  { href: '/docs/stories/observe-claude-code', title: 'Stop Claude Code from running a destructive command', body: 'Prove the action never reaches the disk.' },
  { href: '/docs/stories/prompt-injection-codex', title: 'Catch a prompt injection on Codex', body: 'Combine deterministic rules with an optional judge.' },
  { href: '/docs/stories/hitl-approvals', title: 'Approve risky tool calls before they fire', body: 'Pause HIGH findings and return the operator’s decision.' },
  { href: '/docs/stories/local-observability', title: 'Pin local observability in under 60 seconds', body: 'Follow one event through metrics, logs, traces, and audit.' },
];

export default function HomePage() {
  return (
    <div className="editorial-home flex flex-1 flex-col">
      <SoftwareApplicationSchema />

      <section className={styles.hero} aria-labelledby="hero-heading">
        <div className={`editorial-shell ${styles.heroGrid}`}>
          <div className={styles.heroCopy}>
            <Link className={styles.enterpriseHook} href="/docs/enterprise/get-started">
              <Building2 aria-hidden />
              <span>
                <strong>Enterprise?</strong>{' '}
                <span className={styles.enterpriseHookText}>Roll out to every endpoint with Intune or any MDM</span>
              </span>
            </Link>
            <h1 id="hero-heading" className={styles.heroTitle}>Guardrails for every AI coding agent.</h1>
            <p className={styles.heroLede}>
              Open source from Cisco AI Defense. Scan skills and MCP servers, block risky tool calls and keep an
              audit trail for {agentSummary()}, on macOS, Linux and Windows.
            </p>
            <FirstBlockRunbook className={styles.heroRunbook} />
            <p className={styles.heroAfter}>
              Release archives, the macOS menu-bar app and checksum steps are on the{' '}
              <Link href="/docs/get-started/download">Download page</Link>.
            </p>
          </div>
          <div className={styles.heroDemo}>
            <DefenseClawDemo scenario="policy-decision-trace" />
          </div>
        </div>
      </section>

      <section className={styles.section} aria-labelledby="agents-heading">
        <div className="editorial-shell">
          <SectionIntro title={`${AGENT_COUNT} agents, one policy`} id="agents-heading">
            Each connector uses the strongest control its agent exposes: native hooks, a policy plugin, or a bridge.
          </SectionIntro>
          <ConnectorGrid />
          <div className={styles.agentsFoot}>
            <ConnectorLegend />
            <Link className={styles.textLink} href="/docs/support-matrix">See the support matrix</Link>
          </div>
        </div>
      </section>

      <section className={styles.section} aria-labelledby="features-heading">
        <div className="editorial-shell">
          <SectionIntro title="Before, during and after every tool call" id="features-heading">
            Admission checks, runtime decisions and the evidence trail share one policy and one audit log.
          </SectionIntro>
          <FeatureGrid />
        </div>
      </section>

      <EnterpriseBand />

      <section className={styles.section} aria-labelledby="stories-heading">
        <div className={`editorial-shell ${styles.storiesGrid}`}>
          <SectionIntro title="See the decision in context" id="stories-heading" stacked>
            Walkthroughs that connect configuration to the interception point, the outcome and the audit evidence.
          </SectionIntro>
          <ul className={styles.stories}>
            {STORIES.map((story) => (
              <li key={story.href}>
                <Link href={story.href}>
                  <strong>{story.title}</strong>
                  <span>{story.body}</span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className={styles.closing} aria-labelledby="closing-heading">
        <div className={`editorial-shell ${styles.closingGrid}`}>
          <div>
            <h2 id="closing-heading">Put a guardrail around your first agent in five minutes.</h2>
            <p>No LLM key is required for deterministic runtime rules or static scanner checks.</p>
          </div>
          <div className="editorial-actions">
            <Link className="editorial-button editorial-button-primary" href="/docs/get-started/quickstart">
              Start the 5-minute quickstart
            </Link>
            <Link className="editorial-button" href="/docs/get-started/download">Download page</Link>
          </div>
        </div>
      </section>
    </div>
  );
}

function SectionIntro({ title, id, stacked, children }: { title: string; id: string; stacked?: boolean; children: React.ReactNode }) {
  return (
    <div className={stacked ? `${styles.intro} ${styles.introStacked}` : styles.intro}>
      <h2 id={id}>{title}</h2>
      <p>{children}</p>
    </div>
  );
}
