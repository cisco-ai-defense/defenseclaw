import Link from 'next/link';
import { ArrowRight, Building2, Download, Fingerprint } from 'lucide-react';
import { SoftwareApplicationSchema } from '@/components/structured-data';
import { CtaGlowButton } from '@/components/cta-glow-button';
import { DefenseClawDemo } from '@/components/feature-demo';
import { EditorialMotionGrid } from '@/components/editorial-motion-grid';
import { OsInstall } from '@/components/install/os-switcher';
import { OsDownloadTiles } from '@/components/install/os-download-tiles';
import { ConnectorGrid, ConnectorLegend } from '@/components/home/connector-grid';
import { EnterpriseBand } from '@/components/home/enterprise-band';
import { FeatureGrid } from '@/components/home/feature-grid';
import { GetStartedSteps } from '@/components/home/get-started-steps';
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

      <section className="editorial-hero" aria-labelledby="hero-heading">
        <EditorialMotionGrid />
        <div className={`editorial-shell ${styles.heroGrid}`}>
          <div className={styles.heroCopy}>
            <Link className={styles.enterpriseHook} href="/docs/enterprise/get-started">
              <span className={styles.enterpriseHookTag}><Building2 aria-hidden /> Enterprise?</span>
              <span className={styles.enterpriseHookText}>Roll out to every endpoint with Intune or any MDM</span>
              <ArrowRight aria-hidden className={styles.enterpriseHookArrow} />
            </Link>
            <p className="editorial-kicker"><span>Cisco AI Defense</span> Open source</p>
            <h1 id="hero-heading" className={styles.heroTitle}>Guardrails for every AI coding agent.</h1>
            <p className={`editorial-lede ${styles.heroLede}`}>
              Scan skills and MCP servers, block risky tool calls, and keep an audit trail for {agentSummary()}, on macOS, Linux and Windows.
            </p>
            <OsInstall className={styles.heroInstall} />
            <div className={styles.heroLinks}>
              <Link className="editorial-text-link" href="/docs/get-started/quickstart">
                5-minute quickstart <ArrowRight aria-hidden />
              </Link>
              <Link className="editorial-text-link" href="/docs/get-started/download">
                All downloads <ArrowRight aria-hidden />
              </Link>
            </div>
            <dl className={`editorial-proof-strip ${styles.heroProof}`}>
              <div><dt>Agents</dt><dd>{AGENT_COUNT}</dd></div>
              <div><dt>Platforms</dt><dd>Linux · macOS · Windows</dd></div>
              <div><dt>License</dt><dd>Apache-2.0</dd></div>
            </dl>
          </div>
          <div className={styles.heroDemo}>
            <DefenseClawDemo scenario="policy-decision-trace" />
          </div>
          <div className={styles.heroSteps}>
            <div className={styles.heroStepsHead}>
              <p className="editorial-kicker">Get started</p>
              <h2>Three commands to your first block.</h2>
            </div>
            <GetStartedSteps />
          </div>
        </div>
      </section>

      <section className="editorial-section editorial-section-tinted" aria-labelledby="download-heading">
        <div className="editorial-shell">
          <SectionIntro eyebrow="Download" title="Pick your system" id="download-heading">
            Every installer is per user, needs no LLM key, and upgrades in place later with <code>defenseclaw upgrade</code>.
          </SectionIntro>
          <OsDownloadTiles />
        </div>
      </section>

      <section className="editorial-section" aria-labelledby="agents-heading">
        <div className="editorial-shell">
          <SectionIntro eyebrow="Works with your agents" title={`${AGENT_COUNT} agents, one policy`} id="agents-heading">
            Each connector uses the strongest control its agent exposes: native hooks, a policy plugin, or a bridge.
          </SectionIntro>
          <ConnectorGrid />
          <div className={styles.agentsFoot}>
            <ConnectorLegend />
            <Link className="editorial-inline-link" href="/docs/support-matrix">
              See the support matrix <ArrowRight aria-hidden />
            </Link>
          </div>
        </div>
      </section>

      <section className="editorial-section editorial-section-tinted" aria-labelledby="features-heading">
        <div className="editorial-shell">
          <SectionIntro eyebrow="What it does" title="Before, during and after every tool call" id="features-heading">
            Admission checks, runtime decisions and the evidence trail share one policy and one audit log.
          </SectionIntro>
          <FeatureGrid />
        </div>
      </section>

      <EnterpriseBand />

      <section className="editorial-section" aria-labelledby="stories-heading">
        <div className="editorial-shell editorial-stories-grid">
          <SectionIntro eyebrow="Operator stories" title="See the decision in context" id="stories-heading">
            Walkthroughs that connect configuration to the interception point, the outcome and the audit evidence.
          </SectionIntro>
          <ol className="story-list">
            {STORIES.map((story, index) => (
              <li key={story.href}>
                <Link href={story.href}>
                  <span>{String(index + 1).padStart(2, '0')}</span>
                  <div><strong>{story.title}</strong><p>{story.body}</p></div>
                  <ArrowRight aria-hidden />
                </Link>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="editorial-install">
        <div className="editorial-shell editorial-install-grid">
          <div>
            <p className="editorial-kicker"><Fingerprint aria-hidden /> Start with evidence</p>
            <h2>Put a guardrail around your first agent in five minutes.</h2>
            <p>No LLM key is required for deterministic runtime rules or static scanner checks.</p>
          </div>
          <div className="editorial-actions">
            <CtaGlowButton href="/docs/get-started/download" className="editorial-button editorial-button-primary">
              <Download aria-hidden /> Download DefenseClaw
            </CtaGlowButton>
            <Link className="editorial-button" href="/docs/get-started/quickstart">5-minute quickstart</Link>
          </div>
        </div>
      </section>
    </div>
  );
}

function SectionIntro({ eyebrow, title, id, children }: { eyebrow: string; title: string; id: string; children: React.ReactNode }) {
  return (
    <div className="editorial-section-intro">
      <p className="editorial-kicker">{eyebrow}</p>
      <h2 id={id}>{title}</h2>
      <p>{children}</p>
    </div>
  );
}
