import Link from 'next/link';
import {
  ArrowRight,
  Check,
  CircleDot,
  Eye,
  FileSearch,
  Fingerprint,
  Network,
  PauseCircle,
  Radar,
  ScanSearch,
  ShieldCheck,
} from 'lucide-react';
import { SoftwareApplicationSchema } from '@/components/structured-data';
import { CtaGlowButton } from '@/components/cta-glow-button';
import { DefenseClawDemo } from '@/components/feature-demo';
import { EditorialMotionGrid } from '@/components/editorial-motion-grid';
import { ConnectorBrand } from '@/components/connector-brand';
import { CapabilityMatrixWrapper } from '@/components/capability-matrix-wrapper';
import matrix from '@/data/capability-matrix.json';

const connectors = matrix.connectors;

const LIFECYCLE = [
  {
    number: '01',
    title: 'Before execution',
    body: 'Discover, register, scan, and quarantine capabilities before an agent can load them.',
    items: ['AI discovery', 'Skill + MCP scanning', 'Registry admission'],
  },
  {
    number: '02',
    title: 'During execution',
    body: 'Inspect prompts and tool calls at the connector’s strongest available interception point.',
    items: ['Runtime rules', 'Policy enforcement', 'Human approval'],
  },
  {
    number: '03',
    title: 'After execution',
    body: 'Correlate each decision with durable evidence and export it to the security stack you already use.',
    items: ['Audit history', 'Observability', 'OTLP + Splunk + webhooks'],
  },
];

const CAPABILITIES = [
  { icon: Radar, title: 'Discover AI running on a host', href: '/docs/ai-discovery' },
  { icon: FileSearch, title: 'Vet a skill before an agent loads it', href: '/docs/setup/skill-scanner' },
  { icon: ScanSearch, title: 'Inspect an MCP server’s advertised capabilities', href: '/docs/setup/mcp-scanner' },
  { icon: ShieldCheck, title: 'Block or audit risky tool calls', href: '/docs/setup/guardrail' },
  { icon: PauseCircle, title: 'Pause HIGH-risk actions for human approval', href: '/docs/hitl' },
  { icon: Network, title: 'Send correlated evidence to Grafana, Splunk, OTLP, or webhooks', href: '/docs/observability' },
];

const STORIES = [
  { href: '/docs/stories/observe-claude-code', title: 'Stop Claude Code from running a destructive command', body: 'Prove the action never reaches the disk.' },
  { href: '/docs/stories/prompt-injection-codex', title: 'Catch a prompt injection on Codex', body: 'Combine deterministic rules with an optional judge.' },
  { href: '/docs/stories/cursor-secret-exfil', title: 'Block secret exfiltration from Cursor', body: 'Use the strongest pre-execution hook the connector exposes.' },
  { href: '/docs/stories/hitl-approvals', title: 'Approve risky tool calls before they fire', body: 'Pause HIGH findings and return the operator’s decision.' },
  { href: '/docs/stories/local-observability', title: 'Pin local observability in under 60 seconds', body: 'Follow one event through metrics, logs, traces, and audit.' },
  { href: '/docs/stories/switch-connectors', title: 'Switch connectors without losing audit history', body: 'Keep the evidence contract stable while the agent changes.' },
];

const AUDIT_SINKS = ['SQLite', 'JSONL', 'OTLP', 'Splunk', 'Webhooks'];

export default function HomePage() {
  return (
    <div className="editorial-home flex flex-1 flex-col">
      <SoftwareApplicationSchema />

      <section className="editorial-hero">
        <EditorialMotionGrid />
        <div className="editorial-shell editorial-hero-grid">
          <div className="editorial-hero-copy">
            <p className="editorial-kicker"><span>DefenseClaw</span> Cisco AI security</p>
            <h1>Security governance for the entire AI agent lifecycle.</h1>
            <p className="editorial-lede">
              Scan skills and MCP servers before admission, inspect prompts and tool calls at runtime, pause risky actions for human approval, and export the evidence to your existing security stack.
            </p>
            <div className="editorial-actions">
              <Link className="editorial-button editorial-button-primary" href="/docs/get-started/quickstart">
                Quickstart <ArrowRight aria-hidden />
              </Link>
              <Link className="editorial-button" href="/docs">
                Explore how it works
              </Link>
              <Link className="editorial-text-link" href="/docs/capability-matrix">
                Capability Matrix <ArrowRight aria-hidden />
              </Link>
            </div>
            <dl className="editorial-proof-strip">
              <div><dt>Connectors</dt><dd>{connectors.length}</dd></div>
              <div><dt>Decision modes</dt><dd>Observe · Action · HITL</dd></div>
              <div><dt>Evidence rails</dt><dd>{AUDIT_SINKS.length}</dd></div>
            </dl>
          </div>
          <div className="editorial-hero-demo">
            <DefenseClawDemo scenario="runtime-secret-exfiltration" />
          </div>
        </div>
      </section>

      <section className="editorial-section" aria-labelledby="lifecycle-heading">
        <div className="editorial-shell">
          <SectionIntro eyebrow="A continuous control plane" title="One control plane for the agent lifecycle" id="lifecycle-heading">
            Admission, runtime, and evidence operate as one sequence instead of three disconnected security products.
          </SectionIntro>
          <div className="lifecycle-rail">
            {LIFECYCLE.map((phase) => (
              <article key={phase.number}>
                <span>{phase.number}</span>
                <h3>{phase.title}</h3>
                <p>{phase.body}</p>
                <ul>{phase.items.map((item) => <li key={item}><CircleDot aria-hidden />{item}</li>)}</ul>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="editorial-section editorial-section-tinted" aria-labelledby="capabilities-heading">
        <div className="editorial-shell">
          <SectionIntro eyebrow="Available now" title="Six things you can do today" id="capabilities-heading">
            Start with one concrete control, then extend the same policy and evidence contract across the lifecycle.
          </SectionIntro>
          <ol className="capability-list">
            {CAPABILITIES.map((item, index) => {
              const Icon = item.icon;
              return (
                <li key={item.title}>
                  <Link href={item.href}>
                    <span className="capability-number">{String(index + 1).padStart(2, '0')}</span>
                    <Icon aria-hidden />
                    <strong>{item.title}</strong>
                    <ArrowRight aria-hidden />
                  </Link>
                </li>
              );
            })}
          </ol>
        </div>
      </section>

      <section className="editorial-section" aria-labelledby="coverage-heading">
        <div className="editorial-shell">
          <SectionIntro eyebrow="Connector-aware enforcement" title="Use the strongest control each agent exposes" id="coverage-heading">
            DefenseClaw normalizes the decision contract while preserving the difference between native ask, downgraded confirm, and pre-execution blocking.
          </SectionIntro>
          <CapabilityMatrixWrapper className="connector-preview" ariaLabel="Connector capability preview">
            <table>
              <thead><tr><th scope="col">Connector</th><th scope="col">Pre-execution block</th><th scope="col">Native ask</th><th scope="col">Fail closed</th></tr></thead>
              <tbody>
                {connectors.slice(0, 7).map((connector) => (
                  <tr key={connector.id}>
                    <th scope="row">
                      <Link href={`/docs/connectors/${connector.id}`} className="connector-preview-name">
                        <ConnectorBrand id={connector.id} size="sm" />
                        {connector.label}
                      </Link>
                    </th>
                    <td><CapabilityValue value={connector.hooks.canBlock} /></td>
                    <td><CapabilityValue value={connector.hooks.canAskNative} /></td>
                    <td><CapabilityValue value={connector.hooks.supportsFailClosed} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CapabilityMatrixWrapper>
          <Link className="editorial-inline-link" href="/docs/capability-matrix">Compare all {connectors.length} connectors <ArrowRight aria-hidden /></Link>
        </div>
      </section>

      <section className="editorial-section editorial-section-tinted" aria-labelledby="stories-heading">
        <div className="editorial-shell editorial-stories-grid">
          <SectionIntro eyebrow="Operator stories" title="See the decision in context" id="stories-heading">
            Concrete walkthroughs connect configuration to the exact interception point, outcome, and audit evidence.
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
            <CtaGlowButton href="/docs/get-started/install" className="editorial-button editorial-button-primary">
              Install DefenseClaw <ArrowRight aria-hidden />
            </CtaGlowButton>
            <Link className="editorial-button" href="/docs/setup/guardrail">Configure guardrail</Link>
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

function CapabilityValue({ value }: { value: boolean }) {
  return value
    ? <span className="capability-yes"><Check aria-hidden />Yes</span>
    : <span className="capability-no"><Eye aria-hidden />No</span>;
}
