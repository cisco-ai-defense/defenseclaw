import Link from 'next/link';
import {
  ArrowRight,
  Box,
  Network,
  PauseCircle,
  Radar,
  ScanSearch,
  ShieldCheck,
  SlidersHorizontal,
  SquareTerminal,
  type LucideIcon,
} from 'lucide-react';
import styles from './home.module.css';

interface Feature {
  icon: LucideIcon;
  title: string;
  body: string;
  href: string;
  preview?: boolean;
}

// Eight things DefenseClaw does. A tile is marked Preview when it is not
// verified live on every OS in this release (see /docs/support-matrix).
const FEATURES: Feature[] = [
  {
    icon: ShieldCheck,
    title: 'Guardrails',
    body: 'Start in observe, switch to action, and block risky tool calls before they run.',
    href: '/docs/setup/guardrail',
  },
  {
    icon: ScanSearch,
    title: 'Skill and MCP scanning',
    body: 'Check skills and MCP servers before an agent can load them.',
    href: '/docs/setup/skill-scanner',
  },
  {
    icon: Radar,
    title: 'AI and runtime discovery',
    body: 'Find the agents, local models, MCP servers and skills on a machine, and see which ones ran.',
    href: '/docs/ai-discovery',
  },
  {
    icon: PauseCircle,
    title: 'Human approval',
    body: 'Pause a high-risk action for a person to approve, where the agent supports it.',
    href: '/docs/hitl',
  },
  {
    icon: Network,
    title: 'Observability',
    body: 'Send every decision over OTLP to Grafana or Galileo, or to a webhook.',
    href: '/docs/observability',
  },
  {
    icon: SlidersHorizontal,
    title: 'Policy creator',
    body: 'Build a policy section by section in the browser and copy the YAML into your config.',
    href: '/docs/policies/creator',
  },
  {
    icon: SquareTerminal,
    title: 'Terminal UI',
    body: 'Alerts, scans and setup in one terminal app on every OS. A macOS menu-bar app is in preview.',
    href: '/docs/tui',
  },
  {
    icon: Box,
    title: 'OpenShell sandboxes',
    body: 'Run a coding agent in an NVIDIA OpenShell sandbox on Linux or an Apple-silicon Mac, with every tool call judged.',
    href: '/docs/sandboxes',
    preview: true,
  },
];

export function FeatureGrid() {
  return (
    <ul className={styles.features}>
      {FEATURES.map((feature) => {
        const Icon = feature.icon;
        return (
          <li key={feature.title}>
            <Link href={feature.href} className={styles.feature}>
              <span className={styles.featureIcon}><Icon aria-hidden /></span>
              <strong className={styles.featureTitle}>
                {feature.title}
                {feature.preview ? <span className={styles.preview}>Preview</span> : null}
              </strong>
              <span className={styles.featureBody}>{feature.body}</span>
              <span className={styles.featureMore}>Read more <ArrowRight aria-hidden /></span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
