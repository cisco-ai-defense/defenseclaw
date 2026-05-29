// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Playground tab — the full-knob wizard for power users (or operators
// fine-tuning what the Quick Start interview produced). This is the
// component that previously lived in index.tsx; the refactor pulled it
// out so the parent can swap between Quick Start and Playground while
// preserving a single shared Policy state.
//
// Two-column shell:
//
//   ┌─────────────────────────────┬──────────────────┐
//   │ left: collapsible sections  │ right: live test │
//   └─────────────────────────────┴──────────────────┘
//
// Each section reads/writes the parent's Policy via the policy +
// onPolicyChange props. The Live Test pane lazy-loads opa-wasm and
// re-evaluates the policy against canned scenarios on every change.

'use client';

import { useEffect, useMemo, useState } from 'react';
import type { Policy } from './types';
import { Section } from './ui/section';
import type { SectionStatus } from './ui/section';
import { BasicsSection } from './sections/basics';
import { SeverityMatrixSection } from './sections/severity-matrix';
import { AdmissionSection } from './sections/admission';
import { GuardrailSection } from './sections/guardrail';
import { RulesSection } from './sections/rules';
import { SuppressionsSection } from './sections/suppressions';
import { SensitiveToolsSection } from './sections/sensitive-tools';
import { JudgesSection } from './sections/judges';
import { CustomRegoSection } from './sections/custom-rego';
import { CorrelatorSection } from './sections/correlator';
import { CiscoAIDefenseSection } from './sections/cisco-ai-defense';
import { FirewallSection } from './sections/firewall';
import {
  AuditSection,
  EnforcementSection,
  ScannersSection,
  WatchSection,
  WebhooksSection,
} from './sections/ops';
import { ReviewSection } from './sections/review';
import { LiveTestPane } from './sections/live-test';
import { diffAgainstBase } from './lib/diff';
import { RISKY_CONFIG_CODES, summarize, validatePolicy } from './lib/validators';
import { CommandPalette, CommandPaletteHint } from './playground/command-palette';

interface SectionDef {
  id: string;
  title: string;
  subtitle: (p: Policy) => string;
  status: (p: Policy) => SectionStatus;
  render: (p: Policy, set: (next: Policy) => void) => React.ReactNode;
}

function customizedIfNonEmpty(values: unknown[]): SectionStatus {
  return values.some((v) => {
    if (v == null) return false;
    if (Array.isArray(v)) return v.length > 0;
    if (typeof v === 'object') return Object.keys(v).length > 0;
    return Boolean(v);
  })
    ? 'customized'
    : 'untouched';
}

const SECTION_DEFS: SectionDef[] = [
  {
    id: 'basics',
    title: 'Basics',
    subtitle: (p) => `name=${p.name || '(unset)'} · base=${p.basedOn}`,
    status: (p) =>
      !p.name || p.name === 'my-policy' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(p.name)
        ? 'warning'
        : 'customized',
    render: (p, set) => <BasicsSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'severity-matrix',
    title: 'Severity matrix',
    subtitle: (p) => {
      const overrides = Object.keys(p.scanner_overrides).length;
      return overrides > 0
        ? `5 severities · ${overrides} scanner override${overrides === 1 ? '' : 's'}`
        : '5 severities';
    },
    status: (p) =>
      Object.keys(p.scanner_overrides).length > 0 ? 'customized' : 'untouched',
    render: (p, set) => <SeverityMatrixSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'admission',
    title: 'Admission',
    subtitle: (p) =>
      `${p.first_party_allow_list.length} allow-list entr${p.first_party_allow_list.length === 1 ? 'y' : 'ies'}`,
    status: (p) => customizedIfNonEmpty([p.first_party_allow_list]),
    render: (p, set) => <AdmissionSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'guardrail',
    title: 'Guardrail',
    subtitle: (p) =>
      `block≥${p.guardrail.block_threshold} · alert≥${p.guardrail.alert_threshold} · ${
        Object.keys(p.guardrail.patterns).length
      } pattern categor${Object.keys(p.guardrail.patterns).length === 1 ? 'y' : 'ies'}`,
    status: (p) =>
      Object.keys(p.guardrail.patterns).length > 0 || p.guardrail.hilt.enabled
        ? 'customized'
        : 'untouched',
    render: (p, set) => <GuardrailSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'rules',
    title: 'Rule pack',
    subtitle: (p) => {
      const total = p.rule_pack.files.reduce((acc, f) => acc + f.rules.length, 0);
      return `${p.rule_pack.files.length} file${p.rule_pack.files.length === 1 ? '' : 's'} · ${total} rule${total === 1 ? '' : 's'}`;
    },
    status: (p) =>
      p.rule_pack.files.some((f) => f.rules.length > 0) ? 'customized' : 'untouched',
    render: (p, set) => <RulesSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'suppressions',
    title: 'Suppressions',
    subtitle: (p) =>
      `${p.suppressions.pre_judge_strips.length} pre-judge · ${p.suppressions.finding_suppressions.length} finding · ${p.suppressions.tool_suppressions.length} tool`,
    status: (p) =>
      customizedIfNonEmpty([
        p.suppressions.pre_judge_strips,
        p.suppressions.finding_suppressions,
        p.suppressions.tool_suppressions,
      ]),
    render: (p, set) => <SuppressionsSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'sensitive-tools',
    title: 'Sensitive tools',
    subtitle: (p) =>
      `${p.sensitive_tools.length} tool${p.sensitive_tools.length === 1 ? '' : 's'}`,
    status: (p) => customizedIfNonEmpty([p.sensitive_tools]),
    render: (p, set) => <SensitiveToolsSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'judges',
    title: 'LLM judges',
    subtitle: (p) =>
      p.judges.length === 0
        ? 'no judges configured'
        : p.judges.map((j) => j.name).join(', '),
    status: (p) => customizedIfNonEmpty([p.judges]),
    render: (p, set) => <JudgesSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'correlator',
    title: 'Session correlator (Layer 5)',
    subtitle: (p) => {
      const enabled = p.correlator.filter((c) => c.enabled).length;
      if (p.correlator.length === 0) return 'not loaded — pick a preset to seed defaults';
      return enabled === p.correlator.length
        ? `${enabled} pattern${enabled === 1 ? '' : 's'} enabled`
        : `${enabled} of ${p.correlator.length} patterns enabled`;
    },
    // Highlight as "warning" when the operator has disabled bundled
    // patterns — that's an intentional choice but the wizard should
    // make it visible so a teammate reviewing the share link spots it.
    status: (p) => {
      if (p.correlator.length === 0) return 'untouched';
      const disabled = p.correlator.filter((c) => !c.enabled).length;
      if (disabled > 0) return 'warning';
      return 'customized';
    },
    render: (p, set) => <CorrelatorSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'firewall',
    title: 'Firewall',
    subtitle: (p) =>
      `${p.firewall.default_action} · ${p.firewall.allowed_domains.length} allow · ${p.firewall.blocked_destinations.length} block`,
    status: (p) =>
      p.firewall.allowed_domains.length > 0 ||
      p.firewall.blocked_destinations.length > 2 // base ships 2 default IMDS entries
        ? 'customized'
        : 'untouched',
    render: (p, set) => <FirewallSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'webhooks',
    title: 'Webhooks',
    subtitle: (p) =>
      p.webhooks.length === 0
        ? 'no destinations configured'
        : `${p.webhooks.length} destination${p.webhooks.length === 1 ? '' : 's'}`,
    status: (p) => customizedIfNonEmpty([p.webhooks]),
    render: (p, set) => <WebhooksSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'watch',
    title: 'Watch (rescan)',
    subtitle: (p) =>
      p.watch.rescan_enabled
        ? `enabled · every ${p.watch.rescan_interval_min} min`
        : 'disabled',
    status: () => 'untouched',
    render: (p, set) => <WatchSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'enforcement',
    title: 'Enforcement',
    subtitle: (p) => `max delay ${p.enforcement.max_enforcement_delay_seconds}s`,
    status: () => 'untouched',
    render: (p, set) => <EnforcementSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'audit',
    title: 'Audit',
    subtitle: (p) => `${p.audit.retention_days} day retention`,
    status: () => 'untouched',
    render: (p, set) => <AuditSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'scanners',
    title: 'Scanner profiles',
    subtitle: (p) => {
      const overrides = Object.values(p.scanners).filter(Boolean).length;
      return overrides > 0
        ? `${overrides} scanner profile${overrides === 1 ? '' : 's'} overridden`
        : 'inherit base';
    },
    status: (p) =>
      Object.values(p.scanners).some(Boolean) ? 'customized' : 'untouched',
    render: (p, set) => <ScannersSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'cisco-ai-defense',
    // Wording: "Optional · Enterprise" makes it clear this lane is
    // (a) not required for DefenseClaw to function and (b) backed by
    // the enterprise Cisco AI Defense product. The body of the
    // section links to https://www.cisco.com/site/us/en/products/security/ai-defense/
    // so operators can learn more without leaving the wizard.
    title: 'Cisco AI Defense (Optional · Enterprise)',
    subtitle: (p) => {
      const aid = p.cisco_ai_defense;
      if (!aid.enabled && !aid.api_key_env && !aid.endpoint) return 'off';
      return [
        aid.enabled ? 'enabled' : 'disabled',
        aid.api_key_env ? `key=${aid.api_key_env}` : 'no key',
        `hook surface ${aid.scan_hook_surface ? 'on' : 'off'}`,
      ].join(' · ');
    },
    status: (p) => {
      const aid = p.cisco_ai_defense;
      if (aid.enabled && !aid.api_key_env) return 'warning'; // toggled on without a key
      if (aid.enabled || aid.api_key_env) return 'customized';
      return 'untouched';
    },
    render: (p, set) => <CiscoAIDefenseSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'custom-rego',
    title: 'Custom Rego (advanced)',
    subtitle: (p) =>
      p.custom_rego.length === 0
        ? 'no snippets'
        : `${p.custom_rego.length} snippet${p.custom_rego.length === 1 ? '' : 's'}`,
    status: (p) => customizedIfNonEmpty([p.custom_rego]),
    render: (p, set) => <CustomRegoSection policy={p} onPolicyChange={set} />,
  },
  {
    id: 'review',
    title: 'Review & export',
    subtitle: () => 'Generated YAML + data.json',
    status: () => 'untouched',
    render: (p) => <ReviewSection policy={p} />,
  },
];

export interface PlaygroundProps {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
  /** Section that should be expanded on first paint. */
  initialOpenId?: string;
  /** Optional banner rendered above the section list — used by the
   *  parent to surface "Loaded from Quick Start" handoff messaging. */
  banner?: React.ReactNode;
}

export function Playground({
  policy,
  onPolicyChange,
  initialOpenId = 'basics',
  banner,
}: PlaygroundProps) {
  // The parent owns Policy state, but the open-section toggle is purely
  // a UI affordance, so it lives here.
  const [openId, setOpenId] = usePersistentState('dc-playground-open-id', initialOpenId);

  const findings = useMemo(() => validatePolicy(policy), [policy]);
  const counts = useMemo(() => summarize(findings), [findings]);
  // Subset surfaced in the pinned "risky configuration" banner so
  // operators can't miss high-impact warnings (firewall default-allow,
  // identity-allow custom Rego, every action allow). The full set is
  // still available in the collapsed details bar below.
  const riskyFindings = useMemo(
    () => findings.filter((f) => RISKY_CONFIG_CODES.has(f.code)),
    [findings],
  );
  // D1 — diff-vs-preset pane. Surfaces what the operator has changed
  // relative to the preset they started from, both as a section
  // summary in the header and as a collapsed detail pane. Computed
  // here so it stays in sync with every Policy edit without each
  // section having to recompute its own slice.
  const diff = useMemo(() => diffAgainstBase(policy), [policy]);
  const [diffOpen, setDiffOpen] = useState(false);

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
      {/* Cmd-K palette is portal-style (fixed full-screen overlay)
       *  but mounted here so it shares the Playground's section
       *  state via setOpenId. */}
      <CommandPalette onJump={setOpenId} />
      <div className="flex flex-col overflow-hidden rounded-xl border border-fd-border bg-fd-background">
        <div className="flex items-center justify-between border-b border-fd-border bg-fd-card px-4 py-3">
          <div>
            <h2 className="text-base font-semibold text-fd-foreground">Playground</h2>
            <p className="mt-0.5 text-[11px] text-fd-muted-foreground">
              Every knob the engine reads, surfaced section-by-section. Edits run through the
              live OPA-WASM engine on the right.
            </p>
          </div>
          <CommandPaletteHint />
        </div>
        {banner}
        {riskyFindings.length > 0 && <RiskyConfigBanner findings={riskyFindings} />}
        <DiffVsPresetBanner
          basedOn={policy.basedOn}
          diff={diff}
          open={diffOpen}
          onToggle={() => setDiffOpen((v) => !v)}
        />
        <div className="divide-y divide-fd-border">
          {SECTION_DEFS.map((sec) => (
            <Section
              key={sec.id}
              id={sec.id}
              title={sec.title}
              subtitle={sec.subtitle(policy)}
              status={sec.status(policy)}
              expanded={openId === sec.id}
              onToggle={() => setOpenId(openId === sec.id ? '' : sec.id)}
            >
              {sec.render(policy, onPolicyChange)}
            </Section>
          ))}
        </div>
        <FindingsBar
          counts={counts}
          findings={findings.slice(0, 6)}
          totalFindings={findings.length}
        />
      </div>
      {/*
        min-h-0 is required for the inner flex column inside
        LiveTestPane to honour overflow-y-auto under a fixed-height
        sticky container. Without it the inner pane grows past the
        aside and the Input JSON / verdict reason / corpus table get
        clipped at the bottom of the viewport (issue reported on the
        merged Pages deploy: "Input JSON in full playground is
        getting cut off").
      */}
      <aside className="flex min-h-0 flex-col lg:sticky lg:top-20 lg:h-[calc(100vh-6rem)]">
        <LiveTestPane policy={policy} />
      </aside>
    </div>
  );
}

// Tiny self-contained localStorage hook so the open-section UI state
// survives a refresh. Reading is gated on `typeof window` so SSR doesn't
// blow up; the actual `localStorage` write happens after mount.
function usePersistentState<T>(key: string, initial: T): [T, (next: T) => void] {
  const [value, setValue] = useState<T>(initial);
  // Hydrate from localStorage *after* mount so the initial server-rendered
  // tree matches the client tree (avoids hydration mismatch warnings).
  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(key);
      if (raw != null) setValue(JSON.parse(raw) as T);
    } catch {
      /* malformed JSON / private mode — keep initial */
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  useEffect(() => {
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch {
      /* quota / private mode — give up silently */
    }
  }, [key, value]);
  return [value, setValue];
}

/**
 * Pinned warning banner for "risky configuration" findings.
 *
 * Unlike the collapsed `FindingsBar` at the bottom of the
 * playground, this lives at the top so the operator sees these
 * specific high-impact warnings (firewall default-allow,
 * identity-allow custom Rego, every action allow, judges disabled
 * with non-zero block_threshold, all correlator patterns disabled)
 * even before they scroll. We intentionally don't show counts here
 * — risky findings are short and few, so we just render them.
 */
function RiskyConfigBanner({
  findings,
}: {
  findings: ReturnType<typeof validatePolicy>;
}) {
  return (
    <div
      role="alert"
      aria-label="Risky policy configuration warnings"
      className="border-t border-amber-400/50 bg-amber-100/50 px-4 py-2 text-[11px] text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200"
    >
      <div className="flex items-baseline gap-2">
        <span aria-hidden="true">⚠</span>
        <span className="font-semibold">Risky configuration</span>
        <span className="text-amber-700/80 dark:text-amber-300/80">
          ({findings.length} {findings.length === 1 ? 'item' : 'items'})
        </span>
      </div>
      <ul className="mt-1 space-y-1">
        {findings.map((f, i) => (
          <li key={`${f.code}:${i}`}>
            <div className="flex items-baseline gap-2">
              <code className="font-mono text-[10px] text-amber-700/80 dark:text-amber-300/80">
                {f.location}
              </code>
            </div>
            <div>{f.message}</div>
            {f.fix && (
              <div className="text-[10px] text-amber-700/80 dark:text-amber-300/80">
                Fix: {f.fix}
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * D1 — Pinned banner showing how many fields diverge from the
 * preset the policy was based on, with a click-to-expand listing.
 *
 * Why a separate banner rather than reusing the Review tab's diff
 * panel: the Review tab is the *exit ramp* (operator is about to
 * download an install script). Live editing needs the same
 * affordance closer to the knobs so an operator can answer
 * "how much have I drifted from the preset?" without leaving the
 * panel they're tuning. Defaults to collapsed so the section list
 * still dominates the layout; expand-on-click keeps the banner
 * lightweight when the operator is heads-down on a single section.
 */
function DiffVsPresetBanner({
  basedOn,
  diff,
  open,
  onToggle,
}: {
  basedOn: string;
  diff: ReturnType<typeof diffAgainstBase>;
  open: boolean;
  onToggle: () => void;
}) {
  if (diff.length === 0) {
    return (
      <div className="flex items-center gap-2 border-t border-fd-border bg-fd-card px-4 py-2 text-[11px] text-fd-muted-foreground">
        <span aria-hidden="true">≡</span>
        <span>
          Matches the <code className="font-mono">{basedOn}</code> preset verbatim — no
          drift.
        </span>
      </div>
    );
  }
  return (
    <div className="border-t border-fd-border bg-fd-card">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls="dc-playground-diff-list"
        className="flex w-full cursor-pointer items-center gap-3 px-4 py-2 text-left text-[11px] text-fd-foreground hover:bg-fd-accent/30"
      >
        <span aria-hidden="true">≢</span>
        <span>
          {diff.length} change{diff.length === 1 ? '' : 's'} from the{' '}
          <code className="font-mono">{basedOn}</code> preset
        </span>
        <span className="ml-auto text-fd-muted-foreground">
          {open ? 'collapse ▾' : 'expand ▸'}
        </span>
      </button>
      {open && (
        <ul
          id="dc-playground-diff-list"
          className="divide-y divide-fd-border border-t border-fd-border"
        >
          {diff.map((d, i) => (
            <li key={`${d.path}:${i}`} className="px-4 py-2 text-[11px]">
              <div className="flex items-baseline gap-2">
                <span
                  className={
                    d.kind === 'added'
                      ? 'text-emerald-600 dark:text-emerald-400'
                      : d.kind === 'removed'
                        ? 'text-red-500'
                        : 'text-amber-600 dark:text-amber-400'
                  }
                >
                  {d.kind === 'added' ? '+' : d.kind === 'removed' ? '−' : '~'}
                </span>
                <code className="font-mono text-[10px] text-fd-muted-foreground">
                  {d.path}
                </code>
              </div>
              <div className="text-fd-foreground">{d.description}</div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function FindingsBar({
  counts,
  findings,
  totalFindings,
}: {
  counts: { errors: number; warnings: number; info: number };
  findings: ReturnType<typeof validatePolicy>;
  totalFindings: number;
}) {
  if (totalFindings === 0) {
    return (
      <div className="flex items-center gap-2 border-t border-fd-border bg-emerald-500/10 px-4 py-2 text-[11px] text-emerald-700 dark:text-emerald-300">
        <span aria-hidden="true">✓</span>
        <span>No issues. Ready to export.</span>
      </div>
    );
  }
  return (
    <details className="border-t border-fd-border bg-fd-card">
      <summary className="flex cursor-pointer items-center gap-3 px-4 py-2 text-[11px] text-fd-foreground">
        <span aria-hidden="true">⚠</span>
        <span>
          {counts.errors > 0 && (
            <span className="text-red-500">
              {counts.errors} error{counts.errors === 1 ? '' : 's'}
            </span>
          )}
          {counts.errors > 0 && (counts.warnings > 0 || counts.info > 0) && ' · '}
          {counts.warnings > 0 && (
            <span className="text-amber-600">
              {counts.warnings} warning{counts.warnings === 1 ? '' : 's'}
            </span>
          )}
          {counts.warnings > 0 && counts.info > 0 && ' · '}
          {counts.info > 0 && <span className="text-fd-muted-foreground">{counts.info} info</span>}
        </span>
        <span className="ml-auto text-fd-muted-foreground">click to expand</span>
      </summary>
      <ul className="divide-y divide-fd-border">
        {findings.map((f, i) => (
          <li key={i} className="px-4 py-2 text-[11px]">
            <div className="flex items-baseline gap-2">
              <span
                className={
                  f.level === 'error'
                    ? 'text-red-500'
                    : f.level === 'warning'
                      ? 'text-amber-600 dark:text-amber-400'
                      : 'text-fd-muted-foreground'
                }
              >
                {f.level.toUpperCase()}
              </span>
              <code className="font-mono text-[10px] text-fd-muted-foreground">{f.location}</code>
            </div>
            <div className="text-fd-foreground">{f.message}</div>
            {f.fix && <div className="text-[10px] text-fd-muted-foreground">Fix: {f.fix}</div>}
          </li>
        ))}
        {totalFindings > findings.length && (
          <li className="px-4 py-2 text-[11px] text-fd-muted-foreground">
            …and {totalFindings - findings.length} more.
          </li>
        )}
      </ul>
    </details>
  );
}
