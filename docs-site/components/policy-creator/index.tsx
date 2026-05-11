// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Main entrypoint for the docs-site policy creator. Two-column shell:
//
//   ┌─────────────────────────────┬──────────────────┐
//   │ left: collapsible sections  │ right: live test │
//   └─────────────────────────────┴──────────────────┘
//
// Mounted from MDX as <PolicyCreator />. Holds a single Policy in
// state and pipes mutations into both the section editors and the
// Live Test pane.
//
// Phase 1 ships Basics, Severity Matrix, Admission, and Review.
// Subsequent phases plug additional sections in via SECTION_DEFS
// without touching the shell.

'use client';

import { useMemo, useState } from 'react';
import type { Policy } from './types';
import { policyFromPreset } from './lib/presets';
import { Section } from './ui/section';
import type { SectionStatus } from './ui/section';
import { BasicsSection } from './sections/basics';
import { SeverityMatrixSection } from './sections/severity-matrix';
import { AdmissionSection } from './sections/admission';
import { ReviewSection } from './sections/review';
import { LiveTestPane } from './sections/live-test';

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
    id: 'review',
    title: 'Review & export',
    subtitle: () => 'Generated YAML + data.json',
    status: () => 'untouched',
    render: (p) => <ReviewSection policy={p} />,
  },
];

export default function PolicyCreator() {
  const initial = useMemo(() => policyFromPreset('default'), []);
  const [policy, setPolicy] = useState<Policy>(initial);
  const [openId, setOpenId] = useState<string>('basics');

  return (
    <div className="my-6 grid grid-cols-1 gap-4 rounded-2xl border border-fd-border bg-fd-card/30 p-3 lg:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
      <div className="flex flex-col overflow-hidden rounded-xl border border-fd-border bg-fd-background">
        <div className="border-b border-fd-border bg-fd-card px-4 py-3">
          <h2 className="text-base font-semibold text-fd-foreground">Policy creator</h2>
          <p className="mt-0.5 text-[11px] text-fd-muted-foreground">
            Build a DefenseClaw policy section by section. Edits run through the live OPA-WASM
            engine on the right so you can see verdicts before exporting.
          </p>
        </div>
        <div className="divide-y divide-fd-border">
          {SECTION_DEFS.map((sec) => (
            <Section
              key={sec.id}
              id={sec.id}
              title={sec.title}
              subtitle={sec.subtitle(policy)}
              status={sec.status(policy)}
              expanded={openId === sec.id}
              onToggle={() => setOpenId((cur) => (cur === sec.id ? '' : sec.id))}
            >
              {sec.render(policy, setPolicy)}
            </Section>
          ))}
        </div>
      </div>
      <aside className="lg:sticky lg:top-20 lg:h-[calc(100vh-6rem)]">
        <LiveTestPane policy={policy} />
      </aside>
    </div>
  );
}
