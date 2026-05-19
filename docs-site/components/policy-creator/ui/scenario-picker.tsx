// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useState } from 'react';
import scenariosData from '@/data/policy-scenarios.json';
import type { Scenario, ScenariosFile } from '../types';

const SCENARIOS = (scenariosData as unknown as ScenariosFile).scenarios;

export function ScenarioPicker({
  domain,
  selectedId,
  onSelect,
}: {
  domain: Scenario['domain'];
  selectedId: string;
  onSelect: (s: Scenario) => void;
}) {
  const filtered = SCENARIOS.filter((s) => s.domain === domain);
  return (
    <div className="space-y-1">
      {filtered.map((s) => {
        const isActive = s.id === selectedId;
        return (
          <button
            key={s.id}
            type="button"
            onClick={() => onSelect(s)}
            className={[
              'flex w-full flex-col items-start gap-0.5 rounded-md border px-2.5 py-1.5 text-left transition-colors',
              isActive
                ? 'border-[var(--brand-cisco)] bg-[var(--brand-cisco)]/10'
                : 'border-fd-border bg-fd-background hover:border-[var(--brand-cisco)]/40',
            ].join(' ')}
          >
            <span className="text-xs font-medium text-fd-foreground">{s.title}</span>
            <span className="text-[11px] text-fd-muted-foreground">{s.description}</span>
          </button>
        );
      })}
    </div>
  );
}

export function ScenarioJsonPreview({ scenario, expanded }: { scenario: Scenario | null; expanded?: boolean }) {
  const [open, setOpen] = useState(!!expanded);
  if (!scenario) return null;
  return (
    <div className="mt-2 rounded-md border border-fd-border bg-fd-card/50">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between gap-2 px-2.5 py-1.5 text-[11px] font-medium text-fd-muted-foreground hover:text-fd-foreground"
      >
        <span>Input JSON</span>
        <span aria-hidden="true">{open ? '▼' : '▶'}</span>
      </button>
      {open && (
        <pre className="overflow-x-auto border-t border-fd-border bg-fd-background px-2.5 py-2 text-[11px] leading-snug text-fd-foreground">
          {JSON.stringify(scenario.input, null, 2)}
        </pre>
      )}
    </div>
  );
}

export function listScenariosForDomain(domain: Scenario['domain']): Scenario[] {
  return SCENARIOS.filter((s) => s.domain === domain);
}
