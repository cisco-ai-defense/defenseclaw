// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Standalone recipe browser mounted from /docs/policies/recipes. Same
// catalog the wizard uses, surfaced as a searchable, filterable page so
// operators can read about a pattern without opening the policy creator.

'use client';

import { useMemo, useState } from 'react';
import recipesData from '@/data/policy-recipes.json';
import type { DataAxis, Recipe, RecipesFile } from './types';
import { CopyButton } from './ui/copy-button';

const ALL: Recipe[] = (recipesData as unknown as RecipesFile).recipes;

const AXIS_LABELS: Array<{ value: DataAxis | 'all'; label: string }> = [
  { value: 'all', label: 'any axis' },
  { value: 'ingress_untrusted', label: 'ingress_untrusted' },
  { value: 'sensitive_access', label: 'sensitive_access' },
  { value: 'egress_external', label: 'egress_external' },
];

const KIND_LABELS: Array<{ value: Recipe['kind'] | 'all'; label: string }> = [
  { value: 'all', label: 'all' },
  { value: 'rule:secrets', label: 'rule: secrets' },
  { value: 'rule:injection', label: 'rule: injection' },
  { value: 'rule:exfiltration', label: 'rule: exfiltration' },
  { value: 'rule:command', label: 'rule: command' },
  { value: 'rule:path', label: 'rule: path' },
  { value: 'rule:enterprise-data', label: 'rule: enterprise-data' },
  { value: 'rule:trust-exploit', label: 'rule: trust-exploit' },
  { value: 'rule:cognitive', label: 'rule: cognitive' },
  { value: 'rule:c2', label: 'rule: c2' },
  { value: 'pre_judge_strip', label: 'pre-judge strip' },
  { value: 'finding_suppression', label: 'finding suppression' },
  { value: 'tool_suppression', label: 'tool suppression' },
];

export function RecipeCatalog() {
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState<Recipe['kind'] | 'all'>('all');
  const [axis, setAxis] = useState<DataAxis | 'all'>('all');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return ALL.filter((r) => kind === 'all' || r.kind === kind)
      .filter((r) => {
        if (axis === 'all') return true;
        return Array.isArray(r.data_axis) && r.data_axis.includes(axis);
      })
      .filter((r) => {
        if (!q) return true;
        return (
          r.title.toLowerCase().includes(q) ||
          r.id.toLowerCase().includes(q) ||
          r.tags.some((t) => t.toLowerCase().includes(q)) ||
          JSON.stringify(r.body).toLowerCase().includes(q)
        );
      });
  }, [query, kind, axis]);

  return (
    <div className="my-6 rounded-2xl border border-fd-border bg-fd-card/30 p-4">
      <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-4">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={`Search ${ALL.length} recipes…`}
          className="flex-1 rounded-md border border-fd-border bg-fd-background px-2.5 py-1.5 text-sm text-fd-foreground placeholder:text-fd-muted-foreground/60 focus:border-[var(--brand-cisco)] focus:outline-none focus:ring-1 focus:ring-[var(--brand-cisco)]"
        />
        <select
          value={kind}
          onChange={(e) => setKind(e.target.value as Recipe['kind'] | 'all')}
          className="rounded-md border border-fd-border bg-fd-background px-2 py-1.5 text-xs text-fd-foreground"
        >
          {KIND_LABELS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <select
          value={axis}
          onChange={(e) => setAxis(e.target.value as DataAxis | 'all')}
          className="rounded-md border border-fd-border bg-fd-background px-2 py-1.5 text-xs text-fd-foreground"
          aria-label="Filter by data axis"
          title="Filter by the lethal-trifecta data axis the recipe contributes to"
        >
          {AXIS_LABELS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>
      <div className="text-[11px] text-fd-muted-foreground">
        Showing {filtered.length} of {ALL.length} recipes.
      </div>
      <ul className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-2">
        {filtered.map((r) => (
          <li
            key={r.id}
            className="flex flex-col gap-2 rounded-md border border-fd-border bg-fd-background p-3"
          >
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-fd-foreground">{r.title}</span>
              <span className="ml-auto rounded-full bg-fd-muted px-2 py-0.5 text-[9px] uppercase tracking-wide text-fd-muted-foreground">
                {r.kind}
              </span>
            </div>
            <div className="font-mono text-[10px] text-fd-muted-foreground">{r.id}</div>
            {(r.data_axis?.length ?? 0) + (r.tool_capability_class?.length ?? 0) > 0 && (
              <div className="flex flex-wrap items-center gap-1 text-[9px]">
                {r.data_axis?.map((a) => (
                  <span
                    key={`ax-${a}`}
                    className="rounded-sm bg-fd-muted px-1.5 py-0.5 font-mono uppercase tracking-wide text-fd-muted-foreground"
                    title="data_axis — what part of the lethal trifecta this contributes to"
                  >
                    {a}
                  </span>
                ))}
                {r.tool_capability_class?.map((c) => (
                  <span
                    key={`cc-${c}`}
                    className="rounded-sm border border-fd-border px-1.5 py-0.5 font-mono uppercase tracking-wide text-fd-muted-foreground"
                    title="tool_capability_class — capability bucket the targeted tool falls into"
                  >
                    {c}
                  </span>
                ))}
              </div>
            )}
            <p className="text-[11px] leading-snug text-fd-muted-foreground">{r.why}</p>
            {r.examples.length > 0 && (
              <details className="rounded border border-fd-border bg-fd-card/60">
                <summary className="cursor-pointer px-2 py-1 text-[10px] uppercase tracking-wide text-fd-muted-foreground">
                  examples ({r.examples.length})
                </summary>
                <ul className="space-y-0.5 px-2 py-1 text-[11px]">
                  {r.examples.map((e) => (
                    <li key={e} className="font-mono text-emerald-700 dark:text-emerald-400">
                      ✓ {e}
                    </li>
                  ))}
                  {r.counterexamples.map((e) => (
                    <li key={e} className="font-mono text-amber-700 dark:text-amber-400">
                      ✗ {e}
                    </li>
                  ))}
                </ul>
              </details>
            )}
            <details>
              <summary className="cursor-pointer text-[10px] uppercase tracking-wide text-fd-muted-foreground hover:text-fd-foreground">
                YAML
              </summary>
              <pre className="mt-1 overflow-x-auto rounded bg-fd-background px-2 py-1.5 text-[11px] leading-snug text-fd-foreground">
                {JSON.stringify(r.body, null, 2)}
              </pre>
            </details>
            <div className="flex items-center justify-between gap-2">
              <span className="text-[10px] text-fd-muted-foreground">{r.source}</span>
              <CopyButton value={JSON.stringify(r.body, null, 2)} label="Copy JSON" />
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
