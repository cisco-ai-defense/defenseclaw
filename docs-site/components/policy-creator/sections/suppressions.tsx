// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Editor for the three suppression layers DefenseClaw applies before
// emitting a finding:
//
//   1) pre_judge_strips     — chunks the gateway strips out of judge
//                             input so noisy fixtures don't trigger.
//   2) finding_suppressions — drops a finding if its id matches a
//                             pattern AND a per-finding entity matches
//                             a regex (with optional condition like
//                             is_epoch / is_platform_id).
//   3) tool_suppressions    — drops findings on tools whose name
//                             matches a regex.
//
// All three are RE2-compiled by the engine, so we re-use the same
// regex tester from Phase 2.

'use client';

import { useState } from 'react';
import type { Policy, Recipe } from '../types';
import { RecipePicker } from '../ui/recipe-picker';
import { RegexInput } from '../ui/regex-input';
import { SegmentedControl } from '../ui/segmented-control';
import { TextField } from '../ui/text-field';

type Tab = 'pre' | 'finding' | 'tool';

export function SuppressionsSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  const [tab, setTab] = useState<Tab>('pre');
  const supp = policy.suppressions;

  const setSupp = (patch: Partial<Policy['suppressions']>) =>
    onPolicyChange({ ...policy, suppressions: { ...policy.suppressions, ...patch } });

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <SegmentedControl
          name="suppression-tab"
          size="sm"
          value={tab}
          options={[
            { value: 'pre', label: `pre-judge (${supp.pre_judge_strips.length})` },
            { value: 'finding', label: `finding (${supp.finding_suppressions.length})` },
            { value: 'tool', label: `tool (${supp.tool_suppressions.length})` },
          ]}
          onChange={(v) => setTab(v)}
        />
      </div>

      {tab === 'pre' && (
        <PreJudgeEditor
          items={supp.pre_judge_strips}
          onChange={(next) => setSupp({ pre_judge_strips: next })}
        />
      )}
      {tab === 'finding' && (
        <FindingEditor
          items={supp.finding_suppressions}
          onChange={(next) => setSupp({ finding_suppressions: next })}
        />
      )}
      {tab === 'tool' && (
        <ToolEditor
          items={supp.tool_suppressions}
          onChange={(next) => setSupp({ tool_suppressions: next })}
        />
      )}

      <p className="text-[11px] text-fd-muted-foreground">
        Suppressions run after rules and judges. They&apos;re the right place to silence known
        false positives — never use a blanket <code>.*</code> here, the wizard&apos;s findings
        bar will warn you.
      </p>
    </div>
  );
}

function PreJudgeEditor({
  items,
  onChange,
}: {
  items: Policy['suppressions']['pre_judge_strips'];
  onChange: (next: Policy['suppressions']['pre_judge_strips']) => void;
}) {
  const [examples, setExamples] = useState<Record<number, { match: string[]; no: string[] }>>({});
  const setExFor = (idx: number, patch: Partial<{ match: string[]; no: string[] }>) =>
    setExamples((p) => ({ ...p, [idx]: { match: p[idx]?.match ?? [], no: p[idx]?.no ?? [], ...patch } }));

  const update = (idx: number, patch: Partial<(typeof items)[number]>) => {
    const next = [...items];
    next[idx] = { ...next[idx], ...patch };
    onChange(next);
  };
  const remove = (idx: number) => onChange(items.filter((_, i) => i !== idx));
  const add = (seed?: (typeof items)[number]) =>
    onChange([
      ...items,
      seed ?? {
        id: 'STRIP-CUSTOM',
        pattern: '',
        context: 'describe what this strip handles',
        applies_to: ['pii'],
      },
    ]);

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-fd-border bg-fd-background p-2">
        <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-fd-muted-foreground">
          Pull from recipe catalog
        </div>
        <RecipePicker
          kinds={['pre_judge_strip']}
          maxHeight={140}
          onPick={(r: Recipe) => add(r.body as unknown as (typeof items)[number])}
        />
      </div>
      <button
        type="button"
        onClick={() => add()}
        className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-foreground hover:border-[var(--brand-cisco)]"
      >
        + Add blank pre-judge strip
      </button>

      {items.length === 0 ? (
        <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-3 text-center text-[11px] text-fd-muted-foreground">
          No pre-judge strips. Add one when an LLM judge keeps flagging a known fixture (e.g. an
          example token in your README).
        </p>
      ) : (
        <ul className="space-y-3">
          {items.map((item, idx) => {
            const ex = examples[idx] ?? { match: [], no: [] };
            return (
              <li
                key={`${item.id}-${idx}`}
                className="space-y-2 rounded-md border border-fd-border bg-fd-background p-3"
              >
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                  <TextField
                    label="id"
                    value={item.id}
                    onChange={(v) => update(idx, { id: v })}
                  />
                  <TextField
                    label="context (free-form)"
                    value={item.context}
                    onChange={(v) => update(idx, { context: v })}
                  />
                  <div>
                    <span className="mb-1 block text-xs font-medium text-fd-muted-foreground">
                      applies_to
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {(['pii', 'injection', 'tool-injection', 'exfil'] as const).map((j) => (
                        <button
                          key={j}
                          type="button"
                          onClick={() =>
                            update(idx, {
                              applies_to: item.applies_to.includes(j)
                                ? item.applies_to.filter((x) => x !== j)
                                : [...item.applies_to, j],
                            })
                          }
                          className={[
                            'rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-wide',
                            item.applies_to.includes(j)
                              ? 'border-[var(--brand-cisco)] bg-[var(--brand-cisco)]/15 text-[var(--brand-cisco-strong)]'
                              : 'border-fd-border bg-fd-background text-fd-muted-foreground',
                          ].join(' ')}
                        >
                          {j}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
                <RegexInput
                  label="pattern (matched chunks are removed before the judge sees the input)"
                  pattern={item.pattern}
                  onChange={(v) => update(idx, { pattern: v })}
                  examples={ex.match}
                  counterexamples={ex.no}
                  onExamplesChange={(next) => setExFor(idx, { match: next })}
                  onCounterexamplesChange={(next) => setExFor(idx, { no: next })}
                />
                <button
                  type="button"
                  onClick={() => remove(idx)}
                  className="text-[11px] text-fd-muted-foreground hover:text-red-500"
                >
                  Remove this strip
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function FindingEditor({
  items,
  onChange,
}: {
  items: Policy['suppressions']['finding_suppressions'];
  onChange: (next: Policy['suppressions']['finding_suppressions']) => void;
}) {
  const [examples, setExamples] = useState<Record<number, { match: string[]; no: string[] }>>({});
  const setExFor = (idx: number, patch: Partial<{ match: string[]; no: string[] }>) =>
    setExamples((p) => ({ ...p, [idx]: { match: p[idx]?.match ?? [], no: p[idx]?.no ?? [], ...patch } }));

  const update = (idx: number, patch: Partial<(typeof items)[number]>) => {
    const next = [...items];
    next[idx] = { ...next[idx], ...patch };
    onChange(next);
  };
  const remove = (idx: number) => onChange(items.filter((_, i) => i !== idx));
  const add = (seed?: (typeof items)[number]) =>
    onChange([
      ...items,
      seed ?? {
        id: 'SUPP-CUSTOM',
        finding_pattern: '',
        entity_pattern: '',
        condition: '',
        reason: '',
      },
    ]);

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-fd-border bg-fd-background p-2">
        <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-fd-muted-foreground">
          Pull from recipe catalog
        </div>
        <RecipePicker
          kinds={['finding_suppression']}
          maxHeight={140}
          onPick={(r) => add(r.body as unknown as (typeof items)[number])}
        />
      </div>
      <button
        type="button"
        onClick={() => add()}
        className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-foreground hover:border-[var(--brand-cisco)]"
      >
        + Add blank finding suppression
      </button>

      {items.length === 0 ? (
        <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-3 text-center text-[11px] text-fd-muted-foreground">
          No finding suppressions. Add one when a specific finding id consistently fires on data
          that&apos;s safe (e.g. epoch timestamps, well-known platform IDs).
        </p>
      ) : (
        <ul className="space-y-3">
          {items.map((item, idx) => {
            const ex = examples[idx] ?? { match: [], no: [] };
            return (
              <li
                key={`${item.id}-${idx}`}
                className="space-y-2 rounded-md border border-fd-border bg-fd-background p-3"
              >
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                  <TextField
                    label="id"
                    value={item.id}
                    onChange={(v) => update(idx, { id: v })}
                  />
                  <div>
                    <span className="mb-1 block text-xs font-medium text-fd-muted-foreground">
                      condition
                    </span>
                    <SegmentedControl
                      name={`cond-${idx}`}
                      size="sm"
                      value={item.condition ?? ''}
                      options={[
                        { value: '', label: 'none' },
                        { value: 'is_epoch', label: 'is_epoch' },
                        { value: 'is_platform_id', label: 'is_platform_id' },
                      ]}
                      onChange={(v) =>
                        update(idx, { condition: v as (typeof items)[number]['condition'] })
                      }
                    />
                  </div>
                  <TextField
                    label="reason"
                    value={item.reason}
                    onChange={(v) => update(idx, { reason: v })}
                  />
                </div>
                <RegexInput
                  label="finding_pattern (matches the rule id)"
                  pattern={item.finding_pattern}
                  onChange={(v) => update(idx, { finding_pattern: v })}
                  examples={ex.match}
                  counterexamples={ex.no}
                  onExamplesChange={(next) => setExFor(idx, { match: next })}
                  onCounterexamplesChange={(next) => setExFor(idx, { no: next })}
                  hint="Anchor with ^ to scope to a specific id prefix (e.g. ^SEC-AWS-)."
                />
                <RegexInput
                  label="entity_pattern (matches the matched substring)"
                  pattern={item.entity_pattern}
                  onChange={(v) => update(idx, { entity_pattern: v })}
                  examples={[]}
                  counterexamples={[]}
                  onExamplesChange={() => {}}
                  onCounterexamplesChange={() => {}}
                />
                <button
                  type="button"
                  onClick={() => remove(idx)}
                  className="text-[11px] text-fd-muted-foreground hover:text-red-500"
                >
                  Remove this suppression
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function ToolEditor({
  items,
  onChange,
}: {
  items: Policy['suppressions']['tool_suppressions'];
  onChange: (next: Policy['suppressions']['tool_suppressions']) => void;
}) {
  const [examples, setExamples] = useState<Record<number, { match: string[]; no: string[] }>>({});
  const setExFor = (idx: number, patch: Partial<{ match: string[]; no: string[] }>) =>
    setExamples((p) => ({ ...p, [idx]: { match: p[idx]?.match ?? [], no: p[idx]?.no ?? [], ...patch } }));

  const update = (idx: number, patch: Partial<(typeof items)[number]>) => {
    const next = [...items];
    next[idx] = { ...next[idx], ...patch };
    onChange(next);
  };
  const remove = (idx: number) => onChange(items.filter((_, i) => i !== idx));
  const add = (seed?: (typeof items)[number]) =>
    onChange([
      ...items,
      seed ?? {
        tool_pattern: '',
        suppress_findings: [],
        reason: '',
      },
    ]);

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-fd-border bg-fd-background p-2">
        <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-fd-muted-foreground">
          Pull from recipe catalog
        </div>
        <RecipePicker
          kinds={['tool_suppression']}
          maxHeight={140}
          onPick={(r) => add(r.body as unknown as (typeof items)[number])}
        />
      </div>
      <button
        type="button"
        onClick={() => add()}
        className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-foreground hover:border-[var(--brand-cisco)]"
      >
        + Add blank tool suppression
      </button>

      {items.length === 0 ? (
        <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-3 text-center text-[11px] text-fd-muted-foreground">
          No tool suppressions. Use these to drop noisy verdicts from cosmetic shell commands
          (git status, ls, pwd) while keeping write/destructive commands surfaced.
        </p>
      ) : (
        <ul className="space-y-3">
          {items.map((item, idx) => {
            const ex = examples[idx] ?? { match: [], no: [] };
            return (
              <li
                key={idx}
                className="space-y-2 rounded-md border border-fd-border bg-fd-background p-3"
              >
                <RegexInput
                  label="tool_pattern (matches tool.name)"
                  pattern={item.tool_pattern}
                  onChange={(v) => update(idx, { tool_pattern: v })}
                  examples={ex.match}
                  counterexamples={ex.no}
                  onExamplesChange={(next) => setExFor(idx, { match: next })}
                  onCounterexamplesChange={(next) => setExFor(idx, { no: next })}
                  hint="Scope tightly. ^.*$ would silence every finding on every tool."
                />
                <TextField
                  label="suppress_findings (comma-separated finding ids)"
                  value={item.suppress_findings.join(', ')}
                  onChange={(v) =>
                    update(idx, {
                      suppress_findings: v
                        .split(',')
                        .map((s) => s.trim())
                        .filter(Boolean),
                    })
                  }
                  placeholder="JUDGE-INJ-DESTRUCTIVE, SEC-SHELL-WRITE"
                />
                <TextField
                  label="reason"
                  value={item.reason}
                  onChange={(v) => update(idx, { reason: v })}
                />
                <button
                  type="button"
                  onClick={() => remove(idx)}
                  className="text-[11px] text-fd-muted-foreground hover:text-red-500"
                >
                  Remove this suppression
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
