// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Editor for the LLM judge configurations. Each judge is one YAML
// file under policies/guardrail/<pack>/judge/<name>.yaml. The judge's
// system prompt drives classification; its categories are the labels
// the judge can return (each with a finding_id and severity).

'use client';

import type { JudgeConfig, JudgeCategoryDef, Policy, SeverityUpper } from '../types';
import { SEVERITIES_UPPER } from '../types';
import { SegmentedControl } from '../ui/segmented-control';
import { TextField, TextArea } from '../ui/text-field';
import { Toggle } from '../ui/toggle';

type JudgeName = JudgeConfig['name'];

const ALL_JUDGES: JudgeName[] = ['pii', 'injection', 'tool-injection', 'exfil'];

export function JudgesSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  const updateJudge = (idx: number, patch: Partial<JudgeConfig>) => {
    const next = [...policy.judges];
    next[idx] = { ...next[idx], ...patch };
    onPolicyChange({ ...policy, judges: next });
  };
  const removeJudge = (idx: number) => {
    onPolicyChange({ ...policy, judges: policy.judges.filter((_, i) => i !== idx) });
  };
  const addJudge = (name: JudgeName) => {
    if (policy.judges.some((j) => j.name === name)) return;
    onPolicyChange({
      ...policy,
      judges: [
        ...policy.judges,
        {
          name,
          enabled: true,
          system_prompt:
            'You are a security judge. Classify the following input. Respond with one of the categories below.',
          categories: {},
        },
      ],
    });
  };

  const addCategory = (judgeIdx: number, key: string) => {
    const judge = policy.judges[judgeIdx];
    if (!key || judge.categories[key]) return;
    updateJudge(judgeIdx, {
      categories: {
        ...judge.categories,
        [key]: { finding_id: `JUDGE-${key.toUpperCase()}`, severity: 'MEDIUM', enabled: true },
      },
    });
  };
  const updateCategory = (
    judgeIdx: number,
    key: string,
    patch: Partial<JudgeCategoryDef>,
  ) => {
    const judge = policy.judges[judgeIdx];
    updateJudge(judgeIdx, {
      categories: { ...judge.categories, [key]: { ...judge.categories[key], ...patch } },
    });
  };
  const removeCategory = (judgeIdx: number, key: string) => {
    const judge = policy.judges[judgeIdx];
    const { [key]: _drop, ...rest } = judge.categories;
    void _drop;
    updateJudge(judgeIdx, { categories: rest });
  };

  const present = new Set(policy.judges.map((j) => j.name));
  const missing = ALL_JUDGES.filter((n) => !present.has(n));

  return (
    <div className="space-y-4">
      <SeverityRubricCallout />
      {missing.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-fd-border bg-fd-background p-2">
          <span className="text-[11px] font-medium text-fd-muted-foreground">
            Add a judge:
          </span>
          {missing.map((n) => (
            <button
              key={n}
              type="button"
              onClick={() => addJudge(n)}
              className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-foreground hover:border-[var(--brand-cisco)]"
            >
              + {n}
            </button>
          ))}
        </div>
      )}

      {policy.judges.length === 0 ? (
        <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-3 text-center text-[11px] text-fd-muted-foreground">
          No judges configured. Add a judge above for any category whose patterns are too varied
          for a regex (e.g. PII, prompt injection).
        </p>
      ) : (
        <div className="space-y-4">
          {policy.judges.map((judge, judgeIdx) => (
            <div
              key={judge.name}
              className="space-y-3 rounded-md border border-fd-border bg-fd-card/50 p-3"
            >
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-fd-foreground">{judge.name}</span>
                <Toggle
                  label="enabled"
                  checked={judge.enabled}
                  onChange={(v) => updateJudge(judgeIdx, { enabled: v })}
                />
                <button
                  type="button"
                  onClick={() => removeJudge(judgeIdx)}
                  className="ml-auto text-[11px] text-fd-muted-foreground hover:text-red-500"
                >
                  Remove judge
                </button>
              </div>
              <TextArea
                label="system_prompt"
                rows={4}
                monospace
                value={judge.system_prompt}
                onChange={(v) => updateJudge(judgeIdx, { system_prompt: v })}
                hint="Instructions the judge model receives. Keep it short, deterministic, and category-driven."
              />
              <TextArea
                label="adjudication_prompt (optional)"
                rows={2}
                monospace
                value={judge.adjudication_prompt ?? ''}
                onChange={(v) =>
                  updateJudge(judgeIdx, { adjudication_prompt: v || undefined })
                }
                hint="Per-call prefix prepended to the judge prompt."
              />
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                <TextField
                  label="min_categories_for_high"
                  inputMode="numeric"
                  value={String(judge.min_categories_for_high ?? '')}
                  onChange={(v) => {
                    const n = Number(v);
                    updateJudge(judgeIdx, {
                      min_categories_for_high: Number.isFinite(n) && v !== '' ? n : undefined,
                    });
                  }}
                />
                <TextField
                  label="min_categories_for_critical"
                  inputMode="numeric"
                  value={String(judge.min_categories_for_critical ?? '')}
                  onChange={(v) => {
                    const n = Number(v);
                    updateJudge(judgeIdx, {
                      min_categories_for_critical:
                        Number.isFinite(n) && v !== '' ? n : undefined,
                    });
                  }}
                />
                <div>
                  <span className="mb-1 block text-xs font-medium text-fd-muted-foreground">
                    single_category_max_severity
                  </span>
                  <SegmentedControl
                    name={`judge-${judge.name}-cap`}
                    size="sm"
                    value={judge.single_category_max_severity ?? 'CRITICAL'}
                    options={[...SEVERITIES_UPPER].map((s) => ({ value: s, label: s }))}
                    onChange={(v: SeverityUpper) =>
                      updateJudge(judgeIdx, { single_category_max_severity: v })
                    }
                  />
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold uppercase tracking-wide text-fd-muted-foreground">
                    Categories
                  </span>
                  <CategoryAdder
                    onAdd={(key) => addCategory(judgeIdx, key)}
                    existing={Object.keys(judge.categories)}
                  />
                </div>
                {Object.keys(judge.categories).length === 0 ? (
                  <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-2 text-center text-[11px] text-fd-muted-foreground">
                    No categories defined.
                  </p>
                ) : (
                  <ul className="space-y-2">
                    {Object.entries(judge.categories).map(([key, cat]) => (
                      <li
                        key={key}
                        className="grid grid-cols-1 gap-2 rounded-md border border-fd-border bg-fd-background p-2 sm:grid-cols-12"
                      >
                        <div className="sm:col-span-3 font-mono text-xs text-fd-foreground">
                          {key}
                        </div>
                        <div className="sm:col-span-4">
                          <TextField
                            label="finding_id"
                            value={cat.finding_id}
                            onChange={(v) =>
                              updateCategory(judgeIdx, key, { finding_id: v })
                            }
                          />
                        </div>
                        <div className="sm:col-span-3">
                          <span className="mb-1 block text-xs font-medium text-fd-muted-foreground">
                            severity
                          </span>
                          <SegmentedControl
                            name={`cat-${judge.name}-${key}-sev`}
                            size="sm"
                            value={cat.severity ?? 'MEDIUM'}
                            options={[...SEVERITIES_UPPER].map((s) => ({ value: s, label: s }))}
                            onChange={(v: SeverityUpper) =>
                              updateCategory(judgeIdx, key, { severity: v })
                            }
                          />
                        </div>
                        <div className="flex items-end justify-end gap-2 sm:col-span-2">
                          <Toggle
                            label="enabled"
                            checked={cat.enabled !== false}
                            onChange={(v) => updateCategory(judgeIdx, key, { enabled: v })}
                          />
                          <button
                            type="button"
                            aria-label={`Remove ${key}`}
                            onClick={() => removeCategory(judgeIdx, key)}
                            className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-muted-foreground hover:border-red-500 hover:text-red-500"
                          >
                            ×
                          </button>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SeverityRubricCallout() {
  return (
    <details className="rounded-md border border-fd-border bg-fd-card/60 p-3 text-[12px] leading-5 text-fd-muted-foreground">
      <summary className="cursor-pointer font-semibold text-fd-foreground">
        Severity rubric &amp; signal_strength coupling
      </summary>
      <div className="mt-2 space-y-2">
        <p>
          Severities are operational, not editorial. Pick the one whose response
          posture you actually want — the rest follows from the policy.
        </p>
        <ul className="ml-4 list-disc space-y-1">
          <li>
            <span className="font-mono">LOW</span> — log, no user friction.
          </li>
          <li>
            <span className="font-mono">MEDIUM</span> — alert; HILT prompt depending on
            install column.
          </li>
          <li>
            <span className="font-mono">HIGH</span> — block by default in the runtime
            column.
          </li>
          <li>
            <span className="font-mono">CRITICAL</span> — block + page on-call. Reserve
            for confirmed RCE / data-loss paths.
          </li>
        </ul>
        <p>
          Findings carry a <span className="font-mono">signal_strength</span> ∈
          &#123; low, medium, high &#125; that captures detector confidence. The
          gateway promotes severity when multiple high-strength signals stack in the
          same event; the correlator promotes again when they stack across events.
        </p>
        <p>
          <strong>Injection judge note (Layer 3):</strong> a single matching
          injection category now maps to <span className="font-mono">HIGH</span> by
          default (was previously gated behind{' '}
          <span className="font-mono">min_categories_for_high</span>). If you need
          the old &ldquo;require 2 categories&rdquo; behavior, raise{' '}
          <span className="font-mono">min_categories_for_high</span> on the{' '}
          <span className="font-mono">injection</span> judge.
        </p>
      </div>
    </details>
  );
}

function CategoryAdder({
  onAdd,
  existing,
}: {
  onAdd: (key: string) => void;
  existing: string[];
}) {
  const taken = new Set(existing);
  const SUGGESTIONS = ['email', 'ssn', 'phone', 'card', 'ip', 'destructive', 'override', 'leak'];
  return (
    <div className="flex items-center gap-1">
      {SUGGESTIONS.map((s) => (
        <button
          key={s}
          type="button"
          disabled={taken.has(s)}
          onClick={() => onAdd(s)}
          className="rounded-md border border-fd-border bg-fd-background px-2 py-0.5 text-[10px] uppercase tracking-wide text-fd-muted-foreground hover:border-[var(--brand-cisco)] hover:text-fd-foreground disabled:cursor-not-allowed disabled:opacity-40"
        >
          + {s}
        </button>
      ))}
    </div>
  );
}
