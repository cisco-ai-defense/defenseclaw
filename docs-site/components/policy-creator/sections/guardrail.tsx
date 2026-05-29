// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

'use client';

import type { GuardrailCategory, Policy, SeverityUpper } from '../types';
import { SEVERITIES_UPPER } from '../types';
import { SegmentedControl } from '../ui/segmented-control';
import { TextField } from '../ui/text-field';
import { Toggle } from '../ui/toggle';

const SEVERITY_RANK_LABEL: Record<1 | 2 | 3 | 4, string> = {
  1: '1 = LOW',
  2: '2 = MEDIUM',
  3: '3 = HIGH',
  4: '4 = CRITICAL',
};

export function GuardrailSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  const setG = (patch: Partial<Policy['guardrail']>) =>
    onPolicyChange({ ...policy, guardrail: { ...policy.guardrail, ...patch } });

  const addPattern = (cat: GuardrailCategory) => {
    const next = { ...policy.guardrail.patterns };
    next[cat] = [...(next[cat] ?? []), ''];
    setG({ patterns: next });
  };
  const updatePattern = (cat: GuardrailCategory, idx: number, value: string) => {
    const next = { ...policy.guardrail.patterns };
    next[cat] = [...(next[cat] ?? [])];
    next[cat][idx] = value;
    setG({ patterns: next });
  };
  const removePattern = (cat: GuardrailCategory, idx: number) => {
    const next = { ...policy.guardrail.patterns };
    next[cat] = (next[cat] ?? []).filter((_, i) => i !== idx);
    if (next[cat].length === 0) delete next[cat];
    setG({ patterns: next });
  };
  const addCategory = (cat: string) => {
    if (!cat || policy.guardrail.patterns[cat]) return;
    setG({
      patterns: { ...policy.guardrail.patterns, [cat]: [] },
      severity_mappings: {
        ...policy.guardrail.severity_mappings,
        [cat]: policy.guardrail.severity_mappings[cat] ?? 'HIGH',
      },
    });
  };

  const categories = Object.keys(policy.guardrail.patterns).sort();

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <ThresholdPicker
          label="Block threshold (severity rank)"
          value={policy.guardrail.block_threshold}
          onChange={(v) => setG({ block_threshold: v })}
          hint="Severity rank that triggers a block. CRITICAL=4 means only CRITICAL findings block."
        />
        <ThresholdPicker
          label="Alert threshold (severity rank)"
          value={policy.guardrail.alert_threshold}
          onChange={(v) => setG({ alert_threshold: v })}
          hint="Severity rank that triggers an alert. MEDIUM=2 is the bundled default."
        />
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium text-fd-muted-foreground">Cisco trust level</span>
          <SegmentedControl
            name="cisco_trust_level"
            size="sm"
            value={policy.guardrail.cisco_trust_level}
            options={[
              { value: 'full', label: 'full' },
              { value: 'advisory', label: 'advisory' },
              { value: 'none', label: 'none' },
            ]}
            onChange={(v) => setG({ cisco_trust_level: v })}
          />
        </div>
      </div>

      <fieldset className="space-y-2 rounded-md border border-fd-border bg-fd-background p-3">
        <legend className="px-1 text-[11px] font-medium uppercase tracking-wide text-fd-muted-foreground">
          Human-in-the-loop confirmation
        </legend>
        <Toggle
          label="Require approval before allow/block at high severity"
          hint="When enabled, the gateway pauses on findings ≥ min_severity until a human responds."
          checked={policy.guardrail.hilt.enabled}
          onChange={(v) =>
            setG({ hilt: { ...policy.guardrail.hilt, enabled: v } })
          }
        />
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-fd-muted-foreground">Min severity</span>
          <SegmentedControl
            name="hilt-sev"
            size="sm"
            disabled={!policy.guardrail.hilt.enabled}
            value={policy.guardrail.hilt.min_severity}
            options={(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const).map((s) => ({
              value: s,
              label: s,
            }))}
            onChange={(v: SeverityUpper) =>
              setG({ hilt: { ...policy.guardrail.hilt, min_severity: v } })
            }
          />
        </div>
      </fieldset>

      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-semibold uppercase tracking-wide text-fd-muted-foreground">
            Local pattern categories
          </span>
          <CategoryAdder onAdd={addCategory} existing={categories} />
        </div>
        {categories.length === 0 ? (
          <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-3 text-center text-[11px] text-fd-muted-foreground">
            No category-level pattern overrides. Use the rule pack section for fine-grained
            patterns; this section is for quick blanket additions (e.g. an extra category called
            "phi" with two patterns that should be tagged HIGH).
          </p>
        ) : (
          <div className="space-y-3">
            {categories.map((cat) => (
              <CategoryEditor
                key={cat}
                category={cat}
                patterns={policy.guardrail.patterns[cat] ?? []}
                severity={policy.guardrail.severity_mappings[cat] ?? 'HIGH'}
                onAddPattern={() => addPattern(cat)}
                onUpdatePattern={(idx, value) => updatePattern(cat, idx, value)}
                onRemovePattern={(idx) => removePattern(cat, idx)}
                onSeverityChange={(sev) =>
                  setG({
                    severity_mappings: {
                      ...policy.guardrail.severity_mappings,
                      [cat]: sev,
                    },
                  })
                }
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ThresholdPicker({
  label,
  value,
  onChange,
  hint,
}: {
  label: string;
  value: 1 | 2 | 3 | 4;
  onChange: (v: 1 | 2 | 3 | 4) => void;
  hint: string;
}) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs font-medium text-fd-muted-foreground">{label}</span>
      <SegmentedControl
        name={label}
        size="sm"
        value={String(value) as '1' | '2' | '3' | '4'}
        options={[
          { value: '1', label: SEVERITY_RANK_LABEL[1] },
          { value: '2', label: SEVERITY_RANK_LABEL[2] },
          { value: '3', label: SEVERITY_RANK_LABEL[3] },
          { value: '4', label: SEVERITY_RANK_LABEL[4] },
        ]}
        onChange={(v) => onChange(Number(v) as 1 | 2 | 3 | 4)}
      />
      <span className="text-[11px] text-fd-muted-foreground">{hint}</span>
    </div>
  );
}

function CategoryAdder({
  onAdd,
  existing,
}: {
  onAdd: (cat: string) => void;
  existing: string[];
}) {
  const taken = new Set(existing);
  return (
    <div className="flex items-center gap-1">
      {(['secrets', 'injection', 'exfiltration', 'phi', 'pci'] as const).map((cat) => (
        <button
          key={cat}
          type="button"
          disabled={taken.has(cat)}
          onClick={() => onAdd(cat)}
          className="rounded-md border border-fd-border bg-fd-background px-2 py-0.5 text-[10px] uppercase tracking-wide text-fd-muted-foreground hover:border-[var(--brand-cisco)] hover:text-fd-foreground disabled:cursor-not-allowed disabled:opacity-40"
        >
          + {cat}
        </button>
      ))}
    </div>
  );
}

function CategoryEditor({
  category,
  patterns,
  severity,
  onAddPattern,
  onUpdatePattern,
  onRemovePattern,
  onSeverityChange,
}: {
  category: GuardrailCategory;
  patterns: string[];
  severity: SeverityUpper;
  onAddPattern: () => void;
  onUpdatePattern: (idx: number, value: string) => void;
  onRemovePattern: (idx: number) => void;
  onSeverityChange: (s: SeverityUpper) => void;
}) {
  return (
    <div className="rounded-md border border-fd-border bg-fd-background p-2">
      <div className="flex items-center gap-2">
        <span className="text-xs font-semibold text-fd-foreground">{category}</span>
        <SegmentedControl
          name={`${category}-sev`}
          size="sm"
          value={severity}
          options={[...SEVERITIES_UPPER].map((s) => ({ value: s, label: s }))}
          onChange={onSeverityChange}
        />
        <button
          type="button"
          onClick={onAddPattern}
          className="ml-auto rounded-md border border-fd-border bg-fd-background px-2 py-0.5 text-[10px] uppercase tracking-wide text-fd-muted-foreground hover:border-[var(--brand-cisco)] hover:text-fd-foreground"
        >
          + Pattern
        </button>
      </div>
      <ul className="mt-2 space-y-1">
        {patterns.length === 0 ? (
          <li className="text-[11px] text-fd-muted-foreground">No patterns yet.</li>
        ) : (
          patterns.map((p, idx) => (
            <li key={idx} className="flex gap-1">
              <TextField
                label=""
                value={p}
                onChange={(v) => onUpdatePattern(idx, v)}
                placeholder="(?i)\\bSSN[:=]\\s*\\d{3}-\\d{2}-\\d{4}"
              />
              <button
                type="button"
                onClick={() => onRemovePattern(idx)}
                aria-label="Remove"
                className="self-end rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-muted-foreground hover:border-red-500 hover:text-red-500"
              >
                ×
              </button>
            </li>
          ))
        )}
      </ul>
    </div>
  );
}
