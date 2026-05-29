// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Layer-5 (session correlator) editor. Mirrors the YAML schema in
// internal/guardrail/defaults/correlation-patterns.yaml. Operators
// can disable a bundled pattern, edit window/severity, add or remove
// clauses, or scaffold a custom pattern from scratch.
//
// The wizard imports the bundled four patterns on preset load, so
// "disable LETHAL-TRIFECTA" round-trips correctly via emit() — see
// lib/emit.ts:correlatorDiffersFromDefault for the heuristic that
// decides when to write correlation-patterns.yaml at install time.

'use client';

import { useMemo, useRef } from 'react';
import type {
  CorrelationClause,
  CorrelationPattern,
  CorrelationSequenceStep,
  DataAxis,
  Policy,
  SeverityUpper,
  ToolCapabilityClass,
} from '../types';
import { DATA_AXES, SEVERITIES_UPPER, TOOL_CAPABILITY_CLASSES } from '../types';
import { TextField } from '../ui/text-field';
import { Toggle } from '../ui/toggle';
import { SegmentedControl } from '../ui/segmented-control';

// Capability-class options for the dropdown. We include an empty
// "(any)" sentinel so operators can clear a clause without removing it.
const CAPABILITY_OPTIONS: Array<{ value: '' | ToolCapabilityClass; label: string }> = [
  { value: '', label: '(any)' },
  ...TOOL_CAPABILITY_CLASSES.map((c) => ({ value: c, label: c })),
];

const AXIS_OPTIONS: Array<{ value: '' | DataAxis; label: string }> = [
  { value: '', label: '(any)' },
  ...DATA_AXES.map((a) => ({ value: a, label: a })),
];

const SEVERITY_OPTIONS: Array<{ value: '' | SeverityUpper; label: string }> = [
  { value: '', label: '(any)' },
  ...SEVERITIES_UPPER.map((s) => ({ value: s, label: s })),
];

function emptyPattern(): CorrelationPattern {
  return {
    id: 'CUSTOM-PATTERN',
    description: '',
    window_events: 30,
    severity_on_match: 'CRITICAL',
    all_of: [{ axis: 'ingress_untrusted' }],
    enabled: true,
  };
}

export function CorrelatorSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  const update = (idx: number, patch: Partial<CorrelationPattern>) => {
    const next = [...policy.correlator];
    next[idx] = { ...next[idx], ...patch };
    onPolicyChange({ ...policy, correlator: next });
  };
  const remove = (idx: number) => {
    onPolicyChange({
      ...policy,
      correlator: policy.correlator.filter((_, i) => i !== idx),
    });
  };
  const add = () => {
    onPolicyChange({ ...policy, correlator: [...policy.correlator, emptyPattern()] });
  };

  // One pass — avoids triple-iteration on every render. `useMemo`
  // caches across renders that don't touch the correlator array.
  const counts = useMemo(() => {
    let enabled = 0;
    let disabled = 0;
    for (const p of policy.correlator) {
      if (p.enabled) enabled += 1;
      else disabled += 1;
    }
    return { enabled, disabled };
  }, [policy.correlator]);

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-fd-border bg-fd-card p-3 text-[12px] leading-5 text-fd-muted-foreground">
        <p>
          The correlator watches the last N findings in a session and emits a synthetic
          <code className="mx-1">CORR-&lt;PATTERN_ID&gt;</code> finding at{' '}
          <strong>severity_on_match</strong> when the pattern matches. It is{' '}
          <strong>detect-and-alert</strong>, not detect-and-block — by the time the CORR row
          lands the contributing requests have already completed. Wire the{' '}
          <code>CORR-*</code> rule_id prefix into Rego, webhooks, or audit triggers to act on
          it.
        </p>
      </div>

      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wide text-fd-muted-foreground">
          Patterns ({counts.enabled} enabled
          {counts.disabled > 0 ? `, ${counts.disabled} disabled` : ''})
        </span>
        <button
          type="button"
          onClick={add}
          className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-foreground hover:border-[var(--brand-cisco)]"
        >
          + Add pattern
        </button>
      </div>

      {policy.correlator.length === 0 ? (
        <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-3 text-center text-[11px] text-fd-muted-foreground">
          No correlator patterns loaded. The bundled defaults
          (LETHAL-TRIFECTA, TRIFECTA-WITH-FINGERPRINT-MATCH, ESCALATION-CHAIN,
          DESTRUCTIVE-FLOW) only appear once you select a preset.
        </p>
      ) : (
        <ul className="space-y-3">
          {policy.correlator.map((pattern, idx) => (
            // Key by index, not pattern.id — the id is editable, and
            // changing the React key on every keystroke would unmount
            // the row's controlled inputs and steal focus mid-edit.
            // Since patterns aren't reordered through the UI, the
            // index is stable for the lifetime of a render pass.
            <PatternEditor
              key={idx}
              pattern={pattern}
              onChange={(patch) => update(idx, patch)}
              onRemove={() => remove(idx)}
            />
          ))}
        </ul>
      )}
    </div>
  );
}

function PatternEditor({
  pattern,
  onChange,
  onRemove,
}: {
  pattern: CorrelationPattern;
  onChange: (patch: Partial<CorrelationPattern>) => void;
  onRemove: () => void;
}) {
  // Which clause set this pattern uses. The Go schema allows exactly
  // one of {all_of, sequence, fingerprint_chain} to be non-empty, so
  // the UI exposes a segmented control rather than rendering all three
  // editors simultaneously.
  type Kind = 'all_of' | 'sequence' | 'fingerprint_chain';
  const kind: Kind =
    pattern.sequence && pattern.sequence.length > 0
      ? 'sequence'
      : pattern.fingerprint_chain && pattern.fingerprint_chain.length > 0
        ? 'fingerprint_chain'
        : 'all_of';

  // Stash the non-active mode's clauses in a session-scoped draft so
  // clicking through modes to compare doesn't discard work. We
  // intentionally do NOT persist drafts back to the Policy object —
  // emit.ts must only see the active mode populated, otherwise the
  // Go-side correlator runs in an unsupported state where multiple
  // modes are non-empty on the same pattern.
  const draftRef = useRef<{
    all_of?: CorrelationClause[];
    sequence?: CorrelationSequenceStep[];
    fingerprint_chain?: CorrelationClause[];
  }>({});

  const setKind = (next: Kind) => {
    // Snapshot the currently-active draft before we clear the other
    // two slots, so flipping back restores the operator's clauses.
    if (kind === 'all_of' && pattern.all_of) draftRef.current.all_of = pattern.all_of;
    if (kind === 'sequence' && pattern.sequence) draftRef.current.sequence = pattern.sequence;
    if (kind === 'fingerprint_chain' && pattern.fingerprint_chain) {
      draftRef.current.fingerprint_chain = pattern.fingerprint_chain;
    }
    onChange({
      all_of:
        next === 'all_of'
          ? pattern.all_of ?? draftRef.current.all_of ?? [{ axis: 'ingress_untrusted' }]
          : undefined,
      sequence:
        next === 'sequence'
          ? pattern.sequence ?? draftRef.current.sequence ?? [{ severity: 'MEDIUM' }]
          : undefined,
      fingerprint_chain:
        next === 'fingerprint_chain'
          ? pattern.fingerprint_chain ??
            draftRef.current.fingerprint_chain ?? [{ axis: 'sensitive_access' }]
          : undefined,
    });
  };

  return (
    <li className="rounded-md border border-fd-border bg-fd-background p-3">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Toggle
            label=""
            checked={pattern.enabled}
            onChange={(v) => onChange({ enabled: v })}
          />
          <code className="rounded bg-fd-muted/40 px-1.5 py-0.5 text-[12px] font-semibold text-fd-foreground">
            {pattern.id || '(unset)'}
          </code>
        </div>
        <button
          type="button"
          onClick={onRemove}
          aria-label="Remove pattern"
          className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-muted-foreground hover:border-red-500 hover:text-red-500"
        >
          ×
        </button>
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-12">
        <div className="sm:col-span-5">
          <TextField
            label="id"
            value={pattern.id}
            onChange={(v) => onChange({ id: v })}
            placeholder="LETHAL-TRIFECTA"
          />
        </div>
        <div className="sm:col-span-3">
          <TextField
            label="window_events"
            inputMode="numeric"
            value={String(pattern.window_events)}
            onChange={(v) => {
              const n = Number(v);
              if (Number.isFinite(n) && n > 0) onChange({ window_events: Math.floor(n) });
            }}
          />
        </div>
        <div className="sm:col-span-4">
          <label className="block text-[11px] font-medium text-fd-muted-foreground">
            severity_on_match
          </label>
          <select
            className="mt-1 w-full rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[12px] text-fd-foreground"
            value={pattern.severity_on_match}
            onChange={(e) =>
              onChange({ severity_on_match: e.target.value as SeverityUpper })
            }
          >
            {SEVERITIES_UPPER.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        <div className="sm:col-span-12">
          <label className="block text-[11px] font-medium text-fd-muted-foreground">
            description
          </label>
          <textarea
            className="mt-1 w-full rounded-md border border-fd-border bg-fd-background px-2 py-1.5 text-[12px] text-fd-foreground"
            value={pattern.description}
            onChange={(e) => onChange({ description: e.target.value })}
            rows={2}
          />
        </div>
      </div>

      <div className="mt-3">
        <span className="text-[11px] font-semibold uppercase tracking-wide text-fd-muted-foreground">
          Match mode
        </span>
        <SegmentedControl<Kind>
          name={`correlator-kind-${pattern.id}`}
          value={kind}
          onChange={setKind}
          size="sm"
          options={[
            { value: 'all_of', label: 'all_of', hint: 'every clause must match some finding in the window' },
            {
              value: 'sequence',
              label: 'sequence',
              hint: 'severity progression in order (e.g. MEDIUM → HIGH → HIGH)',
            },
            {
              value: 'fingerprint_chain',
              label: 'fingerprint_chain',
              hint: 'same content fingerprint in two clauses (direct exfil)',
            },
          ]}
        />
      </div>

      <div className="mt-3 space-y-2">
        {kind === 'all_of' && (
          <ClauseList
            clauses={pattern.all_of ?? []}
            label="all_of"
            onChange={(next) => onChange({ all_of: next })}
          />
        )}
        {kind === 'sequence' && (
          <SequenceList
            steps={pattern.sequence ?? []}
            onChange={(next) => onChange({ sequence: next })}
          />
        )}
        {kind === 'fingerprint_chain' && (
          <ClauseList
            clauses={pattern.fingerprint_chain ?? []}
            label="fingerprint_chain"
            onChange={(next) => onChange({ fingerprint_chain: next })}
          />
        )}
      </div>
    </li>
  );
}

function ClauseList({
  clauses,
  label,
  onChange,
}: {
  clauses: CorrelationClause[];
  label: string;
  onChange: (next: CorrelationClause[]) => void;
}) {
  const update = (i: number, patch: Partial<CorrelationClause>) => {
    const next = [...clauses];
    next[i] = { ...next[i], ...patch };
    onChange(next);
  };
  const remove = (i: number) => onChange(clauses.filter((_, idx) => idx !== i));
  const add = () => onChange([...clauses, { axis: 'ingress_untrusted' }]);

  return (
    <div className="rounded-md border border-fd-border bg-fd-card/50 p-2">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-wide text-fd-muted-foreground">
          {label} clauses
        </span>
        <button
          type="button"
          onClick={add}
          className="rounded-md border border-fd-border bg-fd-background px-1.5 py-0.5 text-[10px] text-fd-foreground hover:border-[var(--brand-cisco)]"
        >
          + Add clause
        </button>
      </div>
      {clauses.length === 0 ? (
        <p className="text-[11px] text-fd-muted-foreground">No clauses — pattern will never match.</p>
      ) : (
        <ul className="space-y-1.5">
          {clauses.map((c, i) => (
            <li key={i} className="grid grid-cols-1 gap-1 rounded border border-fd-border bg-fd-background p-1.5 sm:grid-cols-12">
              <div className="sm:col-span-3">
                <label className="block text-[10px] font-medium text-fd-muted-foreground">axis</label>
                <select
                  className="mt-0.5 w-full rounded border border-fd-border bg-fd-background px-1 py-0.5 text-[11px]"
                  value={c.axis ?? ''}
                  onChange={(e) =>
                    update(i, { axis: (e.target.value || undefined) as DataAxis | undefined })
                  }
                >
                  {AXIS_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="sm:col-span-3">
                <label className="block text-[10px] font-medium text-fd-muted-foreground">tool_capability_class</label>
                <select
                  className="mt-0.5 w-full rounded border border-fd-border bg-fd-background px-1 py-0.5 text-[11px]"
                  value={c.tool_capability_class ?? ''}
                  onChange={(e) =>
                    update(i, {
                      tool_capability_class: (e.target.value || undefined) as
                        | ToolCapabilityClass
                        | undefined,
                    })
                  }
                >
                  {CAPABILITY_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="sm:col-span-3">
                <label className="block text-[10px] font-medium text-fd-muted-foreground">min_severity</label>
                <select
                  className="mt-0.5 w-full rounded border border-fd-border bg-fd-background px-1 py-0.5 text-[11px]"
                  value={c.min_severity ?? ''}
                  onChange={(e) =>
                    update(i, {
                      min_severity: (e.target.value || undefined) as SeverityUpper | undefined,
                    })
                  }
                >
                  {SEVERITY_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="sm:col-span-2">
                <label className="block text-[10px] font-medium text-fd-muted-foreground">
                  with_rule_match
                </label>
                <input
                  type="text"
                  className="mt-0.5 w-full rounded border border-fd-border bg-fd-background px-1 py-0.5 text-[11px]"
                  value={(c.with_rule_match ?? []).join(', ')}
                  onChange={(e) => {
                    const ids = e.target.value
                      .split(',')
                      .map((s) => s.trim())
                      .filter((s) => s.length > 0);
                    update(i, { with_rule_match: ids.length > 0 ? ids : undefined });
                  }}
                  placeholder="CMD-RM-RF, CMD-DD"
                />
              </div>
              <div className="flex items-end justify-end sm:col-span-1">
                <button
                  type="button"
                  onClick={() => remove(i)}
                  aria-label="Remove clause"
                  className="rounded border border-fd-border bg-fd-background px-1 py-0.5 text-[10px] text-fd-muted-foreground hover:border-red-500 hover:text-red-500"
                >
                  ×
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function SequenceList({
  steps,
  onChange,
}: {
  steps: CorrelationSequenceStep[];
  onChange: (next: CorrelationSequenceStep[]) => void;
}) {
  const update = (i: number, severity: SeverityUpper) => {
    const next = [...steps];
    next[i] = { severity };
    onChange(next);
  };
  const remove = (i: number) => onChange(steps.filter((_, idx) => idx !== i));
  const add = () => onChange([...steps, { severity: 'MEDIUM' }]);

  return (
    <div className="rounded-md border border-fd-border bg-fd-card/50 p-2">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-wide text-fd-muted-foreground">
          sequence (each step must match a later finding than the prior one)
        </span>
        <button
          type="button"
          onClick={add}
          className="rounded-md border border-fd-border bg-fd-background px-1.5 py-0.5 text-[10px] text-fd-foreground hover:border-[var(--brand-cisco)]"
        >
          + Add step
        </button>
      </div>
      {steps.length === 0 ? (
        <p className="text-[11px] text-fd-muted-foreground">No steps — pattern will never match.</p>
      ) : (
        <ul className="flex flex-wrap items-center gap-2">
          {steps.map((s, i) => (
            <li
              key={i}
              className="flex items-center gap-1 rounded border border-fd-border bg-fd-background px-1.5 py-1"
            >
              {i > 0 && <span aria-hidden className="text-fd-muted-foreground">→</span>}
              <select
                className="rounded border border-fd-border bg-fd-background px-1 py-0.5 text-[11px]"
                value={s.severity}
                onChange={(e) => update(i, e.target.value as SeverityUpper)}
              >
                {SEVERITIES_UPPER.map((sev) => (
                  <option key={sev} value={sev}>
                    {sev}
                  </option>
                ))}
              </select>
              <button
                type="button"
                onClick={() => remove(i)}
                aria-label="Remove step"
                className="rounded text-[10px] text-fd-muted-foreground hover:text-red-500"
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
