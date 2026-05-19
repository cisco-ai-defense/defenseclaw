// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Regex input + live tester. Used by every section that lets the
// operator author a pattern (rule pack rules, suppressions, sensitive
// tools, judge categories). Re-runs the V8 engine plus our static
// RE2 lints on every keystroke and renders match/no-match results
// next to the operator-supplied examples.

'use client';

import { useEffect, useMemo, useState } from 'react';
import { lintRegex, testRegex } from '../lib/validators';

export function RegexInput({
  label,
  pattern,
  onChange,
  examples,
  counterexamples,
  onExamplesChange,
  onCounterexamplesChange,
  flags = '',
  hint,
}: {
  label: string;
  pattern: string;
  onChange: (next: string) => void;
  examples: string[];
  counterexamples: string[];
  onExamplesChange: (next: string[]) => void;
  onCounterexamplesChange: (next: string[]) => void;
  flags?: string;
  hint?: string;
}) {
  const lint = useMemo(() => lintRegex(pattern), [pattern]);
  const tests = useMemo(
    () => testRegex(pattern, flags, examples, counterexamples),
    [pattern, flags, examples, counterexamples],
  );

  const errorCount = lint.findings.filter((f) => f.level === 'error').length;
  const warnCount = lint.findings.filter((f) => f.level === 'warning').length;
  const passCount = tests.filter((t) => t.actual === t.expected).length;
  const totalCount = tests.length;

  return (
    <div className="space-y-2">
      <label className="flex flex-col gap-1">
        <span className="text-xs font-medium text-fd-muted-foreground">{label}</span>
        <input
          type="text"
          value={pattern}
          onChange={(e) => onChange(e.target.value)}
          spellCheck={false}
          className={[
            'rounded-md border bg-fd-background px-2 py-1.5 font-mono text-xs text-fd-foreground placeholder:text-fd-muted-foreground/60',
            'focus:outline-none focus:ring-1',
            errorCount > 0
              ? 'border-red-500 focus:border-red-500 focus:ring-red-500'
              : warnCount > 0
                ? 'border-amber-500 focus:border-amber-500 focus:ring-amber-500'
                : 'border-fd-border focus:border-[var(--brand-cisco)] focus:ring-[var(--brand-cisco)]',
          ].join(' ')}
        />
        {hint && <span className="text-[11px] text-fd-muted-foreground">{hint}</span>}
      </label>

      {lint.findings.length > 0 && (
        <ul className="space-y-1">
          {lint.findings.map((f, i) => (
            <li
              key={`${f.code}-${i}`}
              className={[
                'flex items-start gap-2 rounded-md border px-2 py-1.5 text-[11px]',
                f.level === 'error'
                  ? 'border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300'
                  : f.level === 'warning'
                    ? 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                    : 'border-fd-border bg-fd-card text-fd-muted-foreground',
              ].join(' ')}
            >
              <span aria-hidden="true" className="mt-px">
                {f.level === 'error' ? '✗' : f.level === 'warning' ? '!' : 'i'}
              </span>
              <span className="flex-1">
                <span className="font-medium">{f.message}</span>
                {f.fix && <span className="block text-[10px] opacity-80">{f.fix}</span>}
              </span>
            </li>
          ))}
        </ul>
      )}

      <ExampleList
        title="Should match"
        kind="match"
        items={examples}
        onChange={onExamplesChange}
        results={tests.filter((t) => t.expected === 'match')}
      />
      <ExampleList
        title="Should NOT match"
        kind="no-match"
        items={counterexamples}
        onChange={onCounterexamplesChange}
        results={tests.filter((t) => t.expected === 'no-match')}
      />

      {totalCount > 0 && (
        <div className="text-[11px] text-fd-muted-foreground">
          {passCount}/{totalCount} examples behave as expected.
        </div>
      )}
    </div>
  );
}

function ExampleList({
  title,
  kind,
  items,
  onChange,
  results,
}: {
  title: string;
  kind: 'match' | 'no-match';
  items: string[];
  onChange: (next: string[]) => void;
  results: Array<{ text: string; actual: 'match' | 'no-match' | 'error'; detail?: string }>;
}) {
  const [pending, setPending] = useState('');
  const add = () => {
    const trimmed = pending.trim();
    if (!trimmed) return;
    if (items.includes(trimmed)) {
      setPending('');
      return;
    }
    onChange([...items, trimmed]);
    setPending('');
  };
  const remove = (idx: number) => {
    onChange(items.filter((_, i) => i !== idx));
  };

  return (
    <div className="space-y-1">
      <div className="text-[11px] font-medium uppercase tracking-wide text-fd-muted-foreground">
        {title}
      </div>
      <div className="flex gap-1">
        <input
          type="text"
          value={pending}
          onChange={(e) => setPending(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              add();
            }
          }}
          placeholder={kind === 'match' ? 'add an example that should match…' : 'add an example that should NOT match…'}
          className="flex-1 rounded-md border border-fd-border bg-fd-background px-2 py-1 font-mono text-[11px] text-fd-foreground placeholder:text-fd-muted-foreground/60 focus:border-[var(--brand-cisco)] focus:outline-none"
        />
        <button
          type="button"
          onClick={add}
          className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-foreground hover:border-[var(--brand-cisco)]"
        >
          + Add
        </button>
      </div>
      {items.length > 0 && (
        <ul className="space-y-1">
          {items.map((item, idx) => {
            const result = results[idx];
            const ok = result?.actual === kind;
            const tone = !result
              ? 'border-fd-border bg-fd-background'
              : result.actual === 'error'
                ? 'border-red-500/40 bg-red-500/10'
                : ok
                  ? 'border-emerald-500/40 bg-emerald-500/10'
                  : 'border-amber-500/40 bg-amber-500/10';
            return (
              <li
                key={`${item}-${idx}`}
                className={`flex items-center justify-between gap-2 rounded-md border px-2 py-1 text-[11px] ${tone}`}
              >
                <code className="truncate font-mono text-fd-foreground">{item}</code>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] uppercase tracking-wide text-fd-muted-foreground">
                    {result?.actual ?? '…'}
                  </span>
                  <button
                    type="button"
                    onClick={() => remove(idx)}
                    aria-label={`Remove ${item}`}
                    className="text-fd-muted-foreground hover:text-red-500"
                  >
                    ×
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
