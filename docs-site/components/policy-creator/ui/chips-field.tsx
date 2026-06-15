// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Tag/chip input for editing string[] fields the user previously had
// to author as a comma-separated single-line string. Each existing
// entry renders as a removable pill above a small "type and Enter"
// add-row, so 5+ entries no longer overflow horizontally.
//
// Replaces uses of TextField that were doing
//   value={arr.join(', ')}
//   onChange={v => v.split(',').map(s => s.trim()).filter(Boolean)}
// in admission, suppressions, and rules sections of the Playground.

'use client';

import { useState, type ReactNode } from 'react';

export function ChipsField({
  label,
  hint,
  values,
  onChange,
  placeholder,
  monospace = true,
}: {
  label: string;
  hint?: ReactNode;
  values: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  /** Render chip text in monospace. Defaults true since these are
   *  almost always identifiers / globs / paths. */
  monospace?: boolean;
}) {
  const [pending, setPending] = useState('');

  const commit = () => {
    // Accept comma-separated paste-from-clipboard too: split on commas,
    // trim, drop blanks and dupes, and append.
    const tokens = pending
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (tokens.length === 0) return;
    const seen = new Set(values);
    const next = [...values];
    for (const t of tokens) {
      if (!seen.has(t)) {
        next.push(t);
        seen.add(t);
      }
    }
    onChange(next);
    setPending('');
  };

  const remove = (idx: number) => {
    onChange(values.filter((_, i) => i !== idx));
  };

  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs font-medium text-fd-muted-foreground">{label}</span>
      <div className="rounded-md border border-fd-border bg-fd-background p-1.5 focus-within:border-[var(--brand-cisco)] focus-within:ring-1 focus-within:ring-[var(--brand-cisco)]">
        {values.length > 0 && (
          <ul className="flex flex-wrap gap-1 pb-1">
            {values.map((v, i) => (
              <li
                key={`${v}-${i}`}
                className="inline-flex items-center gap-1 rounded-md bg-[var(--brand-cisco)]/15 px-1.5 py-0.5 text-[11px] text-[var(--brand-cisco-strong)]"
              >
                <span className={monospace ? 'font-mono' : ''}>{v}</span>
                <button
                  type="button"
                  onClick={() => remove(i)}
                  aria-label={`Remove ${v}`}
                  className="text-fd-muted-foreground hover:text-red-500"
                >
                  ×
                </button>
              </li>
            ))}
          </ul>
        )}
        <input
          type="text"
          value={pending}
          placeholder={values.length === 0 ? placeholder : '+ Add another'}
          onChange={(e) => setPending(e.target.value)}
          onKeyDown={(e) => {
            // Enter or comma commits. Backspace on empty input deletes
            // the last chip — common chip-input convention.
            if (e.key === 'Enter' || e.key === ',') {
              e.preventDefault();
              commit();
            } else if (e.key === 'Backspace' && pending === '' && values.length > 0) {
              e.preventDefault();
              remove(values.length - 1);
            }
          }}
          onBlur={commit}
          className={[
            'w-full bg-transparent px-1 py-1 text-xs text-fd-foreground placeholder:text-fd-muted-foreground/60 focus:outline-none',
            monospace ? 'font-mono' : '',
          ].join(' ')}
        />
      </div>
      {hint && <span className="text-[11px] text-fd-muted-foreground">{hint}</span>}
    </div>
  );
}
