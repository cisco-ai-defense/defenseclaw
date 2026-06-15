// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

'use client';

import { type ReactNode } from 'react';

export function TextField({
  label,
  hint,
  value,
  onChange,
  placeholder,
  inputMode,
  type = 'text',
  disabled,
  error,
}: {
  label: string;
  hint?: ReactNode;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  inputMode?: 'text' | 'numeric' | 'email' | 'url';
  type?: 'text' | 'number';
  disabled?: boolean;
  error?: string;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-xs font-medium text-fd-muted-foreground">{label}</span>
      <input
        type={type}
        value={value}
        disabled={disabled}
        placeholder={placeholder}
        inputMode={inputMode}
        onChange={(e) => onChange(e.target.value)}
        className={[
          'rounded-md border bg-fd-background px-2 py-1.5 text-xs text-fd-foreground placeholder:text-fd-muted-foreground/60',
          'focus:outline-none focus:ring-1',
          error
            ? 'border-red-500 focus:border-red-500 focus:ring-red-500'
            : 'border-fd-border focus:border-[var(--brand-cisco)] focus:ring-[var(--brand-cisco)]',
          disabled ? 'cursor-not-allowed opacity-60' : '',
        ].join(' ')}
      />
      {error ? (
        <span className="text-[11px] text-red-500">{error}</span>
      ) : hint ? (
        <span className="text-[11px] text-fd-muted-foreground">{hint}</span>
      ) : null}
    </label>
  );
}

export function TextArea({
  label,
  hint,
  value,
  onChange,
  placeholder,
  rows = 3,
  disabled,
  monospace,
}: {
  label: string;
  hint?: ReactNode;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  rows?: number;
  disabled?: boolean;
  monospace?: boolean;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-xs font-medium text-fd-muted-foreground">{label}</span>
      <textarea
        value={value}
        rows={rows}
        disabled={disabled}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className={[
          'rounded-md border border-fd-border bg-fd-background px-2 py-1.5 text-xs text-fd-foreground placeholder:text-fd-muted-foreground/60',
          'focus:border-[var(--brand-cisco)] focus:outline-none focus:ring-1 focus:ring-[var(--brand-cisco)]',
          monospace ? 'font-mono' : '',
          disabled ? 'cursor-not-allowed opacity-60' : '',
        ].join(' ')}
      />
      {hint && <span className="text-[11px] text-fd-muted-foreground">{hint}</span>}
    </label>
  );
}
