// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

'use client';

export function Toggle({
  label,
  hint,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  hint?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label
      className={[
        'flex items-start gap-2 text-sm',
        disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer',
      ].join(' ')}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 size-4 rounded border-fd-border text-[var(--brand-cisco)] focus:ring-[var(--brand-cisco)]"
      />
      <span className="flex flex-col">
        <span className="text-fd-foreground">{label}</span>
        {hint && <span className="text-[11px] text-fd-muted-foreground">{hint}</span>}
      </span>
    </label>
  );
}
