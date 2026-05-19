// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

'use client';

export function SegmentedControl<T extends string>({
  name,
  options,
  value,
  onChange,
  size = 'md',
  disabled,
}: {
  name: string;
  options: Array<{ value: T; label: string; hint?: string }>;
  value: T;
  onChange: (v: T) => void;
  size?: 'sm' | 'md';
  disabled?: boolean;
}) {
  const padX = size === 'sm' ? 'px-2 py-1' : 'px-3 py-1.5';
  const fontSize = size === 'sm' ? 'text-[11px]' : 'text-xs';
  return (
    <div
      role="radiogroup"
      aria-label={name}
      className={[
        'inline-flex flex-wrap rounded-lg border border-fd-border bg-fd-background p-1',
        disabled ? 'opacity-50' : '',
      ].join(' ')}
    >
      {options.map((opt) => {
        const isActive = opt.value === value;
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={isActive}
            disabled={disabled}
            onClick={() => onChange(opt.value)}
            className={[
              'rounded-md font-medium transition-colors',
              padX,
              fontSize,
              isActive
                ? 'bg-[var(--brand-cisco)]/15 text-[var(--brand-cisco-strong)]'
                : 'text-fd-muted-foreground hover:text-fd-foreground',
              disabled ? 'cursor-not-allowed' : '',
            ].join(' ')}
          >
            {opt.label}
            {opt.hint && (
              <span className="ml-1 text-[10px] text-fd-muted-foreground">
                {opt.hint}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
