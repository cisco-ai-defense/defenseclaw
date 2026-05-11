// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Tiny utility button that pushes a string blob into the user's
// downloads folder. Shared by the Quick Start Review step and the
// Playground review tab so both can offer "Download install script"
// without duplicating the blob/anchor dance.
//
// Browser-only (uses document + URL.createObjectURL).

'use client';

export interface DownloadButtonProps {
  /** File name the browser will save under. */
  filename: string;
  /** Raw text content. */
  contents: string;
  /** MIME hint — text/plain is fine for YAML/JSON; text/x-shellscript
   *  for the install script so OSes that care set the +x bit prompt. */
  mime: string;
  /** Optional override label; defaults to the filename. */
  label?: string;
  /** Tailwind size variant. "sm" matches inline action bars; "md"
   *  matches primary CTAs. */
  size?: 'sm' | 'md';
  /** "primary" → brand-coloured filled; "ghost" → bordered. */
  variant?: 'primary' | 'ghost';
}

export function DownloadButton({
  filename,
  contents,
  mime,
  label,
  size = 'sm',
  variant = 'ghost',
}: DownloadButtonProps) {
  const onClick = () => {
    // URL.createObjectURL holds the blob in memory until revoked, so we
    // pair every create with a revoke after the click handler runs.
    const blob = new Blob([contents], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const sizeCls = size === 'sm' ? 'px-2 py-1 text-xs' : 'px-3 py-1.5 text-sm';
  const variantCls =
    variant === 'primary'
      ? 'bg-[var(--brand-cisco)] text-white shadow-sm hover:opacity-95 font-semibold'
      : 'border border-fd-border bg-fd-background text-fd-foreground font-medium hover:border-[var(--brand-cisco)] hover:bg-[var(--brand-cisco)]/10';

  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded-md ${sizeCls} ${variantCls}`}
    >
      ↓ {label ?? filename}
    </button>
  );
}
