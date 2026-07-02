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
  /** When set, disables the button. The string is the operator-facing
   *  reason rendered as a `title` tooltip so they understand *why*
   *  the action is unavailable. Used by D4 to block download when
   *  the policy has unresolved validation errors. */
  disabledReason?: string | null;
}

/** Headless implementation of the download handler. Extracted so
 *  B5 can exercise the disabledReason gate + the blob lifecycle in
 *  a node:test environment without booting React or a real browser.
 *
 *  Returns true when a download was triggered, false when blocked by
 *  ``disabledReason``. Callers should not rely on the boolean in
 *  production code — it's an internal signal for tests.
 */
export function triggerDownload(opts: {
  filename: string;
  contents: string;
  mime: string;
  disabledReason?: string | null;
  doc?: Document;
}): boolean {
  if (opts.disabledReason) return false;
  // URL.createObjectURL holds the blob in memory until revoked, so we
  // pair every create with a revoke after the click handler runs.
  const blob = new Blob([opts.contents], { type: opts.mime });
  const url = URL.createObjectURL(blob);
  const doc = opts.doc ?? document;
  const a = doc.createElement('a');
  a.href = url;
  (a as HTMLAnchorElement).download = opts.filename;
  doc.body.appendChild(a);
  (a as HTMLAnchorElement).click();
  doc.body.removeChild(a);
  URL.revokeObjectURL(url);
  return true;
}

export function DownloadButton({
  filename,
  contents,
  mime,
  label,
  size = 'sm',
  variant = 'ghost',
  disabledReason,
}: DownloadButtonProps) {
  const onClick = () => {
    triggerDownload({ filename, contents, mime, disabledReason });
  };

  const sizeCls = size === 'sm' ? 'px-2 py-1 text-xs' : 'px-3 py-1.5 text-sm';
  const variantCls =
    variant === 'primary'
      ? 'bg-[var(--brand-cisco)] text-[var(--editorial-on-blue)] shadow-sm hover:opacity-95 font-semibold'
      : 'border border-fd-border bg-fd-background text-fd-foreground font-medium hover:border-[var(--brand-cisco)] hover:bg-[var(--brand-cisco)]/10';
  const disabledCls = disabledReason ? 'cursor-not-allowed opacity-50' : '';

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!!disabledReason}
      aria-disabled={!!disabledReason}
      title={disabledReason ?? undefined}
      className={`inline-flex items-center gap-1.5 rounded-md ${sizeCls} ${variantCls} ${disabledCls}`}
    >
      ↓ {label ?? filename}
    </button>
  );
}
