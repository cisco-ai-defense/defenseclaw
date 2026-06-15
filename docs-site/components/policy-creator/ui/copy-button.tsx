// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useState } from 'react';

export function CopyButton({
  value,
  label = 'Copy',
  size = 'sm',
}: {
  value: string;
  label?: string;
  size?: 'sm' | 'md';
}) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    if (typeof navigator === 'undefined' || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked — fail silent, the user can select+copy manually */
    }
  };
  const padding = size === 'md' ? 'px-3 py-1.5 text-sm' : 'px-2 py-1 text-xs';
  return (
    <button
      type="button"
      onClick={onCopy}
      className={`inline-flex items-center gap-1.5 rounded-md border border-fd-border bg-fd-background ${padding} font-medium text-fd-foreground hover:border-[var(--brand-cisco)] hover:bg-[var(--brand-cisco)]/10`}
    >
      {copied ? '✓ Copied' : label}
    </button>
  );
}
