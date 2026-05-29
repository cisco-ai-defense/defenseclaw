// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// "Copy share link" button. Generates a URL with the current Policy
// gzip+base64-encoded into the fragment, then writes it to the
// clipboard. Renders a transient "Copied!" confirmation. Used on the
// Quick Start Review step + the Playground review tab.

'use client';

import { useState } from 'react';
import type { Policy } from '../types';
import { buildShareUrl, encodePolicyForHash } from '../lib/share';

export function ShareLinkButton({
  policy,
  size = 'sm',
}: {
  policy: Policy;
  size?: 'sm' | 'md';
}) {
  const [state, setState] = useState<'idle' | 'busy' | 'ok' | 'err'>('idle');

  const onClick = async () => {
    setState('busy');
    try {
      const payload = await encodePolicyForHash(policy);
      const url = buildShareUrl(payload);
      // navigator.clipboard requires a secure context (HTTPS or
      // localhost); fall back to a hidden textarea otherwise.
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(url);
      } else {
        const ta = document.createElement('textarea');
        ta.value = url;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      setState('ok');
      // Auto-revert so the operator can copy again without page nav.
      setTimeout(() => setState('idle'), 1800);
    } catch {
      setState('err');
      setTimeout(() => setState('idle'), 1800);
    }
  };

  const sizeCls = size === 'sm' ? 'px-2 py-1 text-xs' : 'px-3 py-1.5 text-sm';
  const label =
    state === 'busy'
      ? 'Copying…'
      : state === 'ok'
        ? '✓ Link copied'
        : state === 'err'
          ? 'Copy failed'
          : '🔗 Copy share link';

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={state === 'busy'}
      title={
        // Honest about leak surfaces: fragments are not sent in the
        // initial HTTP request, but they DO get persisted in browser
        // history, written to clipboard managers, and forwarded
        // verbatim if the recipient pastes the link into a chat
        // service that previews URLs. Treat the link like any other
        // copy of the policy YAML — share via the same channels you
        // already trust for that.
        'Encodes the policy into the URL fragment. We never upload it, but the link itself contains the draft — it will live in your clipboard, browser history, and any chat tool you paste it into. Share it with the same care you would the YAML.'
      }
      className={[
        'inline-flex items-center gap-1.5 rounded-md border border-fd-border bg-fd-background font-medium text-fd-foreground transition',
        sizeCls,
        state === 'ok'
          ? 'border-emerald-500/60 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
          : 'hover:border-[var(--brand-cisco)] hover:bg-[var(--brand-cisco)]/10',
        state === 'busy' ? 'cursor-wait opacity-60' : '',
      ].join(' ')}
    >
      {label}
    </button>
  );
}
