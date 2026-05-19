// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

'use client';

import { verdictTone } from '../lib/opa-eval';

export function VerdictBadge({
  verdict,
  emphasized,
}: {
  verdict: string;
  emphasized?: boolean;
}) {
  const tone = verdictTone(verdict);
  const cls = (() => {
    switch (tone) {
      case 'positive':
        return 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30';
      case 'caution':
        return 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30';
      case 'negative':
        return 'bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30';
      case 'neutral':
      default:
        return 'bg-fd-muted text-fd-muted-foreground border-fd-border';
    }
  })();
  const sizing = emphasized ? 'px-3 py-1 text-sm' : 'px-2 py-0.5 text-xs';
  return (
    <span
      className={`inline-flex items-center rounded-md border font-medium tracking-wide ${cls} ${sizing}`}
    >
      {verdict}
    </span>
  );
}
