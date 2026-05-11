// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useMemo, useState } from 'react';
import type { Policy } from '../types';
import { emit } from '../lib/emit';
import { CopyButton } from '../ui/copy-button';

export function ReviewSection({ policy }: { policy: Policy }) {
  const files = useMemo(() => emit(policy), [policy]);
  const [activeIdx, setActiveIdx] = useState(0);
  const active = files[activeIdx];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1.5">
        {files.map((f, i) => (
          <button
            key={f.path}
            type="button"
            onClick={() => setActiveIdx(i)}
            className={[
              'rounded-md border px-2 py-1 text-[11px] font-medium transition-colors',
              i === activeIdx
                ? 'border-[var(--brand-cisco)] bg-[var(--brand-cisco)]/15 text-[var(--brand-cisco-strong)]'
                : 'border-fd-border bg-fd-background text-fd-muted-foreground hover:text-fd-foreground',
            ].join(' ')}
          >
            {pathBase(f.path)}
          </button>
        ))}
      </div>

      {active && (
        <div className="overflow-hidden rounded-md border border-fd-border bg-fd-background">
          <div className="flex items-center justify-between border-b border-fd-border bg-fd-card px-3 py-2">
            <div className="flex flex-col">
              <span className="font-mono text-[11px] text-fd-foreground">{active.path}</span>
              <span className="text-[10px] text-fd-muted-foreground">{active.description}</span>
            </div>
            <CopyButton value={active.contents} label="Copy file" />
          </div>
          <pre className="max-h-96 overflow-auto bg-fd-background px-3 py-2 text-[11px] leading-snug text-fd-foreground">
            {active.contents}
          </pre>
        </div>
      )}
    </div>
  );
}

function pathBase(path: string): string {
  const parts = path.split('/');
  return parts[parts.length - 1] ?? path;
}
