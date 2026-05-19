// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Floating "Preview verdict" drawer pinned to the bottom-right of the
// Quick Start. Lets operators run the LiveTestPane against the current
// policy from any wizard step, not just the Review step. Collapsed by
// default (one-line button); expanded reveals the full LiveTestPane.
//
// State persists to localStorage so the operator's preference (open vs.
// collapsed) survives across page loads. Hidden on the Review step
// because the LiveTestPane is already rendered inline there.

'use client';

import { useEffect, useState } from 'react';
import type { Policy } from '../types';
import { LiveTestPane } from '../sections/live-test';

const LS_KEY = 'dc-policy-creator/quickstart/preview-open/v1';

export function PreviewDrawer({ policy, hidden = false }: { policy: Policy; hidden?: boolean }) {
  // Hydrate persisted open/closed state. SSR returns false to keep
  // first paint stable (the drawer animates in if the user previously
  // had it open).
  const [open, setOpen] = useState(false);
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(LS_KEY);
      if (raw === '1') setOpen(true);
    } catch {
      // Storage may be denied (private mode, sandbox); harmless.
    }
    setHydrated(true);
  }, []);
  useEffect(() => {
    if (!hydrated) return;
    try {
      window.localStorage.setItem(LS_KEY, open ? '1' : '0');
    } catch {
      // Same harmless path.
    }
  }, [open, hydrated]);

  if (hidden) return null;

  return (
    <div
      className="fixed bottom-4 right-4 z-30 print:hidden"
      // pointer-events: auto on root so the drawer is interactive even
      // when the page underneath has overlays.
      style={{ pointerEvents: 'auto' }}
    >
      {!open && (
        <button
          type="button"
          onClick={() => setOpen(true)}
          aria-label="Open verdict preview"
          className="flex items-center gap-2 rounded-full border border-fd-border bg-fd-card px-3 py-2 text-[12px] font-medium text-fd-foreground shadow-lg transition hover:border-[var(--brand-cisco)] hover:bg-[var(--brand-cisco)]/10"
        >
          <span aria-hidden className="size-2 rounded-full bg-[var(--brand-cisco)]" />
          Preview verdict
        </button>
      )}
      {open && (
        <div className="flex max-h-[70vh] w-[380px] flex-col overflow-hidden rounded-xl border border-fd-border bg-fd-card shadow-2xl">
          <header className="flex items-center justify-between border-b border-fd-border bg-fd-background px-3 py-2">
            <div className="flex items-center gap-2">
              <span aria-hidden className="size-2 rounded-full bg-[var(--brand-cisco)]" />
              <span className="text-sm font-semibold text-fd-foreground">Preview verdict</span>
            </div>
            <button
              type="button"
              onClick={() => setOpen(false)}
              aria-label="Close verdict preview"
              className="rounded-md p-1 text-fd-muted-foreground hover:bg-fd-muted/40 hover:text-fd-foreground"
            >
              ×
            </button>
          </header>
          <div className="overflow-auto p-3">
            <LiveTestPane policy={policy} />
          </div>
        </div>
      )}
    </div>
  );
}
