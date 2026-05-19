// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Collapsible left-rail section. Mirrors the visual idiom of the
// command-generator's <Section> but adds a status dot + click-to-
// expand affordance so the wizard can keep one section visible at
// a time without overwhelming the operator.

'use client';

import { type ReactNode } from 'react';

export type SectionStatus = 'untouched' | 'customized' | 'warning' | 'error';

export function Section({
  id,
  title,
  subtitle,
  status,
  expanded,
  onToggle,
  children,
}: {
  id: string;
  title: string;
  subtitle?: string;
  status: SectionStatus;
  expanded: boolean;
  onToggle: () => void;
  children: ReactNode;
}) {
  const dotClass = (() => {
    switch (status) {
      case 'error':
        return 'bg-red-500';
      case 'warning':
        return 'bg-amber-500';
      case 'customized':
        return 'bg-[var(--brand-cisco)]';
      case 'untouched':
      default:
        return 'bg-fd-muted-foreground/30';
    }
  })();
  return (
    // The id={section-…} anchor is consumed by the cmd-K command
    // palette to scrollIntoView() and flash the matching section.
    // scroll-mt offsets the smooth-scroll for the sticky doc header
    // so the section title lands fully visible, not under the nav.
    <div id={`section-${id}`} className="scroll-mt-24 border-b border-fd-border last:border-b-0 transition-shadow">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        aria-controls={`policy-section-${id}`}
        className="flex w-full items-center gap-3 px-3 py-2.5 text-left transition-colors hover:bg-fd-muted/40"
      >
        <span
          aria-hidden="true"
          className={`size-2 shrink-0 rounded-full ${dotClass}`}
          title={status}
        />
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium text-fd-foreground">{title}</div>
          {subtitle && (
            <div className="truncate text-[11px] text-fd-muted-foreground">{subtitle}</div>
          )}
        </div>
        <span
          aria-hidden="true"
          className={`text-xs text-fd-muted-foreground transition-transform ${
            expanded ? 'rotate-90' : ''
          }`}
        >
          ›
        </span>
      </button>
      {expanded && (
        <div
          id={`policy-section-${id}`}
          className="border-t border-fd-border bg-fd-card/40 px-4 py-3"
        >
          {children}
        </div>
      )}
    </div>
  );
}
