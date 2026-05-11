// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Cmd-K / Ctrl-K command palette for the Playground. Lets operators
// jump straight to a knob ("hilt severity", "splunk hec token",
// "block threshold") instead of opening every accordion until they
// find it.
//
// The index is hand-curated to keep it tight (~50 entries). A fuzzy
// matcher would be nice but adds bundle weight; for this many entries
// case-insensitive substring + token AND-match is good enough and
// behaves predictably.
//
// Selecting a result:
//   1. expands the section it belongs to (via setOpenId callback),
//   2. scrolls the matching section's anchor into view,
//   3. flashes a brief outline so the operator sees where they landed.

'use client';

import { useEffect, useMemo, useRef, useState } from 'react';

interface IndexEntry {
  /** Section id (matches sections/<file>.tsx + accordion id). */
  sectionId: string;
  /** Display label inside the search results. */
  label: string;
  /** Section group, shown as a tag. */
  group: string;
  /** Optional aliases the operator might type ("hec", "url", etc). */
  keywords?: string[];
}

const INDEX: IndexEntry[] = [
  // basics
  { sectionId: 'basics', group: 'Basics', label: 'Policy name', keywords: ['name', 'id'] },
  { sectionId: 'basics', group: 'Basics', label: 'Description', keywords: ['desc'] },
  { sectionId: 'basics', group: 'Basics', label: 'Base preset', keywords: ['based on', 'preset', 'starter'] },

  // severity
  { sectionId: 'severity-matrix', group: 'Severity', label: 'Severity → action mapping', keywords: ['critical', 'high', 'medium', 'low', 'info', 'block', 'alert'] },
  { sectionId: 'severity-matrix', group: 'Severity', label: 'Per-scanner severity overrides', keywords: ['override', 'scanner sev'] },

  // admission
  { sectionId: 'admission', group: 'Admission', label: 'First-party allow list', keywords: ['allow', 'whitelist', 'trusted source', 'path contains'] },
  { sectionId: 'admission', group: 'Admission', label: 'Admission gate / block-on-critical', keywords: ['gate', 'critical block'] },

  // guardrail
  { sectionId: 'guardrail', group: 'Guardrail', label: 'Block threshold', keywords: ['block_threshold', 'sev to block'] },
  { sectionId: 'guardrail', group: 'Guardrail', label: 'Alert threshold', keywords: ['alert_threshold'] },
  { sectionId: 'guardrail', group: 'Guardrail', label: 'Pattern categories', keywords: ['regex', 'patterns'] },
  { sectionId: 'guardrail', group: 'Guardrail', label: 'HILT (human in the loop)', keywords: ['human in the loop', 'hilt min severity', 'hilt timeout'] },

  // rules
  { sectionId: 'rules', group: 'Rules', label: 'Rule pack files', keywords: ['rule pack', 'pack file'] },
  { sectionId: 'rules', group: 'Rules', label: 'Custom regex rule', keywords: ['rule', 'pattern', 'regex rule'] },
  { sectionId: 'rules', group: 'Rules', label: 'Rule tags', keywords: ['tag', 'category', 'classification'] },
  { sectionId: 'rules', group: 'Rules', label: 'Rule severity', keywords: ['severity', 'action'] },

  // suppressions
  { sectionId: 'suppressions', group: 'Suppressions', label: 'Pre-judge strips', keywords: ['strip', 'remove before judge', 'pii'] },
  { sectionId: 'suppressions', group: 'Suppressions', label: 'Finding suppressions', keywords: ['suppress finding', 'allow finding'] },
  { sectionId: 'suppressions', group: 'Suppressions', label: 'Tool suppressions', keywords: ['suppress tool', 'tool allow'] },

  // sensitive tools
  { sectionId: 'sensitive-tools', group: 'Sensitive tools', label: 'Sensitive tool list', keywords: ['dangerous', 'destructive', 'risky tool'] },

  // judges
  { sectionId: 'judges', group: 'LLM judges', label: 'LLM judge', keywords: ['llm', 'model', 'openai', 'anthropic', 'judge'] },
  { sectionId: 'judges', group: 'LLM judges', label: 'Judge model + endpoint', keywords: ['endpoint', 'model name', 'base url'] },
  { sectionId: 'judges', group: 'LLM judges', label: 'Judge API key (env var name)', keywords: ['api key', 'env var', 'token'] },

  // firewall
  { sectionId: 'firewall', group: 'Firewall', label: 'Default action', keywords: ['allow', 'deny', 'firewall default'] },
  { sectionId: 'firewall', group: 'Firewall', label: 'Allowed domains', keywords: ['domain', 'allowlist', 'host'] },
  { sectionId: 'firewall', group: 'Firewall', label: 'Blocked destinations / IMDS', keywords: ['ssrf', 'imds', '169.254', 'metadata'] },

  // webhooks
  { sectionId: 'webhooks', group: 'Webhooks', label: 'Webhook destination', keywords: ['webhook', 'callback', 'url'] },
  { sectionId: 'webhooks', group: 'Webhooks', label: 'Webhook signing secret', keywords: ['hmac', 'signing', 'secret', 'env var'] },
  { sectionId: 'webhooks', group: 'Webhooks', label: 'Splunk HEC sink', keywords: ['splunk', 'hec', 'token', 'url'] },
  { sectionId: 'webhooks', group: 'Webhooks', label: 'PagerDuty sink', keywords: ['pagerduty', 'pd', 'routing key'] },
  { sectionId: 'webhooks', group: 'Webhooks', label: 'Slack webhook', keywords: ['slack', 'channel', 'webhook'] },

  // watch
  { sectionId: 'watch', group: 'Watch', label: 'Rescan enabled', keywords: ['rescan', 'watcher', 'on/off'] },
  { sectionId: 'watch', group: 'Watch', label: 'Rescan interval (minutes)', keywords: ['interval', 'cadence', 'frequency'] },

  // enforcement
  { sectionId: 'enforcement', group: 'Enforcement', label: 'Max enforcement delay (seconds)', keywords: ['delay', 'budget', 'timeout', 'block sla'] },

  // audit
  { sectionId: 'audit', group: 'Audit', label: 'Retention (days)', keywords: ['retention', 'log retention', 'days'] },

  // scanners
  { sectionId: 'scanners', group: 'Scanners', label: 'Scanner profiles', keywords: ['profile', 'enable scanner', 'disable scanner'] },

  // custom rego
  { sectionId: 'custom-rego', group: 'Custom Rego', label: 'Custom Rego snippet', keywords: ['rego', 'opa', 'advanced', 'custom rule'] },

  // review
  { sectionId: 'review', group: 'Review', label: 'Review & export', keywords: ['export', 'install', 'download', 'yaml', 'json'] },
];

interface CommandPaletteProps {
  /** Called when the operator picks a result. The Playground should
   *  expand the matching section. */
  onJump: (sectionId: string) => void;
}

export function CommandPalette({ onJump }: CommandPaletteProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Global shortcut: cmd-k / ctrl-k toggles the palette.
  //
  // IMPORTANT: Fumadocs already binds ⌘K to its site-wide doc search
  // (radix dialog with aria-label "Search"). To take precedence on
  // the policy creator page we register in the *capture* phase and
  // stopImmediatePropagation so Fumadocs never sees the event.
  // Outside the playground (where this component isn't mounted) the
  // Fumadocs handler is untouched.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const isToggle =
        (e.key === 'k' || e.key === 'K') && (e.metaKey || e.ctrlKey);
      if (isToggle) {
        e.preventDefault();
        e.stopImmediatePropagation();
        setOpen((prev) => !prev);
      } else if (e.key === 'Escape' && open) {
        e.preventDefault();
        e.stopImmediatePropagation();
        setOpen(false);
      }
    }
    // capture: true so we run before Fumadocs' (default-phase) handler.
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [open]);

  // Focus the input when the palette opens; reset query on close.
  useEffect(() => {
    if (open) {
      // requestAnimationFrame ensures the input is mounted + visible
      // before we try to focus it.
      requestAnimationFrame(() => inputRef.current?.focus());
    } else {
      setQuery('');
      setActive(0);
    }
  }, [open]);

  const results = useMemo(() => filterIndex(INDEX, query), [query]);

  // Keep `active` in bounds when results shrink.
  useEffect(() => {
    if (active >= results.length) setActive(Math.max(0, results.length - 1));
  }, [results.length, active]);

  function commit(entry: IndexEntry | undefined) {
    if (!entry) return;
    setOpen(false);
    onJump(entry.sectionId);
    // Defer so the section can expand before we scroll/flash.
    requestAnimationFrame(() => {
      const el = document.getElementById(`section-${entry.sectionId}`);
      if (!el) return;
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      el.classList.add('dc-cmdk-flash');
      window.setTimeout(() => el.classList.remove('dc-cmdk-flash'), 1400);
    });
  }

  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center p-4 sm:pt-[12vh]"
      onClick={() => setOpen(false)}
      // Keep keyboard focus inside the modal.
      role="dialog"
      aria-modal="true"
      aria-label="Search policy knobs"
    >
      <div
        className="absolute inset-0 bg-black/40 backdrop-blur-[2px]"
        aria-hidden="true"
      />
      <div
        className="relative z-10 w-full max-w-xl overflow-hidden rounded-xl border border-fd-border bg-fd-card shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 border-b border-fd-border px-3 py-2">
          <span aria-hidden className="text-fd-muted-foreground">⌕</span>
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setActive((a) => Math.min(results.length - 1, a + 1));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActive((a) => Math.max(0, a - 1));
              } else if (e.key === 'Enter') {
                e.preventDefault();
                commit(results[active]);
              }
            }}
            placeholder="Search knobs (e.g. 'hilt severity', 'splunk token', 'block threshold')"
            className="flex-1 bg-transparent text-sm text-fd-foreground placeholder:text-fd-muted-foreground focus:outline-none"
          />
          <kbd className="rounded border border-fd-border bg-fd-background px-1.5 py-0.5 text-[10px] text-fd-muted-foreground">
            Esc
          </kbd>
        </div>
        <ul className="max-h-[50vh] overflow-auto py-1" role="listbox">
          {results.length === 0 && (
            <li className="px-3 py-4 text-center text-xs text-fd-muted-foreground">
              No matches. Try a section name or a knob keyword.
            </li>
          )}
          {results.map((r, i) => (
            <li key={`${r.sectionId}/${r.label}`} role="option" aria-selected={i === active}>
              <button
                type="button"
                onMouseEnter={() => setActive(i)}
                onClick={() => commit(r)}
                className={[
                  'flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-sm transition',
                  i === active
                    ? 'bg-[var(--brand-cisco)]/15 text-fd-foreground'
                    : 'text-fd-foreground/90 hover:bg-fd-muted/40',
                ].join(' ')}
              >
                <span className="truncate">{r.label}</span>
                <span className="shrink-0 rounded-md border border-fd-border bg-fd-background px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-fd-muted-foreground">
                  {r.group}
                </span>
              </button>
            </li>
          ))}
        </ul>
        <div className="flex items-center justify-between border-t border-fd-border bg-fd-background px-3 py-1.5 text-[10px] text-fd-muted-foreground">
          <span>
            <kbd className="rounded border border-fd-border bg-fd-card px-1">↑↓</kbd> navigate
            <span className="mx-2">·</span>
            <kbd className="rounded border border-fd-border bg-fd-card px-1">↵</kbd> jump
          </span>
          <span>{results.length} match{results.length === 1 ? '' : 'es'}</span>
        </div>
      </div>
      {/* Scoped flash style. We attach a class to the section root and
       *  fade it out after ~1.4s so the operator sees where they landed. */}
      <style>{`
        .dc-cmdk-flash {
          animation: dc-cmdk-flash 1.2s ease-out;
        }
        @keyframes dc-cmdk-flash {
          0%   { box-shadow: 0 0 0 0 var(--brand-cisco, #00bceb); }
          50%  { box-shadow: 0 0 0 6px rgba(0,188,235,0.30); }
          100% { box-shadow: 0 0 0 0 rgba(0,188,235,0); }
        }
      `}</style>
    </div>
  );
}

/** Hint button operators can click to discover the shortcut. */
export function CommandPaletteHint() {
  return (
    <span className="hidden items-center gap-1 text-[11px] text-fd-muted-foreground sm:inline-flex">
      <kbd className="rounded border border-fd-border bg-fd-background px-1 py-px text-[10px]">⌘K</kbd>
      <span>to search knobs</span>
    </span>
  );
}

// ── filtering ───────────────────────────────────────────────────────

function filterIndex(idx: IndexEntry[], q: string): IndexEntry[] {
  const trimmed = q.trim().toLowerCase();
  if (!trimmed) return idx;
  // Token AND-match: every whitespace-separated token must appear in
  // (label + group + keywords) somewhere. This handles natural typing
  // like "splunk token" → matches "Splunk HEC sink" via its keywords.
  const tokens = trimmed.split(/\s+/);
  const scored: Array<{ entry: IndexEntry; score: number }> = [];
  for (const entry of idx) {
    const hay = [
      entry.label.toLowerCase(),
      entry.group.toLowerCase(),
      ...(entry.keywords ?? []).map((k) => k.toLowerCase()),
    ].join(' | ');
    let ok = true;
    let score = 0;
    for (const t of tokens) {
      const at = hay.indexOf(t);
      if (at < 0) {
        ok = false;
        break;
      }
      // Earlier matches score higher; label hits score higher than
      // keyword hits.
      score += entry.label.toLowerCase().includes(t) ? 100 - at : 50 - at;
    }
    if (ok) scored.push({ entry, score });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.map((s) => s.entry);
}
