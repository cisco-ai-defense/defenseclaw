// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Quick Start interview — six-step wizard. One question per screen, a
// breadcrumb stepper at the top, and Back/Next at the bottom. The
// final "Review" step is the only one that surfaces the live policy
// summary + scenario evaluator, so the question screens stay calm.
//
// State model: parent owns `policy` + `answers`. We rebuild `policy`
// from `answers` on every change via applyAnswers(); the parent's
// setPolicy lifts the result so the Playground tab + localStorage
// stay in sync. Step index is owned here and persisted to its own
// localStorage key so a refresh keeps you where you were.

'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import type { Policy } from '../types';
import { emit } from '../lib/emit';
import { emitInstallScript } from '../lib/emit-script';
import { LiveTestPane } from '../sections/live-test';
import { CopyButton } from '../ui/copy-button';
import { DownloadButton } from '../ui/download-button';
import { applyAnswers } from './apply';
import { PreviewDrawer } from './preview-drawer';
import { PolicySummaryCard } from './summary';
import {
  ALLOW_CARDS,
  BLOCK_CARDS,
  BLOCK_CATEGORIES,
  POSTURES,
  RESPONSES,
  SINK_CARDS,
  type Answers,
  type AllowCard,
  type BlockCard,
  type SinkCard,
} from './questions';

// Next.js `basePath` ("" or "/defenseclaw") gets baked into the client
// bundle via NEXT_PUBLIC_BASE_PATH in next.config. Cookbook links are
// just plain anchors (we want them to open in a new tab so the
// interview state stays intact), so we prefix manually here — Next's
// <Link> would do this for us, but only for in-app navigations.
const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH ?? '';
function docsHref(path: string): string {
  return `${BASE_PATH}${path}`;
}

const STEP_KEY = 'dc-policy-creator/quickstart/step/v1';

const STEPS = [
  { id: 'posture', label: 'Posture' },
  { id: 'block', label: 'Block' },
  { id: 'allow', label: 'Allow' },
  { id: 'response', label: 'Response' },
  { id: 'sinks', label: 'Sinks' },
  { id: 'review', label: 'Review' },
] as const;

type StepId = (typeof STEPS)[number]['id'];

export interface QuickStartProps {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
  answers: Answers;
  onAnswersChange: (next: Answers) => void;
  onOpenInPlayground: () => void;
}

export function QuickStart({
  policy,
  onPolicyChange,
  answers,
  onAnswersChange,
  onOpenInPlayground,
}: QuickStartProps) {
  // Re-derive Policy from Answers whenever they change. We compare via
  // a ref to avoid an infinite render loop (policy → setPolicy → re-
  // render → re-derive → setPolicy …).
  const lastSerialized = useRef('');
  useEffect(() => {
    const next = applyAnswers(answers);
    const ser = JSON.stringify(next);
    if (ser === lastSerialized.current) return;
    lastSerialized.current = ser;
    onPolicyChange(next);
  }, [answers, onPolicyChange]);

  // Step index. Hydrate from localStorage on mount only — SSR returns
  // 0 to keep first paint stable.
  const [stepIdx, setStepIdx] = useState(0);
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(STEP_KEY);
      if (raw !== null) {
        const n = Number.parseInt(raw, 10);
        if (Number.isFinite(n) && n >= 0 && n < STEPS.length) setStepIdx(n);
      }
    } catch {
      // Storage may be denied (private mode, sandbox); harmless to skip.
    }
    setHydrated(true);
  }, []);
  useEffect(() => {
    if (!hydrated) return;
    try {
      window.localStorage.setItem(STEP_KEY, String(stepIdx));
    } catch {
      // Same harmless path as above.
    }
  }, [stepIdx, hydrated]);

  // Helpers that return a NEW Answers without mutating the caller's
  // copy (Sets are reference types).
  function update(mut: (draft: Answers) => void) {
    const draft: Answers = {
      ...answers,
      block: new Set(answers.block),
      allow: new Set(answers.allow),
      firstPartyExtra: [...answers.firstPartyExtra],
      domainsExtra: [...answers.domainsExtra],
      sinks: { ...answers.sinks },
    };
    mut(draft);
    onAnswersChange(draft);
  }

  const current = STEPS[stepIdx];
  const isFirst = stepIdx === 0;
  const isLast = stepIdx === STEPS.length - 1;
  // Install script + per-file emit are pure functions of `policy`. We
  // compute once here so the Review step and the sticky footer share
  // the same string (and the same useMemo cache key) — emit() walks
  // the whole policy graph so it isn't free.
  const installScript = useMemo(() => emitInstallScript(policy), [policy]);
  const installFilename = `install-${policy.name}.sh`;

  return (
    <>
    <div className="space-y-4">
      <Stepper steps={STEPS} current={stepIdx} onJump={setStepIdx} />

      <section className="rounded-xl border border-fd-border bg-fd-background p-4 md:p-5">
        {current.id === 'posture' && (
          <StepPosture answers={answers} update={update} />
        )}
        {current.id === 'block' && (
          <StepBlock answers={answers} update={update} />
        )}
        {current.id === 'allow' && (
          <StepAllow answers={answers} update={update} />
        )}
        {current.id === 'response' && (
          <StepResponse answers={answers} update={update} />
        )}
        {current.id === 'sinks' && (
          <StepSinks answers={answers} update={update} />
        )}
        {current.id === 'review' && (
          <StepReview
            policy={policy}
            answers={answers}
            installScript={installScript}
            installFilename={installFilename}
            onOpenInPlayground={onOpenInPlayground}
          />
        )}
      </section>

      <footer className="sticky bottom-2 flex items-center gap-2 rounded-xl border border-fd-border bg-fd-card p-3 shadow-lg">
        <button
          type="button"
          onClick={() => setStepIdx((n) => Math.max(0, n - 1))}
          disabled={isFirst}
          className="rounded-lg border border-fd-border bg-fd-background px-3 py-1.5 text-sm font-medium hover:border-fd-foreground/30 disabled:cursor-not-allowed disabled:opacity-40"
        >
          ← Back
        </button>
        <span className="text-[12px] text-fd-muted-foreground">
          Step {stepIdx + 1} of {STEPS.length}
        </span>
        <div className="ml-auto flex items-center gap-2">
          {!isLast && (
            <button
              type="button"
              onClick={() => setStepIdx((n) => Math.min(STEPS.length - 1, n + 1))}
              className="rounded-lg bg-[var(--brand-cisco)] px-4 py-1.5 text-sm font-semibold text-white shadow-sm hover:opacity-95"
            >
              Next →
            </button>
          )}
          {isLast && (
            <>
              <DownloadButton
                filename={installFilename}
                contents={installScript}
                mime="text/x-shellscript"
                label={`Download ${installFilename}`}
                size="md"
                variant="primary"
              />
              <button
                type="button"
                onClick={onOpenInPlayground}
                className="rounded-lg border border-fd-border bg-fd-background px-3 py-1.5 text-sm font-medium text-fd-foreground hover:border-[var(--brand-cisco)] hover:bg-[var(--brand-cisco)]/10"
              >
                Open in Playground →
              </button>
            </>
          )}
        </div>
      </footer>
    </div>
    {/* Floating verdict-preview pinned to bottom-right. Hidden on the
     *  Review step since the LiveTestPane is already rendered inline
     *  there. */}
    <PreviewDrawer policy={policy} hidden={current.id === 'review'} />
    </>
  );
}

// ── Stepper ─────────────────────────────────────────────────────────

function Stepper({
  steps,
  current,
  onJump,
}: {
  steps: ReadonlyArray<{ id: StepId; label: string }>;
  current: number;
  onJump: (idx: number) => void;
}) {
  return (
    <ol className="flex flex-wrap items-center gap-1.5 rounded-xl border border-fd-border bg-fd-background p-2">
      {steps.map((s, i) => {
        const state = i < current ? 'done' : i === current ? 'active' : 'pending';
        return (
          <li key={s.id} className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => onJump(i)}
              className={[
                'flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[12px] font-medium transition',
                state === 'active'
                  ? 'bg-[var(--brand-cisco)] text-white'
                  : state === 'done'
                    ? 'bg-fd-card text-fd-foreground hover:border-fd-foreground/30'
                    : 'text-fd-muted-foreground hover:text-fd-foreground',
              ].join(' ')}
            >
              <span
                className={[
                  'inline-flex size-5 items-center justify-center rounded-full text-[10px] font-mono',
                  state === 'active'
                    ? 'bg-white/20'
                    : state === 'done'
                      ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                      : 'bg-fd-card',
                ].join(' ')}
                aria-hidden
              >
                {state === 'done' ? '✓' : i + 1}
              </span>
              {s.label}
            </button>
            {i < steps.length - 1 && (
              <span aria-hidden className="text-[10px] text-fd-muted-foreground">
                ›
              </span>
            )}
          </li>
        );
      })}
    </ol>
  );
}

// ── Step renderers ──────────────────────────────────────────────────

interface StepProps {
  answers: Answers;
  update: (mut: (draft: Answers) => void) => void;
}

function StepHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <header className="mb-4">
      <h3 className="text-base font-semibold text-fd-foreground">{title}</h3>
      {subtitle && <p className="mt-0.5 text-[12px] text-fd-muted-foreground">{subtitle}</p>}
    </header>
  );
}

function StepPosture({ answers, update }: StepProps) {
  return (
    <>
      <StepHeader
        title="What posture should we start from?"
        subtitle="Picks a base preset. You'll layer your block / allow choices on top."
      />
      <div className="grid gap-2 md:grid-cols-3">
        {POSTURES.map((p) => (
          <RadioCard
            key={p.id}
            checked={answers.posture === p.id}
            title={p.title}
            description={p.description}
            onSelect={() => update((d) => void (d.posture = p.id))}
          />
        ))}
      </div>
    </>
  );
}

function StepBlock({ answers, update }: StepProps) {
  // Group the cards by category so the grid never feels like one long
  // wall of checkboxes. The category ordering is taken from
  // BLOCK_CATEGORIES so questions.ts stays the source of truth.
  const grouped = useMemo(() => {
    const map = new Map<string, BlockCard[]>();
    for (const c of BLOCK_CATEGORIES) map.set(c.id, []);
    for (const card of BLOCK_CARDS) {
      const bucket = map.get(card.category);
      if (bucket) bucket.push(card);
    }
    return map;
  }, []);
  return (
    <>
      <StepHeader
        title="What should we block?"
        subtitle="Pick everything you want flagged. We'll enable the matching rules and add destinations to the firewall."
      />
      <div className="space-y-5">
        {BLOCK_CATEGORIES.map((cat) => {
          const cards = grouped.get(cat.id) ?? [];
          if (cards.length === 0) return null;
          return (
            <div key={cat.id} className="space-y-2">
              <div className="flex items-baseline gap-2">
                <h4 className="text-[12px] font-semibold uppercase tracking-wide text-fd-muted-foreground">
                  {cat.title}
                </h4>
                <span className="text-[11px] text-fd-muted-foreground/80">{cat.blurb}</span>
              </div>
              <div className="grid gap-2 md:grid-cols-2">
                {cards.map((card) => (
                  <CheckCard
                    key={card.id}
                    card={card}
                    checked={answers.block.has(card.id)}
                    onToggle={() =>
                      update((d) => {
                        if (d.block.has(card.id)) d.block.delete(card.id);
                        else d.block.add(card.id);
                      })
                    }
                  />
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </>
  );
}

function StepAllow({ answers, update }: StepProps) {
  return (
    <>
      <StepHeader
        title="What should we allow even when flagged?"
        subtitle="Reduce alert noise by letting known-safe tools / domains / first-party plugins through."
      />
      <div className="grid gap-2 md:grid-cols-2">
        {ALLOW_CARDS.map((card) => (
          <AllowCheckCard
            key={card.id}
            card={card}
            checked={answers.allow.has(card.id)}
            onToggle={() =>
              update((d) => {
                if (d.allow.has(card.id)) d.allow.delete(card.id);
                else d.allow.add(card.id);
              })
            }
          />
        ))}
      </div>
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <FreeFormList
          label="Additional first-party globs"
          placeholder="my-org/*"
          items={answers.firstPartyExtra}
          onChange={(next) => update((d) => void (d.firstPartyExtra = next))}
          hint="One per line. Matches a target_name on the first-party allow list."
        />
        <FreeFormList
          label="Additional internal domains"
          placeholder="*.corp.internal"
          items={answers.domainsExtra}
          onChange={(next) => update((d) => void (d.domainsExtra = next))}
          hint="One per line. Added to firewall.allowed_domains."
        />
      </div>
    </>
  );
}

function StepResponse({ answers, update }: StepProps) {
  return (
    <>
      <StepHeader
        title="When something risky happens, what should we do?"
        subtitle="Sets the block / alert thresholds and HILT (human-in-the-loop) configuration."
      />
      <div className="grid gap-2 md:grid-cols-2">
        {RESPONSES.map((r) => (
          <RadioCard
            key={r.id}
            checked={answers.response === r.id}
            title={r.title}
            description={r.description}
            onSelect={() => update((d) => void (d.response = r.id))}
          />
        ))}
      </div>
    </>
  );
}

function StepSinks({ answers, update }: StepProps) {
  return (
    <>
      <StepHeader
        title="Where should events go?"
        subtitle="Wire one or more destinations. Local audit log is on by default — turn it off only if you really mean to."
      />
      <div className="space-y-2">
        {SINK_CARDS.map((card) => (
          <SinkRow
            key={card.id}
            card={card}
            value={answers.sinks[card.id]}
            onToggle={(enabled) =>
              update((d) => {
                d.sinks = { ...d.sinks, [card.id]: { ...d.sinks[card.id], enabled } };
              })
            }
            onChangeField={(key, val) =>
              update((d) => {
                d.sinks = { ...d.sinks, [card.id]: { ...d.sinks[card.id], [key]: val } };
              })
            }
          />
        ))}
      </div>
    </>
  );
}

function StepReview({
  policy,
  answers,
  installScript,
  installFilename,
  onOpenInPlayground,
}: {
  policy: Policy;
  answers: Answers;
  installScript: string;
  installFilename: string;
  onOpenInPlayground: () => void;
}) {
  // emit() walks the full Policy graph so this useMemo matters; the
  // install-script string is computed once in the parent and lifted
  // down so the footer shares the cache.
  const files = useMemo(() => emit(policy), [policy]);

  return (
    <>
      <StepHeader
        title="Review your policy"
        subtitle="Test it against canned scenarios on the right, then download the install script — or jump into the Playground if you want to fine-tune anything."
      />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(280px,1fr)]">
        <PolicySummaryCard policy={policy} answers={answers} />
        <LiveTestPane policy={policy} />
      </div>

      {/* Primary CTA: download the self-contained install script. */}
      <div className="mt-4 rounded-lg border border-[var(--brand-cisco)]/50 bg-[var(--brand-cisco)]/5 p-4">
        <div className="flex flex-wrap items-start gap-3">
          <div className="min-w-[200px] flex-1">
            <div className="text-sm font-semibold text-fd-foreground">Download &amp; run</div>
            <p className="mt-0.5 text-[12px] leading-snug text-fd-muted-foreground">
              One self-contained bash script. Drops every YAML / <code>data.json</code> / Rego file
              under <code>~/.defenseclaw/policies/</code> via heredocs (no curl, no scp), then
              runs <code>defenseclaw policy activate {policy.name}</code>. Re-runs are idempotent.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <DownloadButton
              filename={installFilename}
              contents={installScript}
              mime="text/x-shellscript"
              label={installFilename}
              size="md"
              variant="primary"
            />
            <CopyButton value={installScript} label="Copy script" />
          </div>
        </div>
      </div>

      {/* Secondary: per-file downloads for operators who want to drop a
       *  single YAML into a config repo without running the script. */}
      <details className="mt-3 rounded-lg border border-fd-border bg-fd-background p-3">
        <summary className="cursor-pointer text-[12px] font-medium text-fd-foreground">
          Or download individual files ({files.length})
        </summary>
        <ul className="mt-2 space-y-1.5">
          {files.map((f) => (
            <li
              key={f.path}
              className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-fd-border bg-fd-card p-2"
            >
              <div className="min-w-0 flex-1">
                <div className="truncate font-mono text-[11px] text-fd-foreground">{f.path}</div>
                <div className="text-[10px] text-fd-muted-foreground">{f.description}</div>
              </div>
              <div className="flex gap-1">
                <DownloadButton
                  filename={pathBase(f.path)}
                  contents={f.contents}
                  mime="text/plain"
                  label={pathBase(f.path)}
                />
                <CopyButton value={f.contents} label="Copy" />
              </div>
            </li>
          ))}
        </ul>
      </details>

      {/* Tertiary: hand off to Playground for fine-tuning. */}
      <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border border-fd-border bg-fd-background p-3 text-[12px] text-fd-muted-foreground">
        <span>
          Want to see the generated YAML side-by-side, edit a rule, or write custom Rego?
        </span>
        <button
          type="button"
          onClick={onOpenInPlayground}
          className="ml-auto rounded-md border border-fd-border bg-fd-background px-3 py-1.5 text-sm font-medium text-fd-foreground hover:border-[var(--brand-cisco)] hover:bg-[var(--brand-cisco)]/10"
        >
          Open in Playground →
        </button>
      </div>
    </>
  );
}

function pathBase(path: string): string {
  const parts = path.split('/');
  return parts[parts.length - 1] ?? path;
}

// ── Building blocks ─────────────────────────────────────────────────

function RadioCard({
  checked,
  title,
  description,
  onSelect,
}: {
  checked: boolean;
  title: string;
  description: string;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={checked}
      onClick={onSelect}
      className={[
        'flex flex-col items-start gap-1 rounded-lg border p-3 text-left transition',
        checked
          ? 'border-[var(--brand-cisco)] bg-[var(--brand-cisco)]/5 ring-1 ring-[var(--brand-cisco)]'
          : 'border-fd-border bg-fd-card hover:border-fd-foreground/20',
      ].join(' ')}
    >
      <span className="text-sm font-semibold text-fd-foreground">{title}</span>
      <span className="text-[11px] leading-snug text-fd-muted-foreground">{description}</span>
    </button>
  );
}

function CheckCard({
  card,
  checked,
  onToggle,
}: {
  card: BlockCard;
  checked: boolean;
  onToggle: () => void;
}) {
  return (
    <div
      className={[
        'flex flex-col gap-2 rounded-lg border p-3 transition',
        checked
          ? 'border-[var(--brand-cisco)] bg-[var(--brand-cisco)]/5 ring-1 ring-[var(--brand-cisco)]'
          : 'border-fd-border bg-fd-card hover:border-fd-foreground/20',
      ].join(' ')}
    >
      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          checked={checked}
          onChange={onToggle}
          className="mt-0.5 size-4 cursor-pointer accent-[var(--brand-cisco)]"
        />
        <span className="flex-1">
          <span className="block text-sm font-semibold text-fd-foreground">{card.title}</span>
          <span className="mt-0.5 block text-[11px] leading-snug text-fd-muted-foreground">
            {card.description}
          </span>
        </span>
      </label>
      <div className="flex flex-wrap items-center gap-1.5 pl-6 text-[10px] text-fd-muted-foreground">
        {card.ruleIds.length > 0 && (
          <span className="rounded bg-fd-muted px-1.5 py-0.5 font-mono">
            {card.ruleIds.length} rule{card.ruleIds.length === 1 ? '' : 's'}
          </span>
        )}
        {(card.destinations?.length ?? 0) > 0 && (
          <span className="rounded bg-fd-muted px-1.5 py-0.5 font-mono">
            {card.destinations!.length} firewall destination
            {card.destinations!.length === 1 ? '' : 's'}
          </span>
        )}
        {card.cookbookHref && (
          <a
            href={docsHref(card.cookbookHref)}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-auto text-[10px] text-[var(--brand-cisco)] hover:underline"
          >
            see cookbook →
          </a>
        )}
      </div>
    </div>
  );
}

function AllowCheckCard({
  card,
  checked,
  onToggle,
}: {
  card: AllowCard;
  checked: boolean;
  onToggle: () => void;
}) {
  return (
    <div
      className={[
        'flex flex-col gap-2 rounded-lg border p-3 transition',
        checked
          ? 'border-emerald-500 bg-emerald-500/5 ring-1 ring-emerald-500'
          : 'border-fd-border bg-fd-card hover:border-fd-foreground/20',
      ].join(' ')}
    >
      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          checked={checked}
          onChange={onToggle}
          className="mt-0.5 size-4 cursor-pointer accent-emerald-500"
        />
        <span className="flex-1">
          <span className="block text-sm font-semibold text-fd-foreground">{card.title}</span>
          <span className="mt-0.5 block text-[11px] leading-snug text-fd-muted-foreground">
            {card.description}
          </span>
        </span>
      </label>
      <div className="flex flex-wrap items-center gap-1.5 pl-6 text-[10px] text-fd-muted-foreground">
        {card.toolPattern && (
          <code className="rounded bg-fd-muted px-1.5 py-0.5 font-mono">{card.toolPattern}</code>
        )}
        {card.cookbookHref && (
          <a
            href={docsHref(card.cookbookHref)}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-auto text-[10px] text-emerald-600 hover:underline dark:text-emerald-400"
          >
            see cookbook →
          </a>
        )}
      </div>
    </div>
  );
}

function FreeFormList({
  label,
  placeholder,
  items,
  onChange,
  hint,
}: {
  label: string;
  placeholder: string;
  items: string[];
  onChange: (next: string[]) => void;
  hint?: string;
}) {
  const [pending, setPending] = useState('');
  const add = () => {
    const t = pending.trim();
    if (!t) return;
    if (items.includes(t)) {
      setPending('');
      return;
    }
    onChange([...items, t]);
    setPending('');
  };
  return (
    <div className="space-y-1.5">
      <label className="block text-[11px] font-medium uppercase tracking-wide text-fd-muted-foreground">
        {label}
      </label>
      <div className="flex gap-1.5">
        <input
          type="text"
          value={pending}
          onChange={(e) => setPending(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              add();
            }
          }}
          placeholder={placeholder}
          className="flex-1 rounded-md border border-fd-border bg-fd-background px-2 py-1.5 font-mono text-[11px] text-fd-foreground placeholder:text-fd-muted-foreground/60 focus:border-[var(--brand-cisco)] focus:outline-none"
        />
        <button
          type="button"
          onClick={add}
          className="rounded-md border border-fd-border bg-fd-background px-2 py-1.5 text-[11px] hover:border-[var(--brand-cisco)]"
        >
          + Add
        </button>
      </div>
      {items.length > 0 && (
        <ul className="space-y-1">
          {items.map((it, i) => (
            <li
              key={`${it}-${i}`}
              className="flex items-center justify-between gap-2 rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px]"
            >
              <code className="truncate font-mono">{it}</code>
              <button
                type="button"
                onClick={() => onChange(items.filter((_, idx) => idx !== i))}
                className="text-fd-muted-foreground hover:text-red-500"
                aria-label={`Remove ${it}`}
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}
      {hint && <p className="text-[10px] text-fd-muted-foreground">{hint}</p>}
    </div>
  );
}

function SinkRow({
  card,
  value,
  onToggle,
  onChangeField,
}: {
  card: SinkCard;
  value: { enabled: boolean; url: string; secret_env: string } | undefined;
  onToggle: (enabled: boolean) => void;
  onChangeField: (key: 'url' | 'secret_env', val: string) => void;
}) {
  const enabled = value?.enabled ?? false;
  return (
    <div
      className={[
        'rounded-lg border p-3 transition',
        enabled
          ? 'border-[var(--brand-cisco)] bg-[var(--brand-cisco)]/5'
          : 'border-fd-border bg-fd-card',
      ].join(' ')}
    >
      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => onToggle(e.target.checked)}
          className="mt-0.5 size-4 cursor-pointer accent-[var(--brand-cisco)]"
        />
        <span className="flex-1">
          <span className="block text-sm font-semibold text-fd-foreground">{card.title}</span>
          <span className="mt-0.5 block text-[11px] leading-snug text-fd-muted-foreground">
            {card.description}
          </span>
        </span>
      </label>
      {enabled && card.configFields && (
        <div className="mt-2 grid grid-cols-1 gap-2 pl-6 md:grid-cols-2">
          {card.configFields.map((f) => (
            <label key={f.key} className="flex flex-col gap-1">
              <span className="text-[10px] font-medium uppercase tracking-wide text-fd-muted-foreground">
                {f.label}
              </span>
              <input
                type="text"
                value={value?.[f.key] ?? ''}
                onChange={(e) => onChangeField(f.key, e.target.value)}
                placeholder={f.placeholder}
                spellCheck={false}
                className="rounded-md border border-fd-border bg-fd-background px-2 py-1 font-mono text-[11px] focus:border-[var(--brand-cisco)] focus:outline-none"
              />
            </label>
          ))}
        </div>
      )}
    </div>
  );
}
