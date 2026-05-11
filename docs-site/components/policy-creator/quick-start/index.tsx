// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Quick Start interview — five card-based question groups laid out as a
// single scrollable page. Right rail shows the "Policy summary" card +
// the existing Live Test pane (re-evaluated on every answer change).
//
// State model: the parent owns both `policy` and `answers`. We rebuild
// `policy` from `answers` on every change via applyAnswers(); the
// parent's setPolicy lifts the result so the Playground tab and
// localStorage stay in sync.

'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import type { Policy } from '../types';
import { LiveTestPane } from '../sections/live-test';
import { applyAnswers } from './apply';
import { PolicySummaryCard } from './summary';
import {
  ALLOW_CARDS,
  BLOCK_CARDS,
  POSTURES,
  RESPONSES,
  SINK_CARDS,
  type Answers,
  type AllowCard,
  type BlockCard,
  type SinkCard,
} from './questions';

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

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
      {/* ── Left column: questions ───────────────────────────────── */}
      <div className="space-y-5">
        <header className="rounded-xl border border-fd-border bg-fd-background p-4">
          <h2 className="text-base font-semibold text-fd-foreground">Quick start</h2>
          <p className="mt-0.5 text-[12px] leading-snug text-fd-muted-foreground">
            Answer five questions and we&apos;ll assemble a complete policy. Watch the right
            rail update as you go. When you&apos;re done, hop into the Playground for
            fine-tuning or copy the install script straight from there.
          </p>
        </header>

        {/* Q1 — posture */}
        <QuestionGroup
          number={1}
          title="What posture should we start from?"
          subtitle="Picks a base preset. You&rsquo;ll layer your block / allow choices on top."
        >
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
        </QuestionGroup>

        {/* Q2 — block */}
        <QuestionGroup
          number={2}
          title="What should we block?"
          subtitle="Pick everything you want flagged. We&rsquo;ll enable the matching rules and add destinations to the firewall."
        >
          <div className="grid gap-2 md:grid-cols-2">
            {BLOCK_CARDS.map((card) => (
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
        </QuestionGroup>

        {/* Q3 — allow */}
        <QuestionGroup
          number={3}
          title="What should we allow even when flagged?"
          subtitle="Reduce alert noise by letting known-safe tools / domains / first-party plugins through."
        >
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
        </QuestionGroup>

        {/* Q4 — response */}
        <QuestionGroup
          number={4}
          title="When something risky happens, what should we do?"
          subtitle="Sets the block / alert thresholds and HILT (human-in-the-loop) configuration."
        >
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
        </QuestionGroup>

        {/* Q5 — sinks */}
        <QuestionGroup
          number={5}
          title="Where should events go?"
          subtitle="Wire one or more destinations. Local audit log is on by default \u2014 turn it off only if you really mean to."
        >
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
        </QuestionGroup>

        <div className="sticky bottom-2 flex flex-wrap items-center gap-2 rounded-xl border border-fd-border bg-fd-card p-3 shadow-lg">
          <span className="text-[12px] text-fd-muted-foreground">
            Done? Pre-fill the Playground with these choices and fine-tune anything you like.
          </span>
          <button
            type="button"
            onClick={onOpenInPlayground}
            className="ml-auto rounded-lg bg-[var(--brand-cisco)] px-4 py-2 text-sm font-semibold text-white shadow-sm hover:opacity-95"
          >
            Open in Playground →
          </button>
        </div>
      </div>

      {/* ── Right column: live policy + scenario test ───────────── */}
      <aside className="space-y-3 lg:sticky lg:top-20 lg:max-h-[calc(100vh-6rem)] lg:overflow-auto">
        <PolicySummaryCard policy={policy} answers={answers} />
        <LiveTestPane policy={policy} />
      </aside>
    </div>
  );
}

// ── Building blocks ─────────────────────────────────────────────────

function QuestionGroup({
  number,
  title,
  subtitle,
  children,
}: {
  number: number;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-2 rounded-xl border border-fd-border bg-fd-background p-4">
      <header className="flex items-baseline gap-2">
        <span className="rounded-md bg-fd-card px-1.5 py-0.5 text-[11px] font-mono text-fd-muted-foreground">
          Q{number}
        </span>
        <h3 className="text-sm font-semibold text-fd-foreground">{title}</h3>
      </header>
      {subtitle && <p className="text-[11px] text-fd-muted-foreground">{subtitle}</p>}
      <div className="pt-2">{children}</div>
    </section>
  );
}

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
            {card.destinations!.length} firewall destination{card.destinations!.length === 1 ? '' : 's'}
          </span>
        )}
        {card.cookbookHref && (
          <a
            href={card.cookbookHref}
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
            href={card.cookbookHref}
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
    <div className="space-y-1.5 pt-3">
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
