// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Top-level entrypoint for the docs-site policy creator. Renders a
// 2-tab shell:
//
//   ┌───────────────────────────────────────────────────────────┐
//   │  [ Quick start ]  [ Playground ]                          │
//   ├───────────────────────────────────────────────────────────┤
//   │  Active tab content                                       │
//   └───────────────────────────────────────────────────────────┘
//
// Both tabs read and write the SAME `policy` state, so an operator can
// answer the Quick Start interview, hop into the Playground for a
// targeted tweak, and hop back without losing work. The handoff banner
// in the Playground signals when state arrived from the interview.
//
// Persistence: the active tab + the current Policy + the Quick Start
// answers all live in localStorage so a refresh is non-destructive.
// Nothing leaves the browser.

'use client';

import { useEffect, useMemo, useState } from 'react';
import type { Policy } from './types';
import { policyFromPreset } from './lib/presets';
import { Playground } from './playground';
import { QuickStart } from './quick-start';
import type { Answers } from './quick-start/questions';
import { defaultAnswers, deserializeAnswers, serializeAnswers } from './quick-start/questions';
import { clearHashPayload, decodePolicyFromHash, readHashPayload } from './lib/share';

type TabId = 'quick-start' | 'playground';

const LS_TAB = 'dc-policy-creator-tab';
const LS_POLICY = 'dc-policy-creator-policy';
const LS_ANSWERS = 'dc-policy-creator-answers';

export default function PolicyCreator() {
  // Lazy initial state: build the default-preset policy once. Replaced
  // immediately if localStorage has a saved copy.
  const initialPolicy = useMemo(() => policyFromPreset('default'), []);
  const [policy, setPolicy] = useState<Policy>(initialPolicy);
  const [answers, setAnswers] = useState<Answers>(defaultAnswers());
  const [tab, setTab] = useState<TabId>('quick-start');
  const [hydrated, setHydrated] = useState(false);
  // Tracks whether the most recent `policy` mutation came from the
  // Quick Start interview. Used by the Playground to render the
  // handoff banner and the "restart Quick Start" affordance.
  const [arrivedFromQuickStart, setArrivedFromQuickStart] = useState(false);

  // Hydrate persisted state on mount. We delay setting `hydrated` until
  // after the first paint so SSR and CSR trees agree.
  useEffect(() => {
    let restoredFromLs = false;
    try {
      const rawTab = window.localStorage.getItem(LS_TAB);
      if (rawTab === 'playground' || rawTab === 'quick-start') setTab(rawTab);
      const rawPolicy = window.localStorage.getItem(LS_POLICY);
      if (rawPolicy) {
        setPolicy(JSON.parse(rawPolicy) as Policy);
        restoredFromLs = true;
      }
      const rawAnswers = window.localStorage.getItem(LS_ANSWERS);
      if (rawAnswers) setAnswers(deserializeAnswers(JSON.parse(rawAnswers)));
    } catch {
      /* malformed — keep initial */
    }

    // After localStorage, check whether the URL has #policy=… from a
    // share link and offer to load it. We do this asynchronously
    // because decompression is async; the page is already interactive
    // by then (with the localStorage-restored draft visible).
    const payload = readHashPayload();
    if (payload) {
      void (async () => {
        const shared = await decodePolicyFromHash(payload);
        if (!shared) {
          // Bad payload — strip it so the URL bar isn't lying about
          // having a draft, but don't show a noisy error.
          clearHashPayload();
          return;
        }
        const proceed =
          !restoredFromLs ||
          window.confirm(
            'Load policy from share link? Your in-progress draft in this browser will be replaced.',
          );
        if (proceed) {
          setPolicy(shared);
          // Reset answers — share link only carries the Policy, not
          // the Quick Start answer state. Operator can re-derive by
          // walking through the wizard if they want to.
          setAnswers(defaultAnswers());
          // Switch to Playground; share links almost always intend
          // "review the policy I just sent you" rather than "redo
          // the interview".
          setTab('playground');
        }
        clearHashPayload();
      })();
    }

    setHydrated(true);
  }, []);

  // Persist on every change. Skipping the first paint avoids overwriting
  // a saved state with the default-preset placeholder.
  useEffect(() => {
    if (!hydrated) return;
    try {
      window.localStorage.setItem(LS_POLICY, JSON.stringify(policy));
    } catch {
      /* quota / private mode — drop silently */
    }
  }, [policy, hydrated]);
  useEffect(() => {
    if (!hydrated) return;
    try {
      window.localStorage.setItem(LS_ANSWERS, JSON.stringify(serializeAnswers(answers)));
    } catch {
      /* quota / private mode — drop silently */
    }
  }, [answers, hydrated]);
  useEffect(() => {
    if (!hydrated) return;
    try {
      window.localStorage.setItem(LS_TAB, tab);
    } catch {
      /* quota / private mode — drop silently */
    }
  }, [tab, hydrated]);

  // Called by the Quick Start tab when the operator clicks "Open in
  // Playground". The Quick Start has already mutated `policy` via the
  // setter on every answer change, so we just flip the tab and arm
  // the handoff banner.
  function handleOpenInPlayground() {
    setArrivedFromQuickStart(true);
    setTab('playground');
    // Scroll to top so the section list starts at Basics.
    if (typeof window !== 'undefined') {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }

  // Called when an operator clicks "Restart Quick Start" from the
  // Playground. This IS destructive — it resets answers to defaults
  // and overwrites the current Policy from a clean preset — so we
  // confirm before nuking state.
  function handleRestartQuickStart() {
    if (!confirmRestart(answers)) return;
    setAnswers(defaultAnswers());
    setArrivedFromQuickStart(false);
    setTab('quick-start');
    if (typeof window !== 'undefined') {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }

  return (
    <div className="my-6 rounded-2xl border border-fd-border bg-fd-card/30 p-3">
      <Tabs active={tab} onSwitch={setTab} />
      <div className="mt-3">
        {tab === 'quick-start' ? (
          <QuickStart
            policy={policy}
            onPolicyChange={setPolicy}
            answers={answers}
            onAnswersChange={setAnswers}
            onOpenInPlayground={handleOpenInPlayground}
          />
        ) : (
          <Playground
            policy={policy}
            onPolicyChange={(next) => {
              setPolicy(next);
              // Any direct edit in the Playground breaks the "arrived
              // from Quick Start" contract — the banner can disappear.
              setArrivedFromQuickStart(false);
            }}
            banner={
              arrivedFromQuickStart ? (
                <HandoffBanner onRestart={handleRestartQuickStart} />
              ) : null
            }
          />
        )}
      </div>
    </div>
  );
}

function Tabs({
  active,
  onSwitch,
}: {
  active: TabId;
  onSwitch: (next: TabId) => void;
}) {
  const tabs: Array<{ id: TabId; label: string; hint: string }> = [
    {
      id: 'quick-start',
      label: 'Quick start',
      hint: 'Step through 6 questions, get a complete policy',
    },
    {
      id: 'playground',
      label: 'Playground',
      hint: 'Every knob, section by section',
    },
  ];
  return (
    <div
      role="tablist"
      aria-label="Policy creator mode"
      className="flex flex-wrap items-stretch gap-2 rounded-xl border border-fd-border bg-fd-background p-1"
    >
      {tabs.map((t) => {
        const selected = active === t.id;
        return (
          <button
            key={t.id}
            role="tab"
            aria-selected={selected}
            type="button"
            onClick={() => onSwitch(t.id)}
            className={[
              'flex-1 rounded-lg px-3 py-2 text-left transition',
              selected
                ? 'bg-fd-card text-fd-foreground shadow-sm ring-1 ring-[var(--brand-cisco)]/40'
                : 'text-fd-muted-foreground hover:bg-fd-card/60 hover:text-fd-foreground',
            ].join(' ')}
          >
            <div className="text-sm font-semibold">{t.label}</div>
            <div className="text-[11px] opacity-80">{t.hint}</div>
          </button>
        );
      })}
    </div>
  );
}

function HandoffBanner({ onRestart }: { onRestart: () => void }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-fd-border bg-[var(--brand-cisco)]/5 px-4 py-2 text-[11px] text-fd-foreground">
      <span>
        <strong>Loaded from Quick Start.</strong> Every section below is pre-filled with
        the choices you just made. Tweak anything you like — your edits stick.
      </span>
      <button
        type="button"
        onClick={onRestart}
        className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] hover:border-[var(--brand-cisco)]"
      >
        Restart Quick Start
      </button>
    </div>
  );
}

// Restart-the-interview confirmation. Skips the prompt when the user
// hasn't actually answered anything (so a freshly-loaded page never
// blocks on a needless confirm).
function confirmRestart(answers: Answers): boolean {
  if (typeof window === 'undefined') return true;
  const hasAnswers =
    answers.block.size > 0 ||
    answers.allow.size > 0 ||
    answers.firstPartyExtra.length > 0 ||
    answers.domainsExtra.length > 0 ||
    Object.values(answers.sinks).some((s) => s.enabled && s.url) ||
    answers.posture !== 'default' ||
    answers.response !== 'alert';
  if (!hasAnswers) return true;
  return window.confirm(
    'Restart the Quick Start interview? This clears every answer you picked. The policy currently loaded in the Playground will be replaced with the result of the empty interview.',
  );
}
