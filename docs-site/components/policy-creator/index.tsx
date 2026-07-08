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
import {
  clearHashPayload,
  decodePolicyFromHash,
  looksLikePolicy,
  normalizeImportedPolicy,
  readHashPayload,
  type DecodeFailure,
} from './lib/share';
import { diffAgainstBase } from './lib/diff';
import { summarize, validatePolicy } from './lib/validators';

type ShareErrorReason = DecodeFailure;

type TabId = 'quick-start' | 'playground';

const LS_TAB = 'dc-policy-creator-tab';
const LS_POLICY = 'dc-policy-creator-policy';
const LS_ANSWERS = 'dc-policy-creator-answers';

// Schema version of the wrapped localStorage payload. Bump when a
// Policy/Answer shape change is large enough that older drafts must
// be evicted rather than normalized. Smaller schema additions stay on
// the current version and rely on normalizeImportedPolicy /
// deserializeAnswers to backfill missing fields.
//
// History:
//   1 — first envelope. Bare-Policy payloads from older builds are
//       still recognized via the !.schema heuristic in the hydrator.
const LS_SCHEMA_VERSION = 1;

// Maximum schema version this build knows how to read. A future build
// will set this to LS_SCHEMA_VERSION + N once it can migrate older
// envelopes; older builds reading a newer envelope will fall through
// to the default-preset placeholder rather than risk corrupt state.
const LS_MAX_KNOWN_SCHEMA = 1;

interface LSEnvelope<T> {
  schema: number;
  // Optional savedAt epoch for the (future) debug overlay; not used
  // for migration decisions today, but cheap to write and useful
  // when an operator reports "my draft disappeared at <time>".
  savedAt?: number;
  payload: T;
}

function wrapEnvelope<T>(payload: T): LSEnvelope<T> {
  return { schema: LS_SCHEMA_VERSION, savedAt: Date.now(), payload };
}

// Try to interpret a localStorage value as either a versioned
// envelope OR a legacy bare payload (older builds that wrote raw
// Policy/Answers JSON). Returns the inner payload, or null if we
// recognize the envelope as too new to read.
//
// `legacyShapeCheck` validates the bare-payload fallback path so we
// don't silently restore garbage from a wholly different key that
// somehow collided in localStorage.
function unwrapMaybeEnvelope<T>(raw: unknown, legacyShapeCheck: (x: unknown) => boolean): T | null {
  if (raw && typeof raw === 'object' && 'schema' in raw && typeof (raw as { schema: unknown }).schema === 'number') {
    const env = raw as LSEnvelope<T>;
    if (env.schema > LS_MAX_KNOWN_SCHEMA) {
      // Newer build wrote this; we don't know its shape. Better to
      // drop it than risk crashing the page or corrupting their work.
      return null;
    }
    return env.payload;
  }
  return legacyShapeCheck(raw) ? (raw as T) : null;
}

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
  // Surfaced when a share link decoded into something we couldn't trust.
  // Cleared by the user dismissing the banner.
  const [shareError, setShareError] = useState<ShareErrorReason | null>(null);
  // Surfaced when an imported policy carries top-level keys this build
  // doesn't model. Non-blocking — the policy is still installable, but
  // the listed keys will be dropped on the next emit.
  const [unknownImportedKeys, setUnknownImportedKeys] = useState<string[]>([]);

  // Hydrate persisted state on mount. We delay setting `hydrated` until
  // after the first paint so SSR and CSR trees agree.
  useEffect(() => {
    let restoredFromLs = false;
    try {
      const rawTab = window.localStorage.getItem(LS_TAB);
      if (rawTab === 'playground' || rawTab === 'quick-start') setTab(rawTab);
      const rawPolicy = window.localStorage.getItem(LS_POLICY);
      if (rawPolicy) {
        // Drafts persisted by older builds (pre-correlator, pre-Cisco
        // AI Defense) are missing fields that every downstream consumer
        // (emit, validators, sections, data-projection) reads
        // unconditionally. Run the same normalize pass we use for
        // share-link imports so a stale draft doesn't crash the tab.
        // Shape-check first; on failure we fall back to the default
        // preset rather than smuggling garbage into setPolicy().
        const parsed: unknown = JSON.parse(rawPolicy);
        const inner = unwrapMaybeEnvelope<unknown>(parsed, looksLikePolicy);
        if (inner !== null && looksLikePolicy(inner)) {
          setPolicy(normalizeImportedPolicy(inner));
          restoredFromLs = true;
        }
      }
      const rawAnswers = window.localStorage.getItem(LS_ANSWERS);
      if (rawAnswers) {
        const parsedAnswers: unknown = JSON.parse(rawAnswers);
        const innerAnswers = unwrapMaybeEnvelope<unknown>(
          parsedAnswers,
          // Bare-Answers payload from older builds is any record; we
          // don't have a stricter shape check, so accept any object.
          (x) => typeof x === 'object' && x !== null,
        );
        if (innerAnswers !== null) setAnswers(deserializeAnswers(innerAnswers));
      }
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
        const result = await decodePolicyFromHash(payload);
        if (!result.ok) {
          // Bad payload — surface an actionable error and strip the
          // hash so the URL bar isn't lying about having a draft.
          // Distinguishing the failure mode helps the operator decide
          // whether to ask the sender for a fresh link vs report a bug.
          setShareError(result.reason);
          clearHashPayload();
          return;
        }
        const proceed =
          !restoredFromLs ||
          window.confirm(
            'Load policy from share link? Your in-progress draft in this browser will be replaced.',
          );
        if (proceed) {
          setPolicy(result.policy);
          // Reset answers — share link only carries the Policy, not
          // the Quick Start answer state. Operator can re-derive by
          // walking through the wizard if they want to.
          setAnswers(defaultAnswers());
          // Switch to Playground; share links almost always intend
          // "review the policy I just sent you" rather than "redo
          // the interview".
          setTab('playground');
          // If the imported policy carries fields this build doesn't
          // model, surface a non-blocking warning so the operator
          // knows what won't survive the next emit/install cycle.
          if (result.unknownKeys.length > 0) {
            setUnknownImportedKeys(result.unknownKeys);
          }
        }
        clearHashPayload();
      })();
    }

    setHydrated(true);
  }, []);

  // Persist on every change. Skipping the first paint avoids overwriting
  // a saved state with the default-preset placeholder. Both payloads
  // are wrapped in a versioned envelope so a future build can detect
  // and migrate (or evict) older drafts deterministically.
  useEffect(() => {
    if (!hydrated) return;
    try {
      window.localStorage.setItem(LS_POLICY, JSON.stringify(wrapEnvelope(policy)));
    } catch {
      /* quota / private mode — drop silently */
    }
  }, [policy, hydrated]);
  useEffect(() => {
    if (!hydrated) return;
    try {
      window.localStorage.setItem(
        LS_ANSWERS,
        JSON.stringify(wrapEnvelope(serializeAnswers(answers))),
      );
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
    <div className="policy-creator my-6 border border-fd-border bg-fd-card/30 p-3">
      <Tabs active={tab} onSwitch={setTab} />
      {shareError && (
        <ShareErrorBanner reason={shareError} onDismiss={() => setShareError(null)} />
      )}
      {unknownImportedKeys.length > 0 && (
        <UnknownImportedKeysBanner
          keys={unknownImportedKeys}
          onDismiss={() => setUnknownImportedKeys([])}
        />
      )}
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
      <DebugOverlay policy={policy} schemaVersion={LS_SCHEMA_VERSION} tab={tab} />
    </div>
  );
}

/**
 * G2 — Session debug overlay. Renders a small button in the
 * bottom-right of the wizard that opens a panel summarizing the
 * current session: schema version, finding counts, diff size,
 * preset, localStorage footprint, and a "Copy diagnostics" button
 * that puts a JSON blob on the clipboard.
 *
 * The blob is structural metadata ONLY — no policy contents, no
 * scenario JSON, no operator-typed strings. Useful for bug reports
 * the operator opens against the docs site without leaking their
 * draft policy.
 */
function DebugOverlay({
  policy,
  schemaVersion,
  tab,
}: {
  policy: Policy;
  schemaVersion: number;
  tab: TabId;
}) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const findings = useMemo(() => validatePolicy(policy), [policy]);
  const counts = useMemo(() => summarize(findings), [findings]);
  const diff = useMemo(() => diffAgainstBase(policy), [policy]);

  // localStorage footprint — total bytes the wizard owns. Cheap
  // signal for "I cleared cache and the wizard now loads fast" vs
  // "I have a stale 200KB draft from six builds ago".
  const lsBytes = useMemo(() => {
    if (typeof window === 'undefined') return 0;
    let total = 0;
    for (const key of [LS_TAB, LS_POLICY, LS_ANSWERS]) {
      try {
        const v = window.localStorage.getItem(key);
        if (v) total += v.length;
      } catch {
        /* ignore */
      }
    }
    return total;
  }, [open]); // recompute only when the overlay opens

  function snapshot() {
    return {
      schema_version: schemaVersion,
      tab,
      preset: policy.basedOn,
      // Structural metrics — never the actual values.
      counts: {
        validation_errors: counts.errors,
        validation_warnings: counts.warnings,
        validation_info: counts.info,
        diff_vs_preset: diff.length,
        custom_rego_snippets: policy.custom_rego.length,
        correlator_patterns: policy.correlator.length,
        webhooks: policy.webhooks.length,
        suppressions:
          policy.suppressions.pre_judge_strips.length +
          policy.suppressions.finding_suppressions.length +
          policy.suppressions.tool_suppressions.length,
      },
      flags: {
        cisco_ai_defense_enabled: !!policy.cisco_ai_defense?.enabled,
        guardrail_hilt_enabled: !!policy.guardrail.hilt.enabled,
      },
      localStorage_bytes: lsBytes,
      user_agent: typeof navigator !== 'undefined' ? navigator.userAgent : '',
      page_url: typeof window !== 'undefined' ? window.location.href : '',
    };
  }

  async function copyDiagnostics() {
    const blob = JSON.stringify(snapshot(), null, 2);
    try {
      await navigator.clipboard.writeText(blob);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard API may be unavailable (insecure context, focus
      // rules) — fall back to a textarea selection so the operator
      // can manually copy.
      const ta = document.createElement('textarea');
      ta.value = blob;
      ta.setAttribute('readonly', 'true');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      } catch {
        /* give up — operator can still see the JSON in the panel */
      }
      document.body.removeChild(ta);
    }
  }

  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col items-end gap-2">
      {open && (
        <div className="pointer-events-auto w-80 max-w-[90vw] rounded-lg border border-fd-border bg-fd-background p-3 shadow-lg">
          <div className="mb-2 flex items-baseline justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wide text-fd-muted-foreground">
              Session debug
            </span>
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="text-[10px] text-fd-muted-foreground hover:text-fd-foreground"
              aria-label="Close debug panel"
            >
              ✕
            </button>
          </div>
          <dl className="grid grid-cols-2 gap-x-2 gap-y-1 text-[11px]">
            <dt className="text-fd-muted-foreground">Schema</dt>
            <dd className="font-mono text-fd-foreground">v{schemaVersion}</dd>
            <dt className="text-fd-muted-foreground">Tab</dt>
            <dd className="font-mono text-fd-foreground">{tab}</dd>
            <dt className="text-fd-muted-foreground">Preset</dt>
            <dd className="font-mono text-fd-foreground">{policy.basedOn}</dd>
            <dt className="text-fd-muted-foreground">Findings</dt>
            <dd className="font-mono text-fd-foreground">
              {counts.errors}E · {counts.warnings}W · {counts.info}I
            </dd>
            <dt className="text-fd-muted-foreground">Diff</dt>
            <dd className="font-mono text-fd-foreground">{diff.length}</dd>
            <dt className="text-fd-muted-foreground">Custom Rego</dt>
            <dd className="font-mono text-fd-foreground">{policy.custom_rego.length}</dd>
            <dt className="text-fd-muted-foreground">Correlator</dt>
            <dd className="font-mono text-fd-foreground">{policy.correlator.length}</dd>
            <dt className="text-fd-muted-foreground">Webhooks</dt>
            <dd className="font-mono text-fd-foreground">{policy.webhooks.length}</dd>
            <dt className="text-fd-muted-foreground">AID lane</dt>
            <dd className="font-mono text-fd-foreground">
              {policy.cisco_ai_defense?.enabled ? 'on' : 'off'}
            </dd>
            <dt className="text-fd-muted-foreground">localStorage</dt>
            <dd className="font-mono text-fd-foreground">{(lsBytes / 1024).toFixed(1)} KB</dd>
          </dl>
          <p className="mt-2 text-[10px] text-fd-muted-foreground">
            Counters only — no policy contents are read or copied.
          </p>
          <button
            type="button"
            onClick={copyDiagnostics}
            className="mt-2 inline-flex w-full items-center justify-center rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] font-medium hover:border-[var(--brand-cisco)] hover:bg-[var(--brand-cisco)]/10"
          >
            {copied ? 'Copied!' : 'Copy diagnostics JSON'}
          </button>
        </div>
      )}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-label="Open session debug panel"
        aria-expanded={open}
        className="pointer-events-auto inline-flex h-8 w-8 items-center justify-center rounded-full border border-fd-border bg-fd-background text-fd-muted-foreground shadow-md hover:border-[var(--brand-cisco)] hover:text-[var(--brand-cisco)]"
        title="Show session debug overlay"
      >
        <span aria-hidden="true">ⓘ</span>
      </button>
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
            <div className="text-[11px] text-fd-muted-foreground">{t.hint}</div>
          </button>
        );
      })}
    </div>
  );
}

const SHARE_ERROR_COPY: Record<ShareErrorReason, { title: string; detail: string }> = {
  version: {
    title: 'Share link uses an unsupported format version.',
    detail:
      'The link was produced by a newer (or much older) version of this page. Ask the sender to re-share from a current build.',
  },
  'too-large': {
    title: 'Share link payload is suspiciously large.',
    detail:
      'We refused to decode it as a guard against gzip bombs. If this was a legitimate policy, the sender can re-export it as a YAML bundle instead.',
  },
  malformed: {
    title: "Share link is malformed and couldn't be decoded.",
    detail:
      'The base64 / gzip / JSON layers all failed. The link is likely truncated or corrupted in transit — ask the sender to copy it again.',
  },
  'invalid-shape': {
    title: 'Share link decoded, but the contents are not a DefenseClaw policy.',
    detail:
      'We dropped it instead of overwriting your draft. If you trust the sender, they can paste their YAML directly into the Playground.',
  },
};

function ShareErrorBanner({
  reason,
  onDismiss,
}: {
  reason: ShareErrorReason;
  onDismiss: () => void;
}) {
  const { title, detail } = SHARE_ERROR_COPY[reason];
  return (
    <div
      role="alert"
      className="mt-3 flex flex-wrap items-start justify-between gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-[12px] text-amber-700 dark:text-amber-300"
    >
      <div className="min-w-0 flex-1">
        <strong className="block">{title}</strong>
        <span className="opacity-90">{detail}</span>
      </div>
      <button
        type="button"
        onClick={onDismiss}
        className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-[11px] hover:bg-amber-500/20"
        aria-label="Dismiss share-link error"
      >
        Dismiss
      </button>
    </div>
  );
}

function UnknownImportedKeysBanner({
  keys,
  onDismiss,
}: {
  keys: string[];
  onDismiss: () => void;
}) {
  // We don't render the full list inline when it's long — instead show
  // the first three and a "+N more" suffix. The keys are bounded by the
  // size of the foreign Policy object, but defensive truncation keeps
  // the banner readable even if someone pastes a wildly forked draft.
  const head = keys.slice(0, 3).map((k) => `\`${k}\``);
  const more = keys.length - head.length;
  return (
    <div
      role="status"
      className="mt-3 flex flex-wrap items-start justify-between gap-3 rounded-lg border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-[12px] text-sky-700 dark:text-sky-300"
    >
      <div className="min-w-0 flex-1">
        <strong className="block">
          Imported policy contains {keys.length} field
          {keys.length === 1 ? '' : 's'} this build doesn&rsquo;t model.
        </strong>
        <span className="opacity-90">
          The listed fields ({head.join(', ')}
          {more > 0 ? `, +${more} more` : ''}) survive in your browser but will be
          dropped when you download the install script. Update DefenseClaw if you
          want them preserved, or ignore this if the fields are stale.
        </span>
      </div>
      <button
        type="button"
        onClick={onDismiss}
        className="rounded-md border border-sky-500/40 bg-sky-500/10 px-2 py-1 text-[11px] hover:bg-sky-500/20"
        aria-label="Dismiss unknown-fields warning"
      >
        Dismiss
      </button>
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
