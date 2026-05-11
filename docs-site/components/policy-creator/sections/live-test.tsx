// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Right-rail Live Test pane. Picks a domain, picks an input source
// (canned scenario or BYO custom JSON), pipes the wizard's current
// Policy through projectPolicyToData() and the WASM evaluator, and
// renders the verdict.
//
// Re-runs whenever (a) the policy mutates, (b) the operator picks a
// different scenario, or (c) the operator edits the custom JSON. WASM
// loading is debounced and cached inside opa-eval.ts so this component
// can stay dumb.
//
// Custom input source:
//   - Per-domain draft persisted to localStorage so "what if a CRITICAL
//     scan came in with my own metadata" experiments survive a refresh.
//   - JSON.parse runs on every change; invalid JSON shows an inline
//     error and we *don't* re-evaluate (keeping the last good verdict).
//   - "Reset to selected scenario" seeds the editor from the canned
//     scenario the operator most recently picked.
//   - Eval is debounced 250ms so fast typing doesn't thrash WASM.

'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import type { Policy, Scenario } from '../types';
import { projectPolicyToData } from '../lib/data-projection';
import { evalDomain, isOpaAvailable, OpaUnavailableError } from '../lib/opa-eval';
import { highlightJsonToHtml } from '../lib/json-highlight';
import { listScenariosForDomain, ScenarioJsonPreview, ScenarioPicker } from '../ui/scenario-picker';
import { SegmentedControl } from '../ui/segmented-control';
import { VerdictBadge } from '../ui/verdict-badge';
import { CodeEditor } from '../ui/rego-editor';

type Domain = Scenario['domain'];
type Source = 'scenario' | 'custom';

const DOMAIN_OPTIONS: Array<{ value: Domain; label: string; hint?: string }> = [
  { value: 'admission', label: 'admission' },
  { value: 'guardrail', label: 'guardrail' },
  { value: 'firewall', label: 'firewall' },
  { value: 'audit', label: 'audit' },
  { value: 'skill_actions', label: 'skill_actions' },
];

const SOURCE_OPTIONS: Array<{ value: Source; label: string }> = [
  { value: 'scenario', label: 'Canned scenario' },
  { value: 'custom', label: 'Custom input' },
];

const LS_CUSTOM_PREFIX = 'dc-policy-creator/live-test/custom/v1/';

export function LiveTestPane({ policy }: { policy: Policy }) {
  const [domain, setDomain] = useState<Domain>('admission');
  const [source, setSource] = useState<Source>('scenario');
  const [scenario, setScenario] = useState<Scenario | null>(null);
  // Per-domain custom JSON drafts. Hydrated from localStorage on
  // mount; falls back to the first canned scenario's input as a
  // useful starting point.
  const [customByDomain, setCustomByDomain] = useState<Record<Domain, string>>({} as Record<Domain, string>);
  const [hydrated, setHydrated] = useState(false);

  const [verdict, setVerdict] = useState<string>('…');
  const [reason, setReason] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [evaluating, setEvaluating] = useState(false);
  const [available, setAvailable] = useState<boolean | null>(null);

  // Initial scenario per domain.
  useEffect(() => {
    const list = listScenariosForDomain(domain);
    setScenario(list[0] ?? null);
  }, [domain]);

  // Hydrate persisted custom drafts. Keep SSR/CSR consistent by
  // deferring localStorage reads to after first paint.
  useEffect(() => {
    const next: Record<string, string> = {};
    for (const opt of DOMAIN_OPTIONS) {
      try {
        const raw = window.localStorage.getItem(`${LS_CUSTOM_PREFIX}${opt.value}`);
        if (raw != null) next[opt.value] = raw;
      } catch {
        /* private mode / quota — fall through */
      }
    }
    setCustomByDomain((prev) => ({ ...prev, ...next }));
    setHydrated(true);
  }, []);

  // Persist drafts. Skipping the first paint avoids overwriting LS
  // with empty defaults during hydration.
  useEffect(() => {
    if (!hydrated) return;
    for (const [d, json] of Object.entries(customByDomain)) {
      try {
        window.localStorage.setItem(`${LS_CUSTOM_PREFIX}${d}`, json);
      } catch {
        /* drop silently */
      }
    }
  }, [customByDomain, hydrated]);

  useEffect(() => {
    let cancelled = false;
    isOpaAvailable().then((ok) => {
      if (!cancelled) setAvailable(ok);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const data = useMemo(() => projectPolicyToData(policy), [policy]);

  // The active input + JSON parse result for the custom path. We
  // always parse, even for the scenario path, so the same eval
  // pipeline downstream can be agnostic.
  const customRaw = customByDomain[domain] ?? '';
  const parsedCustom = useMemo<{ ok: true; value: unknown } | { ok: false; error: string }>(
    () => {
      const trimmed = customRaw.trim();
      if (!trimmed) return { ok: false, error: 'JSON is empty.' };
      try {
        return { ok: true, value: JSON.parse(customRaw) };
      } catch (e) {
        return { ok: false, error: e instanceof Error ? e.message : String(e) };
      }
    },
    [customRaw],
  );

  // Debounce custom-input evaluation so typing doesn't thrash WASM.
  // Scenario-source evaluation runs immediately because the input
  // shape only changes on click.
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (available === false) {
      setVerdict('—');
      setReason(null);
      return;
    }
    if (available === null) {
      setVerdict('loading WASM…');
      return;
    }

    let activeInput: unknown;
    if (source === 'scenario') {
      if (!scenario) {
        setVerdict('—');
        setReason(null);
        setError(null);
        return;
      }
      activeInput = scenario.input;
    } else {
      if (!parsedCustom.ok) {
        // No valid input to evaluate. Clear the verdict instead of
        // holding the previous (possibly different-domain) result —
        // the inline JSON-parse error tells the operator why.
        setVerdict('—');
        setReason(null);
        setError(null);
        setEvaluating(false);
        return;
      }
      activeInput = parsedCustom.value;
    }

    const runDelay = source === 'custom' ? 250 : 0;
    if (debounceRef.current) clearTimeout(debounceRef.current);
    let cancelled = false;
    debounceRef.current = setTimeout(() => {
      setEvaluating(true);
      setError(null);
      evalDomain(domain, activeInput, data)
        .then((res) => {
          if (cancelled) return;
          setVerdict(res.verdict);
          setReason(res.reason ?? null);
        })
        .catch((err: unknown) => {
          if (cancelled) return;
          const msg =
            err instanceof OpaUnavailableError
              ? err.message
              : err instanceof Error
                ? err.message
                : String(err);
          setError(msg);
          setVerdict('error');
        })
        .finally(() => {
          if (!cancelled) setEvaluating(false);
        });
    }, runDelay);
    return () => {
      cancelled = true;
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [source, scenario, customRaw, parsedCustom, data, available, domain]);

  function seedFromScenario() {
    if (!scenario) return;
    setCustomByDomain((prev) => ({
      ...prev,
      [domain]: JSON.stringify(scenario.input, null, 2),
    }));
  }

  function clearCustom() {
    setCustomByDomain((prev) => ({ ...prev, [domain]: '' }));
  }

  const expected = scenario?.expectedVerdict;
  const matchesExpected =
    source === 'scenario' && expected != null && verdict === expected;

  return (
    <div className="flex h-full flex-col gap-4 rounded-lg border border-fd-border bg-fd-card p-4">
      <header className="flex flex-col gap-1">
        <h3 className="text-sm font-semibold text-fd-foreground">Live Test</h3>
        <p className="text-[11px] text-fd-muted-foreground">
          Evaluates your policy in your browser via OPA-WASM. No data leaves the page —
          custom inputs stay in localStorage.
        </p>
      </header>

      {available === false && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-700 dark:text-amber-300">
          WASM modules aren&apos;t available. Run{' '}
          <code className="rounded bg-fd-muted px-1 py-0.5 font-mono text-[10px]">
            npm run build:policy-assets
          </code>{' '}
          and reload — the rest of the wizard works without it.
        </div>
      )}

      <div className="flex flex-col gap-2">
        <span className="text-[11px] font-medium uppercase tracking-wide text-fd-muted-foreground">
          Domain
        </span>
        <SegmentedControl
          name="Domain"
          options={DOMAIN_OPTIONS}
          value={domain}
          onChange={setDomain}
          size="sm"
        />
      </div>

      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-medium uppercase tracking-wide text-fd-muted-foreground">
            Input source
          </span>
          {source === 'custom' && (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={seedFromScenario}
                disabled={!scenario}
                className="text-[10px] text-fd-muted-foreground hover:text-[var(--brand-cisco)] disabled:opacity-40"
                title="Replace the editor contents with the JSON of the currently-selected canned scenario"
              >
                ↺ Reset to scenario
              </button>
              <button
                type="button"
                onClick={clearCustom}
                disabled={!customRaw}
                className="text-[10px] text-fd-muted-foreground hover:text-red-500 disabled:opacity-40"
              >
                Clear
              </button>
            </div>
          )}
        </div>
        <SegmentedControl
          name="InputSource"
          options={SOURCE_OPTIONS}
          value={source}
          onChange={setSource}
          size="sm"
        />
      </div>

      {source === 'scenario' ? (
        <div className="flex flex-col gap-2">
          <span className="text-[11px] font-medium uppercase tracking-wide text-fd-muted-foreground">
            Scenario
          </span>
          <ScenarioPicker
            domain={domain}
            selectedId={scenario?.id ?? ''}
            onSelect={setScenario}
          />
          <ScenarioJsonPreview scenario={scenario} />
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          <CodeEditor
            label="Input JSON"
            language="json"
            highlight={highlightJsonToHtml}
            value={customRaw}
            onChange={(v) =>
              setCustomByDomain((prev) => ({ ...prev, [domain]: v }))
            }
            minRows={10}
            placeholder={'Paste or type JSON, e.g.\n{\n  "scan_result": {\n    "max_severity": "CRITICAL"\n  }\n}'}
            hint={
              parsedCustom.ok ? (
                <span className="text-emerald-600 dark:text-emerald-400">
                  Valid JSON · re-evaluates 250 ms after you stop typing.
                </span>
              ) : (
                <span className="text-red-500">JSON parse error: {parsedCustom.error}</span>
              )
            }
          />
        </div>
      )}

      <div className="rounded-md border border-fd-border bg-fd-background p-3">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] font-medium uppercase tracking-wide text-fd-muted-foreground">
            Verdict {evaluating && <span className="ml-1 animate-pulse">·</span>}
          </span>
          <VerdictBadge verdict={verdict} emphasized />
        </div>
        {reason && (
          <p className="mt-2 text-[11px] leading-snug text-fd-muted-foreground">
            <span className="font-medium text-fd-foreground">Reason:</span> {reason}
          </p>
        )}
        {expected != null && available && !error && source === 'scenario' && (
          <p
            className={`mt-2 text-[11px] ${
              matchesExpected
                ? 'text-emerald-600 dark:text-emerald-400'
                : 'text-amber-600 dark:text-amber-400'
            }`}
          >
            {matchesExpected
              ? `Matches expected verdict (${expected}).`
              : `Differs from expected verdict (${expected}). Tweak the relevant section to align.`}
          </p>
        )}
        {source === 'custom' && available && !error && (
          <p className="mt-2 text-[11px] text-fd-muted-foreground">
            Hand-authored input — no expected verdict to compare against.
          </p>
        )}
        {error && (
          <p className="mt-2 break-words text-[11px] text-red-500">{error}</p>
        )}
      </div>
    </div>
  );
}
