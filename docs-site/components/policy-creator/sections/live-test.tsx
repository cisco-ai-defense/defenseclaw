// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Right-rail Live Test pane. Picks a domain, picks a canned scenario,
// pipes the wizard's current Policy through projectPolicyToData() and
// the WASM evaluator, and renders the verdict.
//
// Re-runs whenever (a) the policy mutates or (b) the operator picks
// a different scenario. WASM loading is debounced and cached inside
// opa-eval.ts so this component can stay dumb.

'use client';

import { useEffect, useMemo, useState } from 'react';
import type { Policy, Scenario } from '../types';
import { projectPolicyToData } from '../lib/data-projection';
import { evalDomain, isOpaAvailable, OpaUnavailableError } from '../lib/opa-eval';
import { listScenariosForDomain, ScenarioJsonPreview, ScenarioPicker } from '../ui/scenario-picker';
import { SegmentedControl } from '../ui/segmented-control';
import { VerdictBadge } from '../ui/verdict-badge';

type Domain = Scenario['domain'];

const DOMAIN_OPTIONS: Array<{ value: Domain; label: string; hint?: string }> = [
  { value: 'admission', label: 'admission' },
  { value: 'guardrail', label: 'guardrail' },
  { value: 'firewall', label: 'firewall' },
  { value: 'audit', label: 'audit' },
  { value: 'skill_actions', label: 'skill_actions' },
];

export function LiveTestPane({ policy }: { policy: Policy }) {
  const [domain, setDomain] = useState<Domain>('admission');
  const [scenario, setScenario] = useState<Scenario | null>(null);
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

  useEffect(() => {
    if (!scenario || available === false) {
      setVerdict('—');
      setReason(null);
      return;
    }
    if (available === null) {
      setVerdict('loading WASM…');
      return;
    }
    let cancelled = false;
    setEvaluating(true);
    setError(null);
    evalDomain(scenario.domain, scenario.input, data)
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
    return () => {
      cancelled = true;
    };
  }, [scenario, data, available]);

  const expected = scenario?.expectedVerdict;
  const matchesExpected = expected != null && verdict === expected;

  return (
    <div className="flex h-full flex-col gap-4 rounded-lg border border-fd-border bg-fd-card p-4">
      <header className="flex flex-col gap-1">
        <h3 className="text-sm font-semibold text-fd-foreground">Live Test</h3>
        <p className="text-[11px] text-fd-muted-foreground">
          Evaluates your policy against a canned input using OPA-WASM in your browser. No data
          leaves the page.
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
        {expected != null && available && !error && (
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
        {error && (
          <p className="mt-2 break-words text-[11px] text-red-500">{error}</p>
        )}
      </div>
    </div>
  );
}
