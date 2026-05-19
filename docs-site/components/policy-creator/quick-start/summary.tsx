// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Compact "what your policy looks like" card rendered in the Quick
// Start right rail. Updates on every answer change so operators can
// see the rule pack growing as they tick boxes.

'use client';

import { useMemo } from 'react';
import type { Policy } from '../types';
import type { Answers } from './questions';
import { POSTURES } from './questions';
import { diffAgainstBase } from '../lib/diff';
import { policyFromPreset } from '../lib/presets';

export function PolicySummaryCard({
  policy,
  answers,
}: {
  policy: Policy;
  answers: Answers;
}) {
  const postureLabel = POSTURES.find((p) => p.id === answers.posture)?.title ?? answers.posture;

  // Active rule count + how it compares to the preset baseline.
  // The previous implementation compared against "preset full pack",
  // but every shipped preset disables some rules out of the box —
  // the bundled `default` preset, for example, ships with 122 of 128
  // rules active. That caused the summary to display
  //   "6 rules disabled vs. preset full pack"
  // even when the operator hadn't touched anything, which read as
  // "I disabled those" rather than "the preset shipped that way."
  // The correct comparison is against the preset's own baseline.
  const totalRules = policy.rule_pack.files.reduce((acc, f) => acc + f.rules.length, 0);
  const enabledRules = policy.rule_pack.files.reduce(
    (acc, f) => acc + f.rules.filter((r) => r.enabled !== false).length,
    0,
  );
  const baselineEnabled = useMemo(() => {
    const base = policyFromPreset(policy.basedOn);
    return base.rule_pack.files.reduce(
      (acc, f) => acc + f.rules.filter((r) => r.enabled !== false).length,
      0,
    );
  }, [policy.basedOn]);
  const rulesDelta = enabledRules - baselineEnabled;

  // Whole-policy diff vs. the preset baseline. This is the same
  // signal the playground "X changes from <preset>" banner shows,
  // surfaced here so the Quick Start Review tab makes it obvious
  // when the operator HAS in fact modified things from the preset.
  const diff = useMemo(() => diffAgainstBase(policy), [policy]);
  const changeCount = diff.length;

  const suppressionTotal =
    policy.suppressions.tool_suppressions.length +
    policy.suppressions.finding_suppressions.length +
    policy.suppressions.pre_judge_strips.length;
  const sinkCount = policy.webhooks.filter((w) => w.enabled).length;
  const allowedDomains = policy.firewall.allowed_domains.length;
  const blockedDestinations = policy.firewall.blocked_destinations.length;
  const firstParty = policy.first_party_allow_list.length;

  return (
    <div className="space-y-3 rounded-xl border border-fd-border bg-fd-card p-3">
      <div className="flex items-baseline justify-between gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-fd-muted-foreground">
          Policy summary
        </h3>
        {/*
          Pill that summarizes "have I changed anything from the preset?".
          Zero changes → muted "unchanged" pill so the operator can tell
          their Quick Start clicks have actually mutated the policy.
        */}
        <span
          className={[
            'shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide',
            changeCount === 0
              ? 'bg-fd-muted/40 text-fd-muted-foreground'
              : 'bg-[var(--brand-cisco)]/15 text-[var(--brand-cisco-strong)]',
          ].join(' ')}
          title={
            changeCount === 0
              ? `No changes from the ${policy.basedOn} preset yet`
              : `${changeCount} change${changeCount === 1 ? '' : 's'} vs. the ${policy.basedOn} preset`
          }
        >
          {changeCount === 0
            ? `${policy.basedOn} preset`
            : `${changeCount} change${changeCount === 1 ? '' : 's'} vs. ${policy.basedOn}`}
        </span>
      </div>
      <ul className="space-y-1.5 text-[12px] text-fd-foreground">
        <Row label="Posture" value={postureLabel} />
        <Row
          label="Rules active"
          value={`${enabledRules} of ${totalRules}`}
          // Three-state hint: identical-to-baseline, you-enabled-more,
          // you-disabled-some. Phrased so it's never ambiguous about
          // who did what.
          hint={
            rulesDelta === 0
              ? `Baseline for the ${policy.basedOn} preset — change individual rules in the Playground → Rule Pack section.`
              : rulesDelta > 0
                ? `You enabled ${rulesDelta} more rule${rulesDelta === 1 ? '' : 's'} than the ${policy.basedOn} preset ships with.`
                : `You disabled ${Math.abs(rulesDelta)} rule${rulesDelta === -1 ? '' : 's'} from the ${policy.basedOn} preset baseline.`
          }
        />
        <Row label="Suppressions" value={String(suppressionTotal)} />
        <Row
          label="Firewall"
          value={`${policy.firewall.default_action} default · ${blockedDestinations} blocked · ${allowedDomains} allowed`}
        />
        <Row label="First-party allow-list" value={String(firstParty)} />
        <Row label="Webhook sinks" value={String(sinkCount)} />
        <Row
          label="Block at"
          value={`severity ${policy.guardrail.block_threshold} (${rankLabel(policy.guardrail.block_threshold)})`}
        />
        <Row label="HILT" value={policy.guardrail.hilt.enabled ? `on @ ${policy.guardrail.hilt.min_severity}` : 'off'} />
      </ul>
    </div>
  );
}

function Row({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <li className="flex flex-col gap-0.5">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-fd-muted-foreground">{label}</span>
        <span className="text-right font-medium tabular-nums">{value}</span>
      </div>
      {hint && (
        <span className="text-[10px] leading-tight text-fd-muted-foreground/80">{hint}</span>
      )}
    </li>
  );
}

function rankLabel(n: number): string {
  return ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][n] ?? 'CRITICAL';
}
