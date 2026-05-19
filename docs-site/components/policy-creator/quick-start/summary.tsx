// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Compact "what your policy looks like" card rendered in the Quick
// Start right rail. Updates on every answer change so operators can
// see the rule pack growing as they tick boxes.

'use client';

import type { Policy } from '../types';
import type { Answers } from './questions';
import { POSTURES } from './questions';

export function PolicySummaryCard({
  policy,
  answers,
}: {
  policy: Policy;
  answers: Answers;
}) {
  const postureLabel = POSTURES.find((p) => p.id === answers.posture)?.title ?? answers.posture;
  const totalRules = policy.rule_pack.files.reduce((acc, f) => acc + f.rules.length, 0);
  const enabledRules = policy.rule_pack.files.reduce(
    (acc, f) => acc + f.rules.filter((r) => r.enabled !== false).length,
    0,
  );
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
      <h3 className="text-xs font-semibold uppercase tracking-wide text-fd-muted-foreground">
        Policy summary
      </h3>
      <ul className="space-y-1.5 text-[12px] text-fd-foreground">
        <Row label="Posture" value={postureLabel} />
        <Row label="Rules enabled" value={`${enabledRules} of ${totalRules}`} />
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

function Row({ label, value }: { label: string; value: string }) {
  return (
    <li className="flex items-baseline justify-between gap-2">
      <span className="text-fd-muted-foreground">{label}</span>
      <span className="text-right font-medium tabular-nums">{value}</span>
    </li>
  );
}

function rankLabel(n: number): string {
  return ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][n] ?? 'CRITICAL';
}
