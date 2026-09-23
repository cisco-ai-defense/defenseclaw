// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

'use client';

import Link from 'next/link';
import useCasePacksData from '@/data/policy-use-case-packs.json';
import type { Policy, RuleDef, UseCasePack, UseCasePacksFile } from '../types';
import {
  ACTIONFACTS_CAPABILITIES,
  BOUNDED_CHAINS,
  DETERMINISTIC_COVERAGE_TOTALS,
  HIGH_ASSURANCE_PACKS,
  YARA_RULES,
} from '../deterministic-coverage-catalog';

const REFERENCE_HREF = '/docs/policies/deterministic-detection/';
const USE_CASE_PACKS = (useCasePacksData as unknown as UseCasePacksFile).packs;
const PACK_DETAILS = new Map<string, (typeof HIGH_ASSURANCE_PACKS)[number]>(
  HIGH_ASSURANCE_PACKS.map((pack) => [pack.id, pack]),
);

export function DeterministicCoverageSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  function packIsApplied(pack: UseCasePack): boolean {
    const existing = new Map(
      policy.rule_pack.files.flatMap((file) => file.rules.map((rule) => [rule.id, rule])),
    );
    return pack.files
      .flatMap((file) => file.rules)
      .every((rule) => equivalentRule(existing.get(rule.id), rule));
  }

  function applyPack(pack: UseCasePack) {
    const incomingIds = new Set(pack.files.flatMap((file) => file.rules.map((rule) => rule.id)));
    let files = policy.rule_pack.files.map((file) => ({
      ...file,
      rules: file.rules.filter((rule) => !incomingIds.has(rule.id)),
    }));
    for (const packFile of pack.files) {
      const nextRules = packFile.rules.map(cloneRule);
      const index = files.findIndex((file) => file.filename === packFile.filename);
      if (index >= 0) {
        files[index] = {
          ...files[index],
          category: packFile.category,
          rules: [...files[index].rules, ...nextRules],
        };
      } else {
        files = [...files, { ...packFile, rules: nextRules }];
      }
    }
    onPolicyChange({
      ...policy,
      rule_pack: { ...policy.rule_pack, files },
    });
  }

  return (
    <div className="space-y-5">
      <div
        role="note"
        aria-label="Deterministic runtime coverage and policy packs"
        className="rounded-lg border border-sky-400/40 bg-sky-50/70 p-3 text-[12px] leading-5 text-sky-950 dark:border-sky-500/30 dark:bg-sky-500/10 dark:text-sky-100"
      >
        <div className="flex gap-2">
          <span aria-hidden="true" className="font-semibold">
            ◈
          </span>
          <div>
            <p className="font-semibold">Runtime-owned proofs, policy-owned profiles</p>
            <p className="mt-0.5 text-sky-800 dark:text-sky-200">
              ActionFacts proofs, fixed chains, and YARA signatures are read-only because
              DefenseClaw owns their bounded runtime implementation. Selectable high-assurance
              packs copy their canonical rules into this custom policy; apply them only where
              the connector&apos;s trust boundary makes that protection appropriate.
            </p>
          </div>
        </div>
      </div>

      <dl className="grid grid-cols-2 gap-2" aria-label="Coverage totals">
        <Metric value="6" label="fact capability groups" />
        <Metric value={String(DETERMINISTIC_COVERAGE_TOTALS.chains)} label="bounded chains" />
        <Metric value={String(DETERMINISTIC_COVERAGE_TOTALS.yaraRules)} label="YARA rules" />
        <Metric
          value={`${DETERMINISTIC_COVERAGE_TOTALS.selectablePacks} + ${DETERMINISTIC_COVERAGE_TOTALS.stagedPacks}`}
          label="selectable + staged packs"
        />
      </dl>

      <InventoryGroup
        title="ActionFacts capabilities"
        description="A bounded, private semantic projection used by CEL and code-owned proof checks."
      >
        <ul className="m-0 grid list-none gap-2 p-0 sm:grid-cols-2">
          {ACTIONFACTS_CAPABILITIES.map((capability) => (
            <li key={capability.title} className="rounded-lg border border-fd-border bg-fd-background p-3">
              <h4 className="text-[12px] font-semibold text-fd-foreground">{capability.title}</h4>
              <p className="mt-1 text-[11px] leading-4 text-fd-muted-foreground">
                {capability.summary}
              </p>
              <ul className="m-0 mt-2 list-none space-y-1 p-0 text-[11px] leading-4 text-fd-muted-foreground">
                {capability.values.map((value) => (
                  <li key={value} className="flex gap-1.5">
                    <span aria-hidden="true" className="text-[var(--brand-cisco)]">
                      •
                    </span>
                    <span>{value}</span>
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      </InventoryGroup>

      <InventoryGroup
        title="Bounded tool-call chains"
        description={`All ${DETERMINISTIC_COVERAGE_TOTALS.chains} fixed same-session proofs. Each examines no more than the current event plus eight predecessors and no more than 30 minutes.`}
        aside={`${DETERMINISTIC_COVERAGE_TOTALS.enforcementCapableChains} enforcement-capable · ${DETERMINISTIC_COVERAGE_TOTALS.alertOnlyChains} alert-only`}
      >
        <ol className="m-0 list-none divide-y divide-fd-border overflow-hidden rounded-lg border border-fd-border bg-fd-background p-0">
          {BOUNDED_CHAINS.map((chain) => (
            <li key={chain.id} className="px-3 py-2.5">
              <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1">
                <div className="min-w-0 flex-1">
                  <p className="text-[12px] font-medium text-fd-foreground">{chain.title}</p>
                  <code className="block break-all text-[10px] text-fd-muted-foreground">
                    {chain.id}
                  </code>
                </div>
                <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                  <StatusBadge mode={chain.mode} />
                  <span className="rounded-full border border-fd-border px-2 py-0.5 text-[10px] text-fd-muted-foreground">
                    {chain.severity}
                  </span>
                  <span className="rounded-full border border-fd-border px-2 py-0.5 text-[10px] text-fd-muted-foreground">
                    {chain.eventWindow} events · {chain.timeWindowMinutes}m
                  </span>
                </div>
              </div>
            </li>
          ))}
        </ol>
      </InventoryGroup>

      <InventoryGroup
        title="MCP description YARA"
        description="Five high-precision static signatures. Findings remain alert-only because authorization and destination trust require runtime policy context."
      >
        <ul className="m-0 grid list-none gap-2 p-0 sm:grid-cols-2">
          {YARA_RULES.map((rule) => (
            <li key={rule.id} className="rounded-lg border border-fd-border bg-fd-background p-3">
              <div className="flex items-start justify-between gap-2">
                <code className="break-all text-[10px] font-semibold text-fd-foreground">{rule.id}</code>
                <span className="shrink-0 rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-300">
                  alert-only
                </span>
              </div>
              <p className="mt-1 text-[11px] leading-4 text-fd-muted-foreground">
                {rule.description}
              </p>
              <p className="mt-2 text-[10px] font-medium uppercase tracking-wide text-fd-muted-foreground">
                {rule.category}
              </p>
            </li>
          ))}
        </ul>
      </InventoryGroup>

      <InventoryGroup
        title="High-assurance policy packs"
        description="Opt-in packs make deployment context explicit. Resource names alone are never treated as proof that an environment is production."
      >
        <ul className="m-0 list-none space-y-2 p-0">
          {USE_CASE_PACKS.map((pack) => {
            const detail = PACK_DETAILS.get(pack.id);
            const ruleCount = pack.files.reduce((count, file) => count + file.rules.length, 0);
            const applied = pack.status === 'selectable' && packIsApplied(pack);
            return (
            <li
              key={pack.id}
              className="flex flex-col gap-2 rounded-lg border border-fd-border bg-fd-background p-3 sm:flex-row sm:items-start sm:justify-between"
            >
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h4 className="text-[12px] font-semibold text-fd-foreground">{pack.title}</h4>
                  <PackBadge status={pack.status} />
                </div>
                <code className="mt-0.5 block break-all text-[10px] text-fd-muted-foreground">
                  {pack.id}
                </code>
                <p className="mt-1 text-[11px] leading-4 text-fd-muted-foreground">
                  {detail?.coverage ?? pack.summary}
                </p>
              </div>
              <div className="flex shrink-0 flex-col items-start gap-1.5 sm:items-end">
                <span className="text-[10px] font-medium text-fd-muted-foreground">
                  {pack.status === 'selectable'
                    ? `${ruleCount} ${ruleCount === 1 ? 'rule' : 'rules'}`
                    : 'contract only'}
                </span>
                {pack.status === 'selectable' && (
                  <button
                    type="button"
                    disabled={applied}
                    onClick={() => applyPack(pack)}
                    className="rounded-md border border-[var(--brand-cisco)] px-2.5 py-1 text-[10px] font-semibold text-[var(--brand-cisco)] transition-colors hover:bg-[var(--brand-cisco)] hover:text-white disabled:cursor-default disabled:border-emerald-500/40 disabled:bg-emerald-500/10 disabled:text-emerald-700 dark:disabled:text-emerald-300"
                  >
                    {applied ? 'Applied to custom pack' : 'Apply to custom pack'}
                  </button>
                )}
              </div>
            </li>
            );
          })}
        </ul>
      </InventoryGroup>

      <div className="flex flex-col gap-2 rounded-lg border border-fd-border bg-fd-card p-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-[11px] leading-4 text-fd-muted-foreground">
          See the proof boundaries, rule inventory, posture behavior, and pack activation
          guidance in the full reference.
        </p>
        <Link
          href={REFERENCE_HREF}
          className="shrink-0 rounded-md border border-[var(--brand-cisco)] px-3 py-1.5 text-center text-[11px] font-semibold text-[var(--brand-cisco)] transition-colors hover:bg-[var(--brand-cisco)] hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--brand-cisco)]"
        >
          Deterministic detection reference →
        </Link>
      </div>
    </div>
  );
}

function cloneRule(rule: RuleDef): RuleDef {
  return { ...rule, tags: [...rule.tags] };
}

function equivalentRule(current: RuleDef | undefined, wanted: RuleDef): boolean {
  if (!current) return false;
  return (
    current.enabled !== false &&
    current.pattern === wanted.pattern &&
    current.expression === wanted.expression &&
    current.tool_call_only === wanted.tool_call_only &&
    current.title === wanted.title &&
    current.severity === wanted.severity &&
    current.confidence === wanted.confidence &&
    JSON.stringify(current.tags) === JSON.stringify(wanted.tags)
  );
}

function Metric({ value, label }: { value: string; label: string }) {
  return (
    <div className="rounded-lg border border-fd-border bg-fd-background p-3">
      <dt className="text-[10px] leading-4 text-fd-muted-foreground">{label}</dt>
      <dd className="mt-0.5 text-xl font-semibold tracking-tight text-fd-foreground">{value}</dd>
    </div>
  );
}

function InventoryGroup({
  title,
  description,
  aside,
  children,
}: {
  title: string;
  description: string;
  aside?: string;
  children: React.ReactNode;
}) {
  return (
    <section aria-labelledby={`deterministic-${slugify(title)}`}>
      <div className="mb-2 flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h3
            id={`deterministic-${slugify(title)}`}
            className="text-xs font-semibold uppercase tracking-wide text-fd-foreground"
          >
            {title}
          </h3>
          <p className="mt-0.5 max-w-3xl text-[11px] leading-4 text-fd-muted-foreground">
            {description}
          </p>
        </div>
        {aside && <p className="shrink-0 text-[10px] font-medium text-fd-muted-foreground">{aside}</p>}
      </div>
      {children}
    </section>
  );
}

function StatusBadge({ mode }: { mode: 'enforcement-capable' | 'alert-only' }) {
  const enforcing = mode === 'enforcement-capable';
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
        enforcing
          ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
          : 'bg-amber-500/10 text-amber-700 dark:text-amber-300'
      }`}
    >
      {mode}
    </span>
  );
}

function PackBadge({ status }: { status: 'selectable' | 'staged' }) {
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
        status === 'selectable'
          ? 'bg-sky-500/10 text-sky-700 dark:text-sky-300'
          : 'bg-fd-muted text-fd-muted-foreground'
      }`}
    >
      {status === 'selectable' ? 'selectable at deployment' : 'staged · not activatable'}
    </span>
  );
}

function slugify(value: string): string {
  return value.toLowerCase().replaceAll(/[^a-z0-9]+/g, '-').replaceAll(/(^-|-$)/g, '');
}
