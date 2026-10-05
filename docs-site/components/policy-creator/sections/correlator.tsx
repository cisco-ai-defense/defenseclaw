// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Layer-5 (session correlator) inventory. Read-only: the gateway runs
// only the patterns compiled in from
// internal/guardrail/defaults/correlation-patterns.yaml
// (guardrail.DefaultCorrelationPatterns), and the rule-pack loader
// rejects a correlation-patterns.yaml file inside a pack. The creator
// therefore shows the bundled patterns but never exports them.

'use client';

import type { CorrelationClause, CorrelationPattern, Policy } from '../types';

export function CorrelatorSection({
  policy,
}: {
  policy: Policy;
  // Kept for the shared section signature; this section never edits.
  onPolicyChange?: (next: Policy) => void;
}) {
  return (
    <div className="space-y-3">
      <div className="rounded-md border border-fd-border bg-fd-card p-3 text-[12px] leading-5 text-fd-muted-foreground">
        <p>
          The correlator reads the most recent findings in a session and saves a
          <code className="mx-1">CORR-&lt;PATTERN_ID&gt;</code> finding at the pattern&apos;s
          severity when the pattern matches. It detects and records; it does not block the
          request that completed the pattern.
        </p>
        <p className="mt-2">
          <strong className="text-fd-foreground">Read-only.</strong>{' '}These patterns are compiled
          into the gateway and always run. They can&apos;t be changed in a rule pack, so the
          export doesn&apos;t include them.
        </p>
      </div>

      {policy.correlator.length === 0 ? (
        <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-3 text-center text-[11px] text-fd-muted-foreground">
          Pick a preset to show the bundled patterns (LETHAL-TRIFECTA and
          TRIFECTA-WITH-FINGERPRINT-MATCH).
        </p>
      ) : (
        <ul className="space-y-3">
          {policy.correlator.map((pattern) => (
            <PatternCard key={pattern.id} pattern={pattern} />
          ))}
        </ul>
      )}
    </div>
  );
}

function PatternCard({ pattern }: { pattern: CorrelationPattern }) {
  const mode =
    pattern.sequence && pattern.sequence.length > 0
      ? 'sequence'
      : pattern.fingerprint_chain && pattern.fingerprint_chain.length > 0
        ? 'fingerprint_chain'
        : 'all_of';
  const clauses: string[] =
    mode === 'sequence'
      ? (pattern.sequence ?? []).map((s) => `severity ${s.severity}`)
      : (mode === 'fingerprint_chain' ? pattern.fingerprint_chain ?? [] : pattern.all_of ?? []).map(
          describeClause,
        );

  return (
    <li className="rounded-md border border-fd-border bg-fd-background p-3">
      <div className="flex flex-wrap items-center gap-2">
        <code className="rounded bg-fd-muted/40 px-1.5 py-0.5 text-[12px] font-semibold text-fd-foreground">
          {pattern.id}
        </code>
        <span className="text-[11px] text-fd-muted-foreground">
          last {pattern.window_events} findings, {pattern.severity_on_match} on match
        </span>
      </div>
      {pattern.description && (
        <p className="mt-2 text-[12px] leading-5 text-fd-muted-foreground">{pattern.description}</p>
      )}
      <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[11px]">
        <dt className="text-fd-muted-foreground">Match mode</dt>
        <dd className="font-mono text-fd-foreground">{mode}</dd>
        <dt className="text-fd-muted-foreground">Clauses</dt>
        <dd className="text-fd-foreground">
          <ol className="list-decimal space-y-0.5 pl-4 font-mono">
            {clauses.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ol>
        </dd>
      </dl>
    </li>
  );
}

function describeClause(c: CorrelationClause | undefined): string {
  if (!c) return '(any finding)';
  const parts: string[] = [];
  if (c.axis) parts.push(`axis ${c.axis}`);
  if (c.tool_capability_class) parts.push(`capability ${c.tool_capability_class}`);
  if (c.min_severity) parts.push(`severity ≥ ${c.min_severity}`);
  if (c.with_rule_match && c.with_rule_match.length > 0) {
    parts.push(`rule ${c.with_rule_match.join(' | ')}`);
  }
  return parts.length > 0 ? parts.join(', ') : '(any finding)';
}
