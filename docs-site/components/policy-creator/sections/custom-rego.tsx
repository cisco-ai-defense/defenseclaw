// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Custom Rego playground. Lets the operator drop in supplemental
// .rego snippets that get installed alongside the bundled modules.
// We do not compile in-browser — when the operator runs the install
// script, OPA on the host validates the snippet via `opa check`.
//
// The source field uses our zero-dep RegoEditor (textarea + transparent
// highlighted overlay). See ui/code-editor.tsx for why we don't pull in
// CodeMirror or Monaco for this niche surface.

'use client';

import { useMemo } from 'react';
import type { CustomRegoSnippet, Policy } from '../types';
import { lintRego } from '../lib/rego-lint';
import { TextField } from '../ui/text-field';
import { RegoEditor } from '../ui/code-editor';

const STARTER_SNIPPET = (name: string) => `package defenseclaw.custom.${name}

import rego.v1

# Example: tag verdict reasons emitted from the bundled policies with
# a custom string operators can search for in the audit log.
extra_reason := "custom-rule-fired" if {
    input.scan_result.max_severity == "CRITICAL"
}
`;

export function CustomRegoSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  const update = (idx: number, patch: Partial<CustomRegoSnippet>) => {
    const next = [...policy.custom_rego];
    next[idx] = { ...next[idx], ...patch };
    onPolicyChange({ ...policy, custom_rego: next });
  };
  const remove = (idx: number) => {
    onPolicyChange({
      ...policy,
      custom_rego: policy.custom_rego.filter((_, i) => i !== idx),
    });
  };
  const add = () => {
    const taken = new Set(policy.custom_rego.map((s) => s.name));
    let name = 'my_rule';
    let i = 1;
    while (taken.has(name)) {
      i += 1;
      name = `my_rule_${i}`;
    }
    onPolicyChange({
      ...policy,
      custom_rego: [
        ...policy.custom_rego,
        {
          name,
          package: `defenseclaw.custom.${name}`,
          description: 'Custom Rego snippet',
          source: STARTER_SNIPPET(name),
        },
      ],
    });
  };

  return (
    <div className="space-y-3">
      <Callout />
      <div className="flex justify-end">
        <button
          type="button"
          onClick={add}
          className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-foreground hover:border-[var(--brand-cisco)]"
        >
          + Add snippet
        </button>
      </div>
      {policy.custom_rego.length === 0 ? (
        <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-3 text-center text-[11px] text-fd-muted-foreground">
          No custom Rego. The bundled admission/guardrail/firewall/audit/skill_actions modules
          cover most cases — only reach for this section when you need a verdict the bundled
          Rego can&apos;t express.
        </p>
      ) : (
        <ul className="space-y-3">
          {policy.custom_rego.map((snippet, idx) => (
            <SnippetEditor
              key={snippet.name + idx}
              snippet={snippet}
              onChange={(patch) => update(idx, patch)}
              onRemove={() => remove(idx)}
            />
          ))}
        </ul>
      )}
    </div>
  );
}

function Callout() {
  return (
    <div className="rounded-md border border-fd-border bg-fd-card/40 px-3 py-2 text-[11px] text-fd-muted-foreground">
      Snippets you author here are written to{' '}
      <code className="font-mono">~/.defenseclaw/policies/rego/custom-&lt;name&gt;.rego</code>{' '}
      by the install script. The wizard runs a few client-side shape checks, but the
      real compile happens via{' '}
      <code className="font-mono">opa check</code> on your host — install will surface any
      errors there before activation.
    </div>
  );
}

function SnippetEditor({
  snippet,
  onChange,
  onRemove,
}: {
  snippet: CustomRegoSnippet;
  onChange: (patch: Partial<CustomRegoSnippet>) => void;
  onRemove: () => void;
}) {
  const findings = useMemo(() => lintRego(snippet.source), [snippet.source]);
  const errors = findings.filter((f) => f.level === 'error');
  const warnings = findings.filter((f) => f.level === 'warning');

  return (
    <li className="space-y-2 rounded-md border border-fd-border bg-fd-background p-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <TextField
          label="name (filename = custom-<name>.rego)"
          value={snippet.name}
          onChange={(v) =>
            onChange({
              name: v,
              package: `defenseclaw.custom.${v.replace(/[^A-Za-z0-9_]/g, '_')}`,
            })
          }
        />
        <TextField
          label="description"
          value={snippet.description}
          onChange={(v) => onChange({ description: v })}
        />
      </div>
      <RegoEditor
        label="source"
        value={snippet.source}
        onChange={(v) => onChange({ source: v })}
        hint="Tab inserts 2 spaces · Shift-Tab dedents · highlighting is presentation-only — `opa check` runs on your host at install time."
      />
      {findings.length === 0 ? (
        <div className="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-[11px] text-emerald-700 dark:text-emerald-300">
          No client-side issues. Run <code className="font-mono">opa check</code> after install
          for the authoritative result.
        </div>
      ) : (
        <ul className="space-y-1">
          {findings.map((f, i) => (
            <li
              key={i}
              className={[
                'rounded-md border px-2 py-1 text-[11px]',
                f.level === 'error'
                  ? 'border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300'
                  : f.level === 'warning'
                    ? 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                    : 'border-fd-border bg-fd-card text-fd-muted-foreground',
              ].join(' ')}
            >
              <span className="mr-1 font-mono">L{f.line}</span>
              <span>{f.message}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10px] text-fd-muted-foreground">
          {errors.length} error{errors.length === 1 ? '' : 's'} · {warnings.length} warning
          {warnings.length === 1 ? '' : 's'}
        </span>
        <button
          type="button"
          onClick={onRemove}
          className="text-[11px] text-fd-muted-foreground hover:text-red-500"
        >
          Remove snippet
        </button>
      </div>
    </li>
  );
}
