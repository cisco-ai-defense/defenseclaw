// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Editor for the gateway's "sensitive tool" inspection list. When a
// matching tool runs, the gateway can either run a heuristic on the
// result (result_inspection: true) or hand the result to a judge
// (judge_result: true). Both are off by default — operators add
// tools here when a particular API is known to leak.

'use client';

import type { Policy, SensitiveTool } from '../types';
import { TextField } from '../ui/text-field';
import { Toggle } from '../ui/toggle';

export function SensitiveToolsSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  const update = (idx: number, patch: Partial<SensitiveTool>) => {
    const next = [...policy.sensitive_tools];
    next[idx] = { ...next[idx], ...patch };
    onPolicyChange({ ...policy, sensitive_tools: next });
  };
  const remove = (idx: number) => {
    onPolicyChange({
      ...policy,
      sensitive_tools: policy.sensitive_tools.filter((_, i) => i !== idx),
    });
  };
  const add = () =>
    onPolicyChange({
      ...policy,
      sensitive_tools: [
        ...policy.sensitive_tools,
        { name: '', result_inspection: true, judge_result: false, min_entities_for_alert: 1 },
      ],
    });

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wide text-fd-muted-foreground">
          Sensitive tool inspection
        </span>
        <button
          type="button"
          onClick={add}
          className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-foreground hover:border-[var(--brand-cisco)]"
        >
          + Add tool
        </button>
      </div>
      {policy.sensitive_tools.length === 0 ? (
        <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-3 text-center text-[11px] text-fd-muted-foreground">
          No sensitive tools configured. Add one when a specific tool (e.g. <code>fs.read</code>,
          <code>db.query</code>) routinely returns sensitive content you want inspected.
        </p>
      ) : (
        <ul className="space-y-2">
          {policy.sensitive_tools.map((tool, idx) => (
            <li
              key={idx}
              className="grid grid-cols-1 gap-2 rounded-md border border-fd-border bg-fd-background p-2 sm:grid-cols-12"
            >
              <div className="sm:col-span-3">
                <TextField
                  label="name"
                  value={tool.name}
                  onChange={(v) => update(idx, { name: v })}
                  placeholder="fs.read"
                />
              </div>
              <div className="sm:col-span-3">
                <Toggle
                  label="result_inspection"
                  hint="Run the heuristic over the tool result before returning."
                  checked={tool.result_inspection}
                  onChange={(v) => update(idx, { result_inspection: v })}
                />
              </div>
              <div className="sm:col-span-3">
                <Toggle
                  label="judge_result"
                  hint="Hand the tool result to the LLM judge."
                  checked={tool.judge_result}
                  onChange={(v) => update(idx, { judge_result: v })}
                />
              </div>
              <div className="sm:col-span-2">
                <TextField
                  label="min_entities_for_alert"
                  inputMode="numeric"
                  value={String(tool.min_entities_for_alert ?? 1)}
                  onChange={(v) => {
                    const n = Number(v);
                    if (Number.isFinite(n)) update(idx, { min_entities_for_alert: n });
                  }}
                />
              </div>
              <div className="flex items-end justify-end sm:col-span-1">
                <button
                  type="button"
                  onClick={() => remove(idx)}
                  aria-label="Remove"
                  className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-muted-foreground hover:border-red-500 hover:text-red-500"
                >
                  ×
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
