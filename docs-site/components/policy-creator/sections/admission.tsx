// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

'use client';

import type { FirstPartyEntry, Policy } from '../types';
import { SCANNER_TYPES } from '../types';
import { SegmentedControl } from '../ui/segmented-control';
import { TextField } from '../ui/text-field';
import { Toggle } from '../ui/toggle';

export function AdmissionSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  const updateAllow = (idx: number, patch: Partial<FirstPartyEntry>) => {
    const next = [...policy.first_party_allow_list];
    next[idx] = { ...next[idx], ...patch };
    onPolicyChange({ ...policy, first_party_allow_list: next });
  };
  const removeAllow = (idx: number) => {
    const next = policy.first_party_allow_list.filter((_, i) => i !== idx);
    onPolicyChange({ ...policy, first_party_allow_list: next });
  };
  const addAllow = () => {
    onPolicyChange({
      ...policy,
      first_party_allow_list: [
        ...policy.first_party_allow_list,
        { target_type: 'plugin', target_name: '', reason: '', source_path_contains: [] },
      ],
    });
  };

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Toggle
          label="Scan on install"
          hint="Run the appropriate scanner before allowing a new skill/MCP/plugin to install."
          checked={policy.admission.scan_on_install}
          onChange={(v) =>
            onPolicyChange({
              ...policy,
              admission: { ...policy.admission, scan_on_install: v },
            })
          }
        />
        <Toggle
          label="Allow-list bypasses scan"
          hint="If set, entries on the first-party allow list skip scanning entirely."
          checked={policy.admission.allow_list_bypass_scan}
          onChange={(v) =>
            onPolicyChange({
              ...policy,
              admission: { ...policy.admission, allow_list_bypass_scan: v },
            })
          }
        />
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wide text-fd-muted-foreground">
            First-party allow list
          </span>
          <button
            type="button"
            onClick={addAllow}
            className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-foreground hover:border-[var(--brand-cisco)]"
          >
            + Add entry
          </button>
        </div>
        {policy.first_party_allow_list.length === 0 ? (
          <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-3 text-center text-[11px] text-fd-muted-foreground">
            No entries. Skills/MCPs/plugins added here are allowed unconditionally and (depending on
            the toggle above) skip scanning.
          </p>
        ) : (
          <div className="space-y-2">
            {policy.first_party_allow_list.map((entry, idx) => (
              <div
                key={`${entry.target_type}-${entry.target_name}-${idx}`}
                className="grid grid-cols-1 gap-2 rounded-md border border-fd-border bg-fd-background p-2 sm:grid-cols-12"
              >
                <div className="sm:col-span-2">
                  <SegmentedControl
                    name={`type-${idx}`}
                    size="sm"
                    value={entry.target_type}
                    options={SCANNER_TYPES.map((s) => ({ value: s, label: s }))}
                    onChange={(v) => updateAllow(idx, { target_type: v })}
                  />
                </div>
                <div className="sm:col-span-3">
                  <TextField
                    label="name"
                    value={entry.target_name}
                    onChange={(v) => updateAllow(idx, { target_name: v })}
                    placeholder="codeguard"
                  />
                </div>
                <div className="sm:col-span-3">
                  <TextField
                    label="reason"
                    value={entry.reason}
                    onChange={(v) => updateAllow(idx, { reason: v })}
                    placeholder="first-party DefenseClaw skill"
                  />
                </div>
                <div className="sm:col-span-3">
                  <TextField
                    label="path contains (comma-separated)"
                    value={entry.source_path_contains.join(', ')}
                    onChange={(v) =>
                      updateAllow(idx, {
                        source_path_contains: v
                          .split(',')
                          .map((s) => s.trim())
                          .filter(Boolean),
                      })
                    }
                    placeholder=".defenseclaw, .openclaw/extensions"
                  />
                </div>
                <div className="flex items-end justify-end sm:col-span-1">
                  <button
                    type="button"
                    onClick={() => removeAllow(idx)}
                    aria-label="Remove"
                    className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-muted-foreground hover:border-red-500 hover:text-red-500"
                  >
                    ×
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
