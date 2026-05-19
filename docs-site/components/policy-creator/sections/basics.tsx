// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useEffect, useState } from 'react';
import type { Policy } from '../types';
import { listPresets, policyFromPreset } from '../lib/presets';
import { SegmentedControl } from '../ui/segmented-control';
import { TextField, TextArea } from '../ui/text-field';

export function BasicsSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  const presets = listPresets();
  const [pendingPreset, setPendingPreset] = useState<Policy['basedOn'] | null>(null);
  // Validate the policy name client-side. Engine accepts [a-z0-9-]+
  // with no leading dash.
  const nameError = validateName(policy.name);

  useEffect(() => {
    if (pendingPreset == null) return;
    if (window.confirm(`Reset all sections to the "${pendingPreset}" preset? Your edits will be lost.`)) {
      const next = policyFromPreset(pendingPreset);
      onPolicyChange({ ...next, name: policy.name, description: policy.description });
    }
    setPendingPreset(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingPreset]);

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <TextField
        label="Policy name"
        placeholder="my-policy"
        value={policy.name}
        onChange={(v) => onPolicyChange({ ...policy, name: v })}
        error={nameError ?? undefined}
        hint={
          nameError ? undefined : 'Used as the directory name under ~/.defenseclaw/policies/.'
        }
      />
      <div className="flex flex-col gap-1">
        <span className="text-xs font-medium text-fd-muted-foreground">Based on</span>
        <SegmentedControl
          name="Preset"
          value={policy.basedOn}
          options={presets.map((p) => ({ value: p.name, label: p.name }))}
          onChange={(v) => setPendingPreset(v)}
        />
        <span className="text-[11px] text-fd-muted-foreground">
          Picking a preset replaces every section with the bundled defaults. You can still
          customize sections afterwards.
        </span>
      </div>
      <div className="sm:col-span-2">
        <TextArea
          label="Description"
          rows={2}
          value={policy.description}
          onChange={(v) => onPolicyChange({ ...policy, description: v })}
          placeholder="What this policy is for, and where it gets activated."
        />
      </div>
    </div>
  );
}

function validateName(name: string): string | null {
  if (!name) return 'Required';
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(name)) {
    return 'Use lowercase letters, digits, and hyphens (≤64 chars).';
  }
  return null;
}
