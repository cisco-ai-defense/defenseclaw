// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Firewall section: default action, blocked destinations, allowed
// domains/ports. Wires into the firewall.wasm Live Test scenarios
// (firewall-allowed-domain, firewall-imds).

'use client';

import type { Policy } from '../types';
import { SegmentedControl } from '../ui/segmented-control';
import { TextField } from '../ui/text-field';

export function FirewallSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  const setF = (patch: Partial<Policy['firewall']>) =>
    onPolicyChange({ ...policy, firewall: { ...policy.firewall, ...patch } });

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-1">
        <span className="text-xs font-medium text-fd-muted-foreground">Default action</span>
        <SegmentedControl
          name="default_action"
          size="sm"
          value={policy.firewall.default_action}
          options={[
            { value: 'deny', label: 'deny' },
            { value: 'allow', label: 'allow' },
          ]}
          onChange={(v) => setF({ default_action: v })}
        />
        <span className="text-[11px] text-fd-muted-foreground">
          Default <code>deny</code> with an explicit <code>allowed_domains</code> list is the
          conservative choice. Default <code>allow</code> with a <code>blocked_destinations</code>
          list trades safety for compatibility with chatty third-party tools.
        </span>
      </div>

      <ListField
        label="blocked_destinations"
        items={policy.firewall.blocked_destinations}
        onChange={(next) => setF({ blocked_destinations: next })}
        placeholder="169.254.169.254"
        hint="Destinations that are always blocked. Default policy includes the AWS IMDS address."
      />
      <ListField
        label="allowed_domains"
        items={policy.firewall.allowed_domains}
        onChange={(next) => setF({ allowed_domains: next })}
        placeholder="api.github.com"
        hint="Domains that are always allowed (used when default_action=deny)."
      />
      <ListField
        label="allowed_ports (numeric)"
        items={policy.firewall.allowed_ports.map(String)}
        onChange={(next) =>
          setF({
            allowed_ports: next
              .map((s) => Number(s))
              .filter((n) => Number.isFinite(n) && n > 0 && n <= 65535),
          })
        }
        placeholder="443"
      />
    </div>
  );
}

function ListField({
  label,
  items,
  onChange,
  placeholder,
  hint,
}: {
  label: string;
  items: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  hint?: string;
}) {
  const add = () => onChange([...items, '']);
  const update = (idx: number, value: string) => {
    const next = [...items];
    next[idx] = value;
    onChange(next);
  };
  const remove = (idx: number) => onChange(items.filter((_, i) => i !== idx));

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-fd-muted-foreground">{label}</span>
        <button
          type="button"
          onClick={add}
          className="rounded-md border border-fd-border bg-fd-background px-2 py-0.5 text-[11px] text-fd-foreground hover:border-[var(--brand-cisco)]"
        >
          + Add
        </button>
      </div>
      {items.length === 0 ? (
        <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-2 text-center text-[11px] text-fd-muted-foreground">
          empty list
        </p>
      ) : (
        <ul className="space-y-1">
          {items.map((item, idx) => (
            <li key={idx} className="flex gap-1">
              <TextField
                label=""
                value={item}
                onChange={(v) => update(idx, v)}
                placeholder={placeholder}
              />
              <button
                type="button"
                onClick={() => remove(idx)}
                aria-label="Remove"
                className="self-end rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-muted-foreground hover:border-red-500 hover:text-red-500"
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}
      {hint && <p className="text-[11px] text-fd-muted-foreground">{hint}</p>}
    </div>
  );
}
