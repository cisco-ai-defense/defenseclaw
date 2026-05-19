// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Operational sections — webhook destinations, watch (rescan)
// schedule, enforcement timeout, audit retention. These are the
// "infra" knobs an operator typically only touches once per
// environment, but the wizard surfaces them for completeness.

'use client';

import type { Policy, SeverityUpper, WebhookEntry } from '../types';
import { SEVERITIES_UPPER } from '../types';
import { SegmentedControl } from '../ui/segmented-control';
import { TextField } from '../ui/text-field';
import { Toggle } from '../ui/toggle';

export function WebhooksSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  const update = (idx: number, patch: Partial<WebhookEntry>) => {
    const next = [...policy.webhooks];
    next[idx] = { ...next[idx], ...patch };
    onPolicyChange({ ...policy, webhooks: next });
  };
  const remove = (idx: number) => {
    onPolicyChange({ ...policy, webhooks: policy.webhooks.filter((_, i) => i !== idx) });
  };
  const add = () => {
    onPolicyChange({
      ...policy,
      webhooks: [
        ...policy.webhooks,
        {
          url: '',
          type: 'slack',
          secret_env: 'SLACK_WEBHOOK_SECRET',
          min_severity: 'HIGH',
          events: ['block', 'guardrail'],
          enabled: true,
        },
      ],
    });
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wide text-fd-muted-foreground">
          Outbound webhooks
        </span>
        <button
          type="button"
          onClick={add}
          className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-foreground hover:border-[var(--brand-cisco)]"
        >
          + Add webhook
        </button>
      </div>
      {policy.webhooks.length === 0 ? (
        <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-3 text-center text-[11px] text-fd-muted-foreground">
          No webhooks. Add one to forward DefenseClaw blocks/drift alerts to Slack, Webex,
          PagerDuty, or a generic JSON endpoint.
        </p>
      ) : (
        <ul className="space-y-2">
          {policy.webhooks.map((wh, idx) => (
            <li
              key={idx}
              className="space-y-2 rounded-md border border-fd-border bg-fd-background p-3"
            >
              <div className="flex flex-wrap items-center gap-2">
                <Toggle
                  label="enabled"
                  checked={wh.enabled}
                  onChange={(v) => update(idx, { enabled: v })}
                />
                <SegmentedControl
                  name={`type-${idx}`}
                  size="sm"
                  value={wh.type}
                  options={[
                    { value: 'slack', label: 'slack' },
                    { value: 'webex', label: 'webex' },
                    { value: 'pagerduty', label: 'pagerduty' },
                    { value: 'generic', label: 'generic' },
                  ]}
                  onChange={(v) => update(idx, { type: v })}
                />
                <SegmentedControl
                  name={`sev-${idx}`}
                  size="sm"
                  value={wh.min_severity}
                  options={[...SEVERITIES_UPPER].map((s) => ({ value: s, label: s }))}
                  onChange={(v: SeverityUpper) => update(idx, { min_severity: v })}
                />
                <button
                  type="button"
                  onClick={() => remove(idx)}
                  aria-label="Remove"
                  className="ml-auto rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-muted-foreground hover:border-red-500 hover:text-red-500"
                >
                  ×
                </button>
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <TextField
                  label="url"
                  value={wh.url}
                  onChange={(v) => update(idx, { url: v })}
                  placeholder="https://hooks.slack.com/services/T0/B0/xxx"
                />
                <TextField
                  label="secret_env (env var holding the signing secret)"
                  value={wh.secret_env ?? ''}
                  onChange={(v) => update(idx, { secret_env: v || undefined })}
                  placeholder="SLACK_WEBHOOK_SECRET"
                />
                {wh.type === 'webex' && (
                  <TextField
                    label="room_id"
                    value={wh.room_id ?? ''}
                    onChange={(v) => update(idx, { room_id: v || undefined })}
                  />
                )}
              </div>
              <div>
                <span className="mb-1 block text-xs font-medium text-fd-muted-foreground">
                  events
                </span>
                <div className="flex flex-wrap gap-1">
                  {(['block', 'drift', 'guardrail'] as const).map((evt) => (
                    <button
                      key={evt}
                      type="button"
                      onClick={() =>
                        update(idx, {
                          events: wh.events.includes(evt)
                            ? wh.events.filter((e) => e !== evt)
                            : [...wh.events, evt],
                        })
                      }
                      className={[
                        'rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-wide',
                        wh.events.includes(evt)
                          ? 'border-[var(--brand-cisco)] bg-[var(--brand-cisco)]/15 text-[var(--brand-cisco-strong)]'
                          : 'border-fd-border bg-fd-background text-fd-muted-foreground',
                      ].join(' ')}
                    >
                      {evt}
                    </button>
                  ))}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function WatchSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  return (
    <div className="space-y-3">
      <Toggle
        label="Periodic rescan enabled"
        hint="Runs the scanners on disk again every interval to catch in-place tampering."
        checked={policy.watch.rescan_enabled}
        onChange={(v) =>
          onPolicyChange({ ...policy, watch: { ...policy.watch, rescan_enabled: v } })
        }
      />
      <TextField
        label="rescan_interval_min"
        inputMode="numeric"
        value={String(policy.watch.rescan_interval_min)}
        onChange={(v) => {
          const n = Number(v);
          if (Number.isFinite(n)) {
            onPolicyChange({
              ...policy,
              watch: { ...policy.watch, rescan_interval_min: n },
            });
          }
        }}
        hint="How often (minutes) to rescan installed skills/MCPs/plugins. 30 is the default."
      />
    </div>
  );
}

export function EnforcementSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  return (
    <div>
      <TextField
        label="max_enforcement_delay_seconds"
        inputMode="numeric"
        value={String(policy.enforcement.max_enforcement_delay_seconds)}
        onChange={(v) => {
          const n = Number(v);
          if (Number.isFinite(n)) {
            onPolicyChange({
              ...policy,
              enforcement: {
                ...policy.enforcement,
                max_enforcement_delay_seconds: Math.max(0, n),
              },
            });
          }
        }}
        hint="Hard ceiling on how long the gateway will block waiting for HITL approval. 2s is the default; bump it for human-driven workflows."
      />
    </div>
  );
}

export function AuditSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  return (
    <div className="space-y-3">
      <Toggle
        label="log_all_actions"
        hint="Persist every gateway action (allow/deny/block/quarantine)."
        checked={policy.audit.log_all_actions}
        onChange={(v) =>
          onPolicyChange({ ...policy, audit: { ...policy.audit, log_all_actions: v } })
        }
      />
      <Toggle
        label="log_scan_results"
        hint="Persist every scanner output, even when the verdict is 'clean'."
        checked={policy.audit.log_scan_results}
        onChange={(v) =>
          onPolicyChange({ ...policy, audit: { ...policy.audit, log_scan_results: v } })
        }
      />
      <TextField
        label="retention_days"
        inputMode="numeric"
        value={String(policy.audit.retention_days)}
        onChange={(v) => {
          const n = Number(v);
          if (Number.isFinite(n)) {
            onPolicyChange({
              ...policy,
              audit: { ...policy.audit, retention_days: Math.max(1, n) },
            });
          }
        }}
        hint="Days non-CRITICAL events are retained. CRITICAL events are kept indefinitely (see audit.rego)."
      />
    </div>
  );
}

export function ScannersSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  const set = (scanner: keyof Policy['scanners'], profile: string | undefined) =>
    onPolicyChange({
      ...policy,
      scanners: { ...policy.scanners, [scanner]: profile },
    });

  const ROW = (
    name: keyof Policy['scanners'],
    presets: string[],
    description: string,
  ) => (
    <li key={name} className="space-y-1 rounded-md border border-fd-border bg-fd-background p-2">
      <div className="flex items-center gap-2">
        <span className="font-mono text-xs text-fd-foreground">{name}</span>
        <span className="text-[11px] text-fd-muted-foreground">{description}</span>
      </div>
      <SegmentedControl
        name={`scanner-${name}`}
        size="sm"
        value={policy.scanners[name] ?? '__default__'}
        options={[
          { value: '__default__', label: 'inherit' },
          ...presets.map((p) => ({ value: p, label: p })),
        ]}
        onChange={(v) => set(name, v === '__default__' ? undefined : v)}
      />
    </li>
  );

  return (
    <ul className="space-y-2">
      {ROW('codeguard', ['default', 'strict', 'permissive'], 'Source-code scanner.')}
      {ROW('plugin-scanner', ['default', 'strict', 'permissive'], 'IDE/editor plugin scanner.')}
      {ROW('skill-scanner', ['default', 'strict', 'permissive'], 'Claude/Codex/OpenClaw skills scanner.')}
    </ul>
  );
}
