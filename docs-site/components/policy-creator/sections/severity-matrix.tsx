// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useState } from 'react';
import type { Policy, Severity } from '../types';
import { SCANNER_TYPES, SEVERITIES } from '../types';
import { SegmentedControl } from '../ui/segmented-control';

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

const RUNTIME_OPTS = [
  { value: 'enable', label: 'enable' },
  { value: 'disable', label: 'disable' },
] as const;

const FILE_OPTS = [
  { value: 'none', label: 'none' },
  { value: 'quarantine', label: 'quarantine' },
] as const;

const INSTALL_OPTS = [
  { value: 'none', label: 'none' },
  { value: 'allow', label: 'allow' },
  { value: 'block', label: 'block' },
] as const;

export function SeverityMatrixSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  const [scanner, setScanner] = useState<'__base__' | (typeof SCANNER_TYPES)[number]>('__base__');

  const updateBase = (sev: Severity, key: 'runtime' | 'file' | 'install', value: string) => {
    const triple = { ...policy.skill_actions[sev], [key]: value };
    onPolicyChange({
      ...policy,
      skill_actions: { ...policy.skill_actions, [sev]: triple },
    });
  };

  const updateOverride = (
    scannerName: (typeof SCANNER_TYPES)[number],
    sev: Severity,
    key: 'runtime' | 'file' | 'install',
    value: string,
  ) => {
    const baseOverride = policy.scanner_overrides[scannerName] ?? {};
    const baseTriple = baseOverride[sev] ?? policy.skill_actions[sev];
    const updatedTriple = { ...baseTriple, [key]: value };
    const updatedOverride = { ...baseOverride, [sev]: updatedTriple };
    onPolicyChange({
      ...policy,
      scanner_overrides: { ...policy.scanner_overrides, [scannerName]: updatedOverride },
    });
  };

  const clearOverrides = (scannerName: (typeof SCANNER_TYPES)[number]) => {
    const next = { ...policy.scanner_overrides };
    delete next[scannerName];
    onPolicyChange({ ...policy, scanner_overrides: next });
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11px] font-medium uppercase tracking-wide text-fd-muted-foreground">
          Scope
        </span>
        <SegmentedControl
          name="Scope"
          value={scanner}
          size="sm"
          options={[
            { value: '__base__', label: 'all scanners' },
            ...SCANNER_TYPES.map((s) => ({ value: s, label: s })),
          ]}
          onChange={(v) => setScanner(v)}
        />
        {scanner !== '__base__' && policy.scanner_overrides[scanner] && (
          <button
            type="button"
            onClick={() => clearOverrides(scanner)}
            className="ml-auto rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-muted-foreground hover:border-red-500 hover:text-red-500"
          >
            Reset {scanner} overrides
          </button>
        )}
      </div>

      <div className="overflow-x-auto rounded-md border border-fd-border bg-fd-background">
        <table className="min-w-full divide-y divide-fd-border text-left text-xs">
          <thead className="bg-fd-card text-[10px] uppercase tracking-wide text-fd-muted-foreground">
            <tr>
              <th className="px-3 py-2">severity</th>
              <th className="px-3 py-2">runtime</th>
              <th className="px-3 py-2">file</th>
              <th className="px-3 py-2">install</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-fd-border">
            {SEVERITIES.map((sev) => {
              const triple =
                scanner === '__base__'
                  ? policy.skill_actions[sev]
                  : policy.scanner_overrides[scanner]?.[sev] ?? policy.skill_actions[sev];
              const isOverride =
                scanner !== '__base__' && policy.scanner_overrides[scanner]?.[sev] != null;
              return (
                <tr key={sev}>
                  <td className="px-3 py-2 font-mono">
                    <span className="text-fd-foreground">{SEVERITY_LABEL[sev]}</span>
                    {isOverride && (
                      <span className="ml-1 rounded-full bg-[var(--brand-cisco)]/15 px-1.5 py-0.5 text-[9px] font-medium text-[var(--brand-cisco-strong)]">
                        override
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <SegmentedControl
                      name={`${sev}-runtime`}
                      size="sm"
                      value={triple.runtime}
                      options={[...RUNTIME_OPTS]}
                      onChange={(v) =>
                        scanner === '__base__'
                          ? updateBase(sev, 'runtime', v)
                          : updateOverride(scanner, sev, 'runtime', v)
                      }
                    />
                  </td>
                  <td className="px-3 py-2">
                    <SegmentedControl
                      name={`${sev}-file`}
                      size="sm"
                      value={triple.file}
                      options={[...FILE_OPTS]}
                      onChange={(v) =>
                        scanner === '__base__'
                          ? updateBase(sev, 'file', v)
                          : updateOverride(scanner, sev, 'file', v)
                      }
                    />
                  </td>
                  <td className="px-3 py-2">
                    <SegmentedControl
                      name={`${sev}-install`}
                      size="sm"
                      value={triple.install}
                      options={[...INSTALL_OPTS]}
                      onChange={(v) =>
                        scanner === '__base__'
                          ? updateBase(sev, 'install', v)
                          : updateOverride(scanner, sev, 'install', v)
                      }
                    />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="text-[11px] text-fd-muted-foreground">
        <strong>runtime:</strong> what happens to a running skill/MCP/plugin.{' '}
        <strong>file:</strong> whether the on-disk artifact is left in place or quarantined.{' '}
        <strong>install:</strong> whether new installs are allowed at this severity.
      </p>
    </div>
  );
}
