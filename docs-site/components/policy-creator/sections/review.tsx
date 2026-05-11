// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Review & Export. Three sub-views:
//
//   files     — every YAML / data.json / Rego snippet the wizard
//               renders, with per-file copy buttons.
//   install   — one bash script that lays everything down on disk
//               and runs `defenseclaw policy activate`.
//   diff      — what's different vs the bundled preset the wizard
//               started from.

'use client';

import { useMemo, useState } from 'react';
import type { Policy } from '../types';
import { diffAgainstBase } from '../lib/diff';
import { emit, type EmittedFile } from '../lib/emit';
import { emitInstallScript } from '../lib/emit-script';
import { CopyButton } from '../ui/copy-button';
import { DownloadButton } from '../ui/download-button';
import { SegmentedControl } from '../ui/segmented-control';

type Tab = 'files' | 'install' | 'diff';

export function ReviewSection({ policy }: { policy: Policy }) {
  const [tab, setTab] = useState<Tab>('files');
  const files = useMemo(() => emit(policy), [policy]);
  const script = useMemo(() => emitInstallScript(policy), [policy]);
  const diff = useMemo(() => diffAgainstBase(policy), [policy]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <SegmentedControl
          name="review-tab"
          size="sm"
          value={tab}
          options={[
            { value: 'files', label: `files (${files.length})` },
            { value: 'install', label: 'install script' },
            { value: 'diff', label: `diff vs ${policy.basedOn} (${diff.length})` },
          ]}
          onChange={setTab}
        />
        {tab === 'install' && (
          <div className="ml-auto flex gap-1">
            <DownloadButton
              filename={`install-${policy.name}.sh`}
              contents={script}
              mime="text/x-shellscript"
            />
            <CopyButton value={script} label="Copy script" />
          </div>
        )}
      </div>

      {tab === 'files' && <FilesView files={files} />}
      {tab === 'install' && <InstallView script={script} />}
      {tab === 'diff' && <DiffView diff={diff} basedOn={policy.basedOn} />}
    </div>
  );
}

function FilesView({ files }: { files: EmittedFile[] }) {
  const [activeIdx, setActiveIdx] = useState(0);
  const active = files[activeIdx];
  return (
    <>
      <div className="flex flex-wrap gap-1.5">
        {files.map((f, i) => (
          <button
            key={f.path}
            type="button"
            onClick={() => setActiveIdx(i)}
            className={[
              'rounded-md border px-2 py-1 text-[11px] font-medium transition-colors',
              i === activeIdx
                ? 'border-[var(--brand-cisco)] bg-[var(--brand-cisco)]/15 text-[var(--brand-cisco-strong)]'
                : 'border-fd-border bg-fd-background text-fd-muted-foreground hover:text-fd-foreground',
            ].join(' ')}
          >
            {pathBase(f.path)}
          </button>
        ))}
      </div>
      {active && (
        <div className="overflow-hidden rounded-md border border-fd-border bg-fd-background">
          <div className="flex items-center justify-between border-b border-fd-border bg-fd-card px-3 py-2">
            <div className="flex flex-col">
              <span className="font-mono text-[11px] text-fd-foreground">{active.path}</span>
              <span className="text-[10px] text-fd-muted-foreground">{active.description}</span>
            </div>
            <div className="flex gap-1">
              <DownloadButton
                filename={pathBase(active.path)}
                contents={active.contents}
                mime="text/plain"
              />
              <CopyButton value={active.contents} label="Copy file" />
            </div>
          </div>
          <pre className="max-h-96 overflow-auto bg-fd-background px-3 py-2 text-[11px] leading-snug text-fd-foreground">
            {active.contents}
          </pre>
        </div>
      )}
    </>
  );
}

function InstallView({ script }: { script: string }) {
  return (
    <div className="overflow-hidden rounded-md border border-fd-border bg-fd-background">
      <div className="flex items-center justify-between border-b border-fd-border bg-fd-card px-3 py-2">
        <div className="flex flex-col">
          <span className="font-mono text-[11px] text-fd-foreground">install-policy.sh</span>
          <span className="text-[10px] text-fd-muted-foreground">
            Self-contained bash script. Inspect the heredocs before running.
          </span>
        </div>
      </div>
      <pre className="max-h-96 overflow-auto bg-fd-background px-3 py-2 text-[11px] leading-snug text-fd-foreground">
        {script}
      </pre>
    </div>
  );
}

function DiffView({
  diff,
  basedOn,
}: {
  diff: ReturnType<typeof diffAgainstBase>;
  basedOn: string;
}) {
  if (diff.length === 0) {
    return (
      <p className="rounded-md border border-fd-border bg-fd-background px-3 py-3 text-center text-[11px] text-fd-muted-foreground">
        No differences from the {basedOn} preset.
      </p>
    );
  }
  return (
    <ul className="divide-y divide-fd-border rounded-md border border-fd-border bg-fd-background">
      {diff.map((d, i) => (
        <li key={i} className="flex items-baseline gap-2 px-3 py-2 text-[11px]">
          <span
            className={[
              'rounded-full px-2 py-0.5 text-[9px] uppercase tracking-wide',
              d.kind === 'added'
                ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300'
                : d.kind === 'removed'
                  ? 'bg-red-500/15 text-red-700 dark:text-red-300'
                  : 'bg-amber-500/15 text-amber-700 dark:text-amber-300',
            ].join(' ')}
          >
            {d.kind}
          </span>
          <code className="font-mono text-fd-foreground">{d.path}</code>
          <span className="ml-auto text-fd-muted-foreground">{d.description}</span>
        </li>
      ))}
    </ul>
  );
}

function pathBase(path: string): string {
  const parts = path.split('/');
  return parts[parts.length - 1] ?? path;
}
