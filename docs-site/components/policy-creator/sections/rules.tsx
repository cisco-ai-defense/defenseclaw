// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Editor for the rule pack files (policies/guardrail/<pack>/rules/*.yaml).
// Each file groups rules by category. The wizard surfaces all bundled
// rules (from the strict pack) inline, lets the operator toggle them on/off,
// and lets them add new rules from the recipe catalog or from scratch.

'use client';

import { useState } from 'react';
import type { Policy, Recipe, RuleDef, RulesFile, SeverityUpper } from '../types';
import { SEVERITIES_UPPER } from '../types';
import { ChipsField } from '../ui/chips-field';
import { RecipePicker } from '../ui/recipe-picker';
import { RegexInput } from '../ui/regex-input';
import { SegmentedControl } from '../ui/segmented-control';
import { TextField } from '../ui/text-field';
import { Toggle } from '../ui/toggle';

const RULE_RECIPE_KINDS: Recipe['kind'][] = [
  'rule:secrets',
  'rule:injection',
  'rule:exfiltration',
  'rule:command',
  'rule:path',
  'rule:enterprise-data',
  'rule:trust-exploit',
  'rule:cognitive',
  'rule:c2',
];

export function RulesSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  // Use a separate exampleStore so the operator's match/no-match
  // examples persist across edits without polluting the rule body
  // (the engine doesn't read them — they're a wizard-side affordance).
  const [examples, setExamples] = useState<Record<string, { match: string[]; no: string[] }>>({});

  const updateRulePack = (next: RulesFile[]) => {
    onPolicyChange({
      ...policy,
      rule_pack: { ...policy.rule_pack, files: next },
    });
  };

  const updateRule = (fileIdx: number, ruleIdx: number, patch: Partial<RuleDef>) => {
    const files = [...policy.rule_pack.files];
    const rules = [...files[fileIdx].rules];
    rules[ruleIdx] = { ...rules[ruleIdx], ...patch };
    files[fileIdx] = { ...files[fileIdx], rules };
    updateRulePack(files);
  };

  const removeRule = (fileIdx: number, ruleIdx: number) => {
    const files = [...policy.rule_pack.files];
    files[fileIdx] = {
      ...files[fileIdx],
      rules: files[fileIdx].rules.filter((_, i) => i !== ruleIdx),
    };
    updateRulePack(files);
  };

  const addRuleToFile = (fileIdx: number, rule: RuleDef) => {
    const files = [...policy.rule_pack.files];
    const taken = new Set(files.flatMap((f) => f.rules.map((r) => r.id)));
    let id = rule.id;
    let i = 2;
    while (taken.has(id)) {
      id = `${rule.id}-${i}`;
      i += 1;
    }
    files[fileIdx] = {
      ...files[fileIdx],
      rules: [...files[fileIdx].rules, { ...rule, id }],
    };
    updateRulePack(files);
  };

  const addBlankRule = (fileIdx: number) => {
    addRuleToFile(fileIdx, {
      id: 'NEW-RULE',
      enabled: true,
      pattern: '',
      title: 'New rule',
      severity: 'MEDIUM',
      confidence: 0.8,
      tags: [],
    });
  };

  const addRulesFile = () => {
    const filename = window.prompt(
      'Filename (without .yaml). E.g. "secrets", "injection", "phi".',
    );
    if (!filename) return;
    if (policy.rule_pack.files.some((f) => f.filename === filename)) {
      window.alert(`File ${filename}.yaml already exists.`);
      return;
    }
    updateRulePack([
      ...policy.rule_pack.files,
      { filename, category: filename, rules: [] },
    ]);
  };

  const removeRulesFile = (fileIdx: number) => {
    if (!window.confirm(`Delete ${policy.rule_pack.files[fileIdx].filename}.yaml and all its rules?`)) return;
    updateRulePack(policy.rule_pack.files.filter((_, i) => i !== fileIdx));
  };

  const ruleKey = (file: RulesFile, rule: RuleDef) => `${file.filename}::${rule.id}`;

  const setExamplesFor = (key: string, patch: Partial<{ match: string[]; no: string[] }>) => {
    setExamples((prev) => ({
      ...prev,
      [key]: { match: prev[key]?.match ?? [], no: prev[key]?.no ?? [], ...patch },
    }));
  };

  return (
    <div className="space-y-4">
      <div className="rounded-md border border-fd-border bg-fd-background p-3">
        <div className="mb-2 flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wide text-fd-muted-foreground">
            Pull from recipe catalog
          </span>
          <span className="text-[11px] text-fd-muted-foreground">
            Pre-cooked rules from the bundled strict pack.
          </span>
        </div>
        <RecipePicker
          kinds={RULE_RECIPE_KINDS}
          maxHeight={180}
          onPick={(r) => {
            // Drop the rule into the file whose name matches its kind suffix
            // (rule:secrets → secrets.yaml). Create the file if missing.
            const targetFilename = r.kind.split(':')[1] ?? 'misc';
            const fileIdx = policy.rule_pack.files.findIndex((f) => f.filename === targetFilename);
            if (fileIdx >= 0) {
              addRuleToFile(fileIdx, r.body as unknown as RuleDef);
            } else {
              const next = [
                ...policy.rule_pack.files,
                {
                  filename: targetFilename,
                  category: targetFilename,
                  rules: [r.body as unknown as RuleDef],
                },
              ];
              updateRulePack(next);
            }
          }}
        />
      </div>

      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-semibold uppercase tracking-wide text-fd-muted-foreground">
          Rule files in this pack
        </span>
        <button
          type="button"
          onClick={addRulesFile}
          className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-foreground hover:border-[var(--brand-cisco)]"
        >
          + Add file
        </button>
      </div>

      {policy.rule_pack.files.length === 0 ? (
        <p className="rounded-md border border-dashed border-fd-border bg-fd-background px-3 py-3 text-center text-[11px] text-fd-muted-foreground">
          No rule files yet. Pick a recipe above or add a blank file to get started.
        </p>
      ) : (
        <div className="space-y-3">
          {policy.rule_pack.files.map((file, fileIdx) => (
            <div key={file.filename} className="rounded-md border border-fd-border bg-fd-card/50">
              <div className="flex items-center gap-2 border-b border-fd-border px-3 py-2">
                <span className="font-mono text-xs text-fd-foreground">{file.filename}.yaml</span>
                <span className="text-[10px] text-fd-muted-foreground">
                  category: {file.category} · {file.rules.length} rule
                  {file.rules.length === 1 ? '' : 's'}
                </span>
                <button
                  type="button"
                  onClick={() => addBlankRule(fileIdx)}
                  className="ml-auto rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-foreground hover:border-[var(--brand-cisco)]"
                >
                  + Rule
                </button>
                <button
                  type="button"
                  onClick={() => removeRulesFile(fileIdx)}
                  aria-label={`Delete ${file.filename}`}
                  className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-muted-foreground hover:border-red-500 hover:text-red-500"
                >
                  Delete file
                </button>
              </div>
              <ul className="divide-y divide-fd-border">
                {file.rules.length === 0 ? (
                  <li className="px-3 py-2 text-[11px] text-fd-muted-foreground">
                    No rules in this file yet.
                  </li>
                ) : (
                  file.rules.map((rule, ruleIdx) => {
                    const key = ruleKey(file, rule);
                    const ex = examples[key] ?? { match: [], no: [] };
                    return (
                      <li key={`${rule.id}-${ruleIdx}`} className="space-y-3 px-3 py-3">
                        <div className="flex flex-wrap items-center gap-3">
                          <Toggle
                            label="enabled"
                            checked={rule.enabled !== false}
                            onChange={(v) => updateRule(fileIdx, ruleIdx, { enabled: v })}
                          />
                          <span className="text-[11px] text-fd-muted-foreground">id</span>
                          <input
                            value={rule.id}
                            onChange={(e) =>
                              updateRule(fileIdx, ruleIdx, { id: e.target.value })
                            }
                            className="w-44 rounded-md border border-fd-border bg-fd-background px-2 py-1 font-mono text-[11px] text-fd-foreground focus:border-[var(--brand-cisco)] focus:outline-none"
                          />
                          <SegmentedControl
                            name={`${rule.id}-sev`}
                            size="sm"
                            value={rule.severity}
                            options={[...SEVERITIES_UPPER].map((s) => ({ value: s, label: s }))}
                            onChange={(v: SeverityUpper) =>
                              updateRule(fileIdx, ruleIdx, { severity: v })
                            }
                          />
                          <button
                            type="button"
                            onClick={() => removeRule(fileIdx, ruleIdx)}
                            aria-label="Remove rule"
                            className="ml-auto rounded-md border border-fd-border bg-fd-background px-2 py-1 text-[11px] text-fd-muted-foreground hover:border-red-500 hover:text-red-500"
                          >
                            ×
                          </button>
                        </div>
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                          <TextField
                            label="title"
                            value={rule.title}
                            onChange={(v) => updateRule(fileIdx, ruleIdx, { title: v })}
                          />
                          <TextField
                            label="confidence (0..1)"
                            value={String(rule.confidence)}
                            inputMode="numeric"
                            onChange={(v) => {
                              const n = Number(v);
                              if (Number.isFinite(n)) {
                                updateRule(fileIdx, ruleIdx, {
                                  confidence: Math.min(1, Math.max(0, n)),
                                });
                              }
                            }}
                          />
                          <ChipsField
                            label="tags"
                            values={rule.tags}
                            onChange={(next) => updateRule(fileIdx, ruleIdx, { tags: next })}
                            placeholder="exfiltration"
                          />
                        </div>
                        <RegexInput
                          label="pattern"
                          pattern={rule.pattern}
                          onChange={(v) => updateRule(fileIdx, ruleIdx, { pattern: v })}
                          examples={ex.match}
                          counterexamples={ex.no}
                          onExamplesChange={(next) => setExamplesFor(key, { match: next })}
                          onCounterexamplesChange={(next) => setExamplesFor(key, { no: next })}
                          hint="Engine compiles with Go's regexp (RE2). Lookarounds and backrefs are not supported."
                        />
                      </li>
                    );
                  })
                )}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
