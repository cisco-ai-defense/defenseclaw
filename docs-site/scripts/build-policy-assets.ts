// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0
//
// Build-time asset pipeline for the docs-site policy creator.
//
// Reads the canonical bundled policies under ../policies/ and emits:
//
//   docs-site/data/policy-presets.json    — the three shipped presets
//                                           (default, strict, permissive)
//                                           projected into the wizard's
//                                           Policy schema.
//   docs-site/data/policy-recipes.json    — operator-facing catalog of
//                                           regex / suppression / judge
//                                           recipes seeded from the
//                                           bundled strict pack.
//   docs-site/data/policy-scenarios.json  — canned OPA inputs for each
//                                           Rego domain so the Live Test
//                                           pane has something to render
//                                           the moment it loads.
//   docs-site/public/opa/<domain>.wasm    — compiled WASM modules for
//                                           every Rego domain reachable
//                                           via opa-wasm in the browser.
//
// Run via:
//   npm run build:policy-assets
//
// Wired into postinstall so a fresh `npm install` is enough to populate
// everything; CI also runs it explicitly to fail fast on schema drift.
//
// If the `opa` binary is not on PATH the WASM step is skipped with a
// warning — the rest of the docs site still builds (the Live Test pane
// degrades gracefully via lib/opa-eval.ts).

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import yaml from 'js-yaml';
import * as tar from 'tar';

const HERE = dirname(fileURLToPath(import.meta.url));
const DOCS_SITE = resolve(HERE, '..');
const REPO_ROOT = resolve(DOCS_SITE, '..');
const POLICIES = resolve(REPO_ROOT, 'policies');
const DATA_OUT = resolve(DOCS_SITE, 'data');
const WASM_OUT = resolve(DOCS_SITE, 'public', 'opa');

// Canonical preset names. Order matters: `default` is the wizard's
// starting selection.
const PRESETS = ['default', 'strict', 'permissive'] as const;
type PresetName = (typeof PRESETS)[number];

// Each Rego domain we surface in the Live Test pane. The entrypoint
// path mirrors the package + rule name in the .rego file. The
// `opa build` command requires every entrypoint we want to evaluate
// from the browser — anything not listed here would return undefined.
const REGO_DOMAINS: Array<{
  name: string;
  source: string;
  entrypoints: string[];
}> = [
  {
    name: 'admission',
    source: 'admission.rego',
    entrypoints: ['defenseclaw/admission/verdict', 'defenseclaw/admission/reason'],
  },
  {
    name: 'guardrail',
    source: 'guardrail.rego',
    entrypoints: [
      'defenseclaw/guardrail/severity',
      'defenseclaw/guardrail/reason',
      'defenseclaw/guardrail/action',
    ],
  },
  {
    name: 'firewall',
    source: 'firewall.rego',
    entrypoints: ['defenseclaw/firewall/action', 'defenseclaw/firewall/rule_name'],
  },
  {
    name: 'audit',
    source: 'audit.rego',
    entrypoints: ['defenseclaw/audit/retain', 'defenseclaw/audit/retain_reason'],
  },
  {
    name: 'skill_actions',
    source: 'skill_actions.rego',
    entrypoints: [
      'defenseclaw/skill_actions/runtime_action',
      'defenseclaw/skill_actions/file_action',
      'defenseclaw/skill_actions/install_action',
    ],
  },
];

interface PresetBundle {
  name: PresetName;
  description: string;
  policy: Record<string, unknown>;
  guardrail: {
    rules: Record<string, unknown>;
    judge: Record<string, unknown>;
    suppressions: Record<string, unknown> | null;
    sensitiveTools: Record<string, unknown> | null;
    // Session-correlator patterns. The defaults file lives outside
    // policies/guardrail/<pack>/ (it's a single source-of-truth under
    // internal/guardrail/defaults/correlation-patterns.yaml), but we
    // attach it per-preset so the wizard's presets-bundle plumbing
    // can stay symmetric.
    correlator: Record<string, unknown> | null;
  };
  scanners: Record<string, Record<string, Record<string, unknown>>>;
}

// Path to the upstream correlation-patterns.yaml. The file is a single
// source of truth shared across packs today; we lift it once and copy
// it onto every preset bundle. If a future per-pack override drops in
// at policies/guardrail/<pack>/correlation-patterns.yaml we prefer it.
const CORRELATION_PATTERNS_DEFAULT = resolve(
  REPO_ROOT,
  'internal',
  'guardrail',
  'defaults',
  'correlation-patterns.yaml',
);

function readYaml(path: string): Record<string, unknown> | null {
  if (!existsSync(path)) return null;
  const raw = readFileSync(path, 'utf-8');
  const parsed = yaml.load(raw) as Record<string, unknown> | null;
  return parsed ?? null;
}

function readDirSafely(path: string): string[] {
  if (!existsSync(path) || !statSync(path).isDirectory()) return [];
  return readdirSync(path);
}

function loadPreset(name: PresetName): PresetBundle | null {
  const policyPath = join(POLICIES, `${name}.yaml`);
  const policy = readYaml(policyPath);
  if (!policy) {
    console.warn(`[policy-assets] missing preset ${name}.yaml — skipping`);
    return null;
  }

  const packDir = join(POLICIES, 'guardrail', name);
  const rulesDir = join(packDir, 'rules');
  const judgeDir = join(packDir, 'judge');

  const rules: Record<string, unknown> = {};
  for (const entry of readDirSafely(rulesDir)) {
    if (!entry.endsWith('.yaml')) continue;
    const data = readYaml(join(rulesDir, entry));
    if (data) rules[entry.replace(/\.yaml$/, '')] = data;
  }

  const judge: Record<string, unknown> = {};
  for (const entry of readDirSafely(judgeDir)) {
    if (!entry.endsWith('.yaml')) continue;
    const data = readYaml(join(judgeDir, entry));
    if (data) judge[entry.replace(/\.yaml$/, '')] = data;
  }

  const suppressions = readYaml(join(packDir, 'suppressions.yaml'));
  const sensitiveTools = readYaml(join(packDir, 'sensitive-tools.yaml'));

  // Layer 5 patterns. Prefer per-pack override if it exists, otherwise
  // fall back to the upstream defaults file. Either way the wizard
  // ends up with the same shape on .guardrail.correlator.
  const correlator =
    readYaml(join(packDir, 'correlation-patterns.yaml')) ??
    readYaml(CORRELATION_PATTERNS_DEFAULT);

  // Per-scanner profiles. Each scanner has its own subdirectory under
  // policies/scanners/<scanner>/<profile>.yaml. We surface them all so
  // the wizard can let the operator pick a profile (or write inline
  // overrides) per scanner.
  const scanners: Record<string, Record<string, Record<string, unknown>>> = {};
  const scannersRoot = join(POLICIES, 'scanners');
  for (const scanner of readDirSafely(scannersRoot)) {
    const scannerDir = join(scannersRoot, scanner);
    if (!statSync(scannerDir).isDirectory()) continue;
    scanners[scanner] = {};
    for (const profile of readDirSafely(scannerDir)) {
      if (!profile.endsWith('.yaml')) continue;
      const data = readYaml(join(scannerDir, profile));
      if (data) scanners[scanner][profile.replace(/\.yaml$/, '')] = data;
    }
  }

  return {
    name,
    description: String((policy as Record<string, unknown>).description ?? name),
    policy,
    guardrail: { rules, judge, suppressions, sensitiveTools, correlator },
    scanners,
  };
}

interface Recipe {
  id: string;
  title: string;
  kind:
    | 'rule:secrets'
    | 'rule:injection'
    | 'rule:exfiltration'
    | 'rule:command'
    | 'rule:path'
    | 'rule:enterprise-data'
    | 'rule:trust-exploit'
    | 'rule:cognitive'
    | 'rule:c2'
    | 'pre_judge_strip'
    | 'finding_suppression'
    | 'tool_suppression';
  body: Record<string, unknown>;
  why: string;
  examples: string[];
  counterexamples: string[];
  source: string;
  tags: string[];
  data_axis?: Array<'ingress_untrusted' | 'sensitive_access' | 'egress_external'>;
  tool_capability_class?: Array<
    'read_fs' | 'write_fs' | 'exec_shell' | 'network_fetch' | 'send_message'
  >;
}

// Rule-axes mapping is sourced from the Go authority at
// internal/guardrail/axes.go via the committed snapshot
// docs-site/data/rule-axes.json. The Go test
// TestRuleAxesSnapshotMatchesCommittedJSON re-emits this file from
// the live axes.go data and fails CI if the committed copy is
// stale — that's our single-source-of-truth guarantee. Re-run it
// with UPDATE_RULE_AXES_JSON=1 after editing axes.go.
type RuleAxesSnapshot = {
  exact_rule_axes: Array<{ id: string; axes: string[] | null }>;
  prefix_axes: Array<{ prefixes: string[]; axes: string[] | null }>;
  prefix_capabilities: Array<{ prefixes: string[]; capability: string }>;
};

let _axesSnapshot: RuleAxesSnapshot | null = null;
function ruleAxesSnapshot(): RuleAxesSnapshot {
  if (_axesSnapshot !== null) return _axesSnapshot;
  const p = join(process.cwd(), 'data', 'rule-axes.json');
  const raw = JSON.parse(readFileSync(p, 'utf8')) as RuleAxesSnapshot;
  if (!raw || !Array.isArray(raw.exact_rule_axes) || !Array.isArray(raw.prefix_axes)) {
    throw new Error(
      `rule-axes.json at ${p} is malformed. Re-run \`UPDATE_RULE_AXES_JSON=1 go test ./internal/guardrail -run TestRuleAxesSnapshotMatchesCommittedJSON\` to regenerate.`,
    );
  }
  _axesSnapshot = raw;
  return _axesSnapshot;
}

function axesForRuleId(id: string): Recipe['data_axis'] {
  const snap = ruleAxesSnapshot();
  for (const e of snap.exact_rule_axes) {
    if (e.id === id) return (e.axes ?? undefined) as Recipe['data_axis'];
  }
  for (const rule of snap.prefix_axes) {
    if (rule.prefixes.some((p) => id.startsWith(p))) {
      return (rule.axes ?? undefined) as Recipe['data_axis'];
    }
  }
  return undefined;
}

function capabilityForRuleId(id: string): Recipe['tool_capability_class'] {
  const snap = ruleAxesSnapshot();
  for (const rule of snap.prefix_capabilities) {
    if (rule.prefixes.some((p) => id.startsWith(p))) {
      return [rule.capability] as Recipe['tool_capability_class'];
    }
  }
  return undefined;
}

function buildRecipes(strict: PresetBundle): Recipe[] {
  const recipes: Recipe[] = [];

  // Rule recipes: lifted verbatim from policies/guardrail/strict/rules/*.yaml.
  // Each rule entry already has the right shape — we just attach a why /
  // examples block from a small in-script lookup table so the recipe
  // picker can pre-fill the live regex tester. The lookup table is
  // intentionally short: most rules don't need bespoke examples because
  // the `pattern` is self-describing. When a rule is missing from the
  // lookup the recipe still ships, just without seed samples.
  const RULE_HINTS: Record<string, { examples: string[]; counterexamples: string[]; why?: string }> = {
    'SEC-AWS-KEY': {
      examples: ['AKIAIOSFODNN7EXAMPLE', 'ASIA1234567890ABCDEFGHIJ'],
      counterexamples: ['BANANAFRUITNOTAKEY', 'AKI', 'AKIAtoolow'],
    },
    'SEC-OPENAI-V2': {
      examples: ['sk-' + 'a'.repeat(48)],
      counterexamples: ['sk-tooshort', 'pk-livenotopenai'],
    },
    'SEC-GITHUB-TOKEN': {
      examples: ['ghp_' + 'a'.repeat(36), 'ghs_' + 'b'.repeat(40)],
      counterexamples: ['ghp_short', 'gh_notatoken'],
    },
    'SEC-PRIVKEY': {
      examples: ['-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN OPENSSH PRIVATE KEY-----'],
      counterexamples: ['-----BEGIN CERTIFICATE-----', 'BEGIN PRIVATE KEY without dashes'],
    },
    'SEC-JWT': {
      examples: ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature_here_xyz'],
      counterexamples: ['eyJonly', 'not.a.jwt'],
    },
    'SEC-SLACK-WEBHOOK': {
      examples: ['https://hooks.slack.com/services/T0000/B0000/abcdefg12345'],
      counterexamples: ['https://hooks.slack.com/wrongpath', 'https://example.com'],
    },
  };

  for (const [filename, file] of Object.entries(strict.guardrail.rules)) {
    const rules = (file as { rules?: Array<Record<string, unknown>>; category?: string }).rules ?? [];
    const category = (file as { category?: string }).category ?? filename;
    const kindStr = `rule:${filename === 'local-patterns' ? 'injection' : category}`;
    for (const rule of rules) {
      const id = String(rule.id ?? '');
      if (!id) continue;
      const hints = RULE_HINTS[id] ?? { examples: [], counterexamples: [] };
      recipes.push({
        id: `RECIPE-${id}`,
        title: String(rule.title ?? id),
        kind: kindStr as Recipe['kind'],
        body: rule,
        why:
          hints.why ??
          `Pattern shipped in the bundled strict rule pack (${filename}.yaml). Severity ${rule.severity ?? 'unset'}.`,
        examples: hints.examples,
        counterexamples: hints.counterexamples,
        source: `policies/guardrail/strict/rules/${filename}.yaml`,
        tags: Array.isArray(rule.tags) ? (rule.tags as string[]) : [],
        data_axis: axesForRuleId(id),
        tool_capability_class: capabilityForRuleId(id),
      });
    }
  }

  // Suppression recipes: walk the strict pack's suppressions.yaml.
  // pre_judge_strips and finding_suppressions are the two layers
  // operators most often want to copy into their own packs (the third,
  // tool_suppressions, is empty in the bundled strict pack but the
  // recipe picker still needs an entry to seed manual authoring).
  const supp = (strict.guardrail.suppressions ?? {}) as Record<string, unknown>;
  const preStrips = (supp.pre_judge_strips ?? []) as Array<Record<string, unknown>>;
  for (const s of preStrips) {
    const id = String(s.id ?? '');
    if (!id) continue;
    recipes.push({
      id: `RECIPE-${id}`,
      title: String(s.context ?? id),
      kind: 'pre_judge_strip',
      body: s,
      why: `Pre-judge strip shipped in the bundled strict pack. Applies to ${(s.applies_to as string[] | undefined)?.join(', ') ?? 'all judges'}.`,
      examples: [],
      counterexamples: [],
      source: 'policies/guardrail/strict/suppressions.yaml',
      tags: ['pre-judge', ...((s.applies_to as string[] | undefined) ?? [])],
    });
  }
  const findingSupps = (supp.finding_suppressions ?? []) as Array<Record<string, unknown>>;
  for (const s of findingSupps) {
    const id = String(s.id ?? '');
    if (!id) continue;
    recipes.push({
      id: `RECIPE-${id}`,
      title: String(s.reason ?? id),
      kind: 'finding_suppression',
      body: s,
      why: `Finding suppression shipped in the bundled strict pack.`,
      examples: [],
      counterexamples: [],
      source: 'policies/guardrail/strict/suppressions.yaml',
      tags: ['finding'],
    });
  }
  // Tool suppression placeholder so the picker has a "starter" the
  // operator can clone. We do NOT lift any from the strict pack
  // (it ships with [] today) — instead we emit a single illustrative
  // example matching the docstring in policies.mdx.
  recipes.push({
    id: 'RECIPE-SUPP-TOOL-COSMETIC-SHELL',
    title: 'Suppress cosmetic shell commands (git status / log / diff)',
    kind: 'tool_suppression',
    body: {
      tool_pattern: '^(shell|bash|sh)\\.execute$',
      suppress_findings: ['JUDGE-INJ-DESTRUCTIVE'],
      reason: 'Cosmetic shell commands (git status, ls, pwd) generate noise without security risk',
    },
    why:
      'Tool suppressions let you silence findings on tools whose name matches a regex. Use this to drop noisy verdicts on read-only commands while keeping write/destructive commands surfaced.',
    examples: ['shell.execute', 'bash.execute'],
    counterexamples: ['shell.write', 'fs.unlink'],
    source: 'docs-site/scripts/build-policy-assets.ts (illustrative)',
    tags: ['tool', 'shell', 'noise-reduction'],
    tool_capability_class: ['exec_shell'],
  });

  return recipes;
}

interface Scenario {
  id: string;
  title: string;
  domain: string;
  input: Record<string, unknown>;
  description: string;
  expectedVerdict: string;
}

function buildScenarios(): Scenario[] {
  // A small library of canned OPA inputs covering the high-traffic
  // verdict paths. The operator picks one in the Live Test pane and
  // sees how their in-progress policy responds. Each scenario carries
  // an `expectedVerdict` so the wizard can flag policies that diverge
  // from intent.
  return [
    {
      id: 'admission-critical-skill',
      title: 'CRITICAL skill scan',
      domain: 'admission',
      description: 'A skill scanner found a CRITICAL finding. Default policy: reject install.',
      expectedVerdict: 'rejected',
      input: {
        target_type: 'skill',
        target_name: 'malicious-helper',
        path: '/Users/op/.openclaw/skills/malicious-helper',
        block_list: [],
        allow_list: [],
        scan_result: {
          max_severity: 'CRITICAL',
          total_findings: 3,
          scanner_name: 'skill-scanner',
          findings: [{ severity: 'CRITICAL', scanner: 'skill-scanner', title: 'Hardcoded credentials' }],
        },
      },
    },
    {
      id: 'admission-medium-mcp',
      title: 'MEDIUM MCP scan',
      domain: 'admission',
      description: 'An MCP server scan found a MEDIUM finding. Default policy clears it; strict rejects.',
      expectedVerdict: 'rejected',
      input: {
        target_type: 'mcp',
        target_name: 'context-server',
        path: '/Users/op/.config/mcp/context-server',
        block_list: [],
        allow_list: [],
        scan_result: {
          max_severity: 'MEDIUM',
          total_findings: 1,
          scanner_name: 'mcp-scanner',
          findings: [{ severity: 'MEDIUM', scanner: 'mcp-scanner', title: 'Untrusted upstream' }],
        },
      },
    },
    {
      id: 'admission-allow-listed',
      title: 'Allow-listed plugin',
      domain: 'admission',
      description: 'Plugin appears on the explicit allow list. Verdict: allowed regardless of scan.',
      expectedVerdict: 'allowed',
      input: {
        target_type: 'plugin',
        target_name: 'defenseclaw',
        path: '/Users/op/.defenseclaw/plugins/defenseclaw',
        block_list: [],
        allow_list: [
          { target_type: 'plugin', target_name: 'defenseclaw', reason: 'first-party DefenseClaw plugin' },
        ],
      },
    },
    {
      id: 'admission-blocked',
      title: 'Block-listed skill',
      domain: 'admission',
      description: 'Skill appears on the block list. Verdict: blocked regardless of allow list.',
      expectedVerdict: 'blocked',
      input: {
        target_type: 'skill',
        target_name: 'banned-skill',
        path: '/Users/op/.openclaw/skills/banned-skill',
        block_list: [
          { target_type: 'skill', target_name: 'banned-skill', reason: 'previously compromised' },
        ],
        allow_list: [],
      },
    },
    {
      id: 'guardrail-critical-prompt',
      title: 'CRITICAL local guardrail finding (prompt)',
      domain: 'guardrail',
      description: 'Local scanner flagged the prompt with CRITICAL severity. Default action: block.',
      expectedVerdict: 'block',
      input: {
        direction: 'prompt',
        model: 'gpt-4o-mini',
        mode: 'action',
        scanner_mode: 'local',
        local_result: {
          action: 'block',
          severity: 'CRITICAL',
          findings: ['Hardcoded AWS key in prompt'],
          reason: 'SEC-AWS-KEY pattern match',
        },
        cisco_result: null,
        content_length: 1024,
      },
    },
    {
      id: 'guardrail-medium-completion',
      title: 'MEDIUM guardrail finding (completion)',
      domain: 'guardrail',
      description: 'MEDIUM finding on completion. Default policy: alert. Strict: block.',
      expectedVerdict: 'alert',
      input: {
        direction: 'completion',
        model: 'gpt-4o-mini',
        mode: 'action',
        scanner_mode: 'local',
        local_result: {
          action: 'alert',
          severity: 'MEDIUM',
          findings: ['Possible IP address leakage'],
          reason: 'JUDGE-PII-IP match',
        },
        cisco_result: null,
        content_length: 256,
      },
    },
    {
      id: 'firewall-allowed-domain',
      title: 'Allowed-domain HTTPS fetch',
      domain: 'firewall',
      description: 'Outbound to api.github.com:443. Allowed by default policy.',
      expectedVerdict: 'allow',
      input: {
        target_type: 'plugin',
        destination: 'api.github.com',
        port: 443,
        protocol: 'tcp',
      },
    },
    {
      id: 'firewall-imds',
      title: 'AWS IMDS fetch attempt',
      domain: 'firewall',
      description: 'Outbound to 169.254.169.254. Blocked by default and strict policies.',
      expectedVerdict: 'deny',
      input: {
        target_type: 'plugin',
        destination: '169.254.169.254',
        port: 80,
        protocol: 'tcp',
      },
    },
    {
      id: 'audit-recent-info',
      title: 'Recent INFO event',
      domain: 'audit',
      description: '5-day-old INFO event. Retained by default (within retention).',
      expectedVerdict: 'true',
      input: {
        event_type: 'scan',
        severity: 'INFO',
        age_days: 5,
        export_targets: [],
      },
    },
    {
      id: 'audit-old-critical',
      title: 'Old CRITICAL event',
      domain: 'audit',
      description: '500-day-old CRITICAL. Retained indefinitely under default policy.',
      expectedVerdict: 'true',
      input: {
        event_type: 'block',
        severity: 'CRITICAL',
        age_days: 500,
        export_targets: ['splunk'],
      },
    },
    {
      id: 'skill-actions-high',
      title: 'HIGH severity skill verdict',
      domain: 'skill_actions',
      description: 'Skill flagged HIGH. Default policy: runtime=disable, file=quarantine, install=block.',
      expectedVerdict: 'block',
      input: {
        severity: 'HIGH',
        target_type: 'skill',
      },
    },
    // ----- Layer 5: session correlator promotions ---------------------------
    // The correlator itself runs in Go (not Rego). These scenarios show
    // what the gateway emits *after* a correlator pattern fires: a
    // synthetic guardrail finding carrying the pattern's severity_on_match.
    // Run them through the guardrail domain to verify your policy's
    // response posture promotes correlator-CRITICAL all the way to block.
    {
      id: 'correlator-lethal-trifecta',
      title: 'Lethal trifecta promotion (Willison)',
      domain: 'guardrail',
      description:
        'Session combined ingress_untrusted + sensitive_access + egress_external findings. The correlator emits a CRITICAL synthetic finding. Default and strict: block.',
      expectedVerdict: 'block',
      input: {
        direction: 'completion',
        model: 'gpt-4o-mini',
        mode: 'action',
        scanner_mode: 'local',
        local_result: {
          action: 'block',
          severity: 'CRITICAL',
          findings: ['Session matched LETHAL-TRIFECTA correlator pattern'],
          reason: 'CORR-LETHAL-TRIFECTA: ingress_untrusted + sensitive_access + egress_external in last 5 events',
          signal_strength: 'high',
          correlator_pattern_id: 'LETHAL-TRIFECTA',
        },
        cisco_result: null,
        content_length: 0,
      },
    },
    {
      id: 'correlator-escalation-chain',
      title: 'Escalation chain promotion',
      domain: 'guardrail',
      description:
        'Session ran MEDIUM → HIGH → HIGH severity findings in order. The correlator emits a CRITICAL on chain completion.',
      expectedVerdict: 'block',
      input: {
        direction: 'prompt',
        model: 'gpt-4o-mini',
        mode: 'action',
        scanner_mode: 'local',
        local_result: {
          action: 'block',
          severity: 'CRITICAL',
          findings: ['Session matched ESCALATION-CHAIN correlator pattern'],
          reason: 'CORR-ESCALATION-CHAIN: MEDIUM→HIGH→HIGH sequence in 6 events',
          signal_strength: 'high',
          correlator_pattern_id: 'ESCALATION-CHAIN',
        },
        cisco_result: null,
        content_length: 0,
      },
    },
    {
      id: 'correlator-destructive-flow',
      title: 'Destructive shell after sensitive read',
      domain: 'guardrail',
      description:
        'rm -rf invoked in the same session as a prior ~/.ssh read. Correlator emits CRITICAL.',
      expectedVerdict: 'block',
      input: {
        direction: 'tool_call',
        model: 'gpt-4o-mini',
        mode: 'action',
        scanner_mode: 'local',
        local_result: {
          action: 'block',
          severity: 'CRITICAL',
          findings: ['Session matched DESTRUCTIVE-FLOW correlator pattern'],
          reason: 'CORR-DESTRUCTIVE-FLOW: exec_shell capability after sensitive_access finding',
          signal_strength: 'high',
          correlator_pattern_id: 'DESTRUCTIVE-FLOW',
        },
        cisco_result: null,
        content_length: 0,
      },
    },
  ];
}

interface BuildResult {
  presets: Array<{ name: string; description: string; bundle: PresetBundle }>;
  recipes: Recipe[];
  scenarios: Scenario[];
}

function buildAll(): BuildResult {
  const presets: BuildResult['presets'] = [];
  for (const name of PRESETS) {
    const bundle = loadPreset(name);
    if (!bundle) continue;
    presets.push({ name, description: bundle.description, bundle });
  }

  const strict = presets.find((p) => p.name === 'strict')?.bundle;
  if (!strict) {
    throw new Error('strict preset is required to seed the recipe catalog');
  }
  const recipes = buildRecipes(strict);
  const scenarios = buildScenarios();

  return { presets, recipes, scenarios };
}

function ensureDir(path: string) {
  mkdirSync(path, { recursive: true });
}

function writeJson(path: string, value: unknown) {
  ensureDir(dirname(path));
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n', 'utf-8');
}

function compileWasm(opts: { skipMissingOpa: boolean }): { compiled: string[]; skipped: string[] } {
  const compiled: string[] = [];
  const skipped: string[] = [];

  // Locate `opa` on PATH. We resolve via `which` instead of a hard-
  // coded path so the script works on Linux CI runners and macOS dev
  // boxes alike.
  let opaPath = '';
  try {
    opaPath = execFileSync('which', ['opa'], { encoding: 'utf-8' }).trim();
  } catch {
    /* missing — fall through */
  }
  if (!opaPath) {
    if (opts.skipMissingOpa) {
      console.warn('[policy-assets] `opa` not on PATH — skipping WASM compilation.');
      console.warn('[policy-assets] Install OPA (https://www.openpolicyagent.org/docs/#running-opa) to enable Live Test in the docs.');
      for (const d of REGO_DOMAINS) skipped.push(d.name);
      return { compiled, skipped };
    }
    throw new Error('`opa` binary not found on PATH');
  }

  ensureDir(WASM_OUT);

  const tmpRoot = join(tmpdir(), `dc-policy-assets-${process.pid}`);
  ensureDir(tmpRoot);

  for (const domain of REGO_DOMAINS) {
    const sourcePath = join(POLICIES, 'rego', domain.source);
    if (!existsSync(sourcePath)) {
      console.warn(`[policy-assets] missing ${sourcePath} — skipping ${domain.name}`);
      skipped.push(domain.name);
      continue;
    }

    const bundlePath = join(tmpRoot, `${domain.name}.tar.gz`);
    const args = ['build', '-t', 'wasm'];
    for (const e of domain.entrypoints) {
      args.push('-e', e);
    }
    args.push('-o', bundlePath, sourcePath);

    try {
      execFileSync(opaPath, args, { stdio: 'pipe' });
    } catch (err) {
      const stderr = (err as { stderr?: Buffer }).stderr?.toString('utf-8') ?? String(err);
      console.error(`[policy-assets] opa build failed for ${domain.name}:\n${stderr}`);
      skipped.push(domain.name);
      continue;
    }

    // The bundle is a tarball: { /policy.wasm, /data.json, /.manifest, /<source>.rego }.
    // We only need policy.wasm — extract it to public/opa/<domain>.wasm.
    const extractDir = join(tmpRoot, domain.name);
    ensureDir(extractDir);
    tar.extract({ file: bundlePath, cwd: extractDir, sync: true });
    const wasmPath = join(extractDir, 'policy.wasm');
    if (!existsSync(wasmPath)) {
      console.error(`[policy-assets] policy.wasm not found in bundle for ${domain.name}`);
      skipped.push(domain.name);
      continue;
    }
    const dest = join(WASM_OUT, `${domain.name}.wasm`);
    writeFileSync(dest, readFileSync(wasmPath));
    compiled.push(domain.name);
  }

  // Always also write a manifest the runtime can read so the loader
  // knows which entrypoint indexes correspond to which rule names.
  // OPA's WASM ABI uses numeric entrypoint IDs that are assigned in
  // the order passed to `opa build -e`. Recording them here keeps
  // opa-eval.ts honest.
  // Note: intentionally no `generated_at` field. The manifest used to
  // include a build timestamp, which churned the diff on every rebuild
  // and made schema drift hard to spot in code review. The runtime
  // never reads it.
  const manifest = {
    domains: REGO_DOMAINS.filter((d) => compiled.includes(d.name)).map((d) => ({
      name: d.name,
      wasm: `/opa/${d.name}.wasm`,
      entrypoints: d.entrypoints,
    })),
    skipped,
  };
  writeJson(join(WASM_OUT, 'manifest.json'), manifest);

  rmSync(tmpRoot, { recursive: true, force: true });

  return { compiled, skipped };
}

function main() {
  const args = process.argv.slice(2);
  const skipMissingOpa = !args.includes('--require-opa');

  ensureDir(DATA_OUT);

  console.log('[policy-assets] building presets, recipes, scenarios…');
  const { presets, recipes, scenarios } = buildAll();
  // Note: no `generated_at` timestamps in any of these JSON files.
  // Dropping the timestamps means a clean PR diff only shows real
  // schema/content changes, which is the whole point of bundling
  // these files instead of regenerating at request time.
  writeJson(join(DATA_OUT, 'policy-presets.json'), { presets });
  writeJson(join(DATA_OUT, 'policy-recipes.json'), { recipes });
  writeJson(join(DATA_OUT, 'policy-scenarios.json'), { scenarios });
  console.log(`[policy-assets]   presets=${presets.length}  recipes=${recipes.length}  scenarios=${scenarios.length}`);

  console.log('[policy-assets] compiling Rego → WASM…');
  const { compiled, skipped } = compileWasm({ skipMissingOpa });
  console.log(`[policy-assets]   compiled=${compiled.length} skipped=${skipped.length}`);

  if (skipped.length > 0 && !skipMissingOpa) {
    process.exit(1);
  }
}

main();
