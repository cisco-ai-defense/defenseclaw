// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Pure-function unit tests for the policy-creator client modules.
// Runs under Node's built-in test runner via tsx; no extra deps.
//
//   npm run test:policy-creator
//
// Coverage targets the modules that are easiest to break silently
// and most painful to debug from a screenshot:
//
//   - lib/share.ts          — round-trip + every failure mode of
//                             decodePolicyFromHash, including the
//                             gzip-bomb cap.
//   - lib/rego-highlight.ts — token classification + HTML escaping.
//   - lib/json-highlight.ts — token classification + HTML escaping.
//   - playground/cmdk-filter.ts — token AND-match + scoring order.
//
// Browser-coupled UI (the editors, the LiveTestPane, the share button
// itself) stay covered by the Playwright run that ships with the
// docs-site smoke test.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  decodePolicyFromHash,
  encodePolicyForHash,
  looksLikePolicy,
  normalizeImportedPolicy,
  __TEST_INTERNALS,
} from '../components/policy-creator/lib/share.js';
import { emit, __TEST_INTERNALS as EMIT_INTERNALS } from '../components/policy-creator/lib/emit.js';
import { highlightRegoToHtml, tokenizeRego } from '../components/policy-creator/lib/rego-highlight.js';
import { highlightJsonToHtml, tokenizeJson } from '../components/policy-creator/lib/json-highlight.js';
import { filterIndex } from '../components/policy-creator/playground/cmdk-filter.js';
import { policyFromPreset } from '../components/policy-creator/lib/presets.js';
import { validatePolicy } from '../components/policy-creator/lib/validators.js';
import type { CorrelationPattern, Policy } from '../components/policy-creator/types.js';

// ── fixtures ────────────────────────────────────────────────────────

// Minimal-but-valid Policy that matches the actual schema in types.ts.
// share.looksLikePolicy gates on top-level `name` + `skill_actions`; we
// populate the rest of the chrome with engine-realistic defaults so a
// round-trip survives JSON.stringify/parse without losing keys.
function makePolicy(overrides: Partial<Policy> = {}): Policy {
  const triple = { runtime: 'enable', file: 'none', install: 'none' } as const;
  const strictTriple = { runtime: 'disable', file: 'quarantine', install: 'block' } as const;
  const base: Policy = {
    name: 'test-policy',
    description: 'unit-test fixture',
    basedOn: 'default',
    admission: { scan_on_install: true, allow_list_bypass_scan: false },
    skill_actions: {
      critical: strictTriple,
      high: strictTriple,
      medium: triple,
      low: triple,
      info: triple,
    },
    scanner_overrides: {},
    first_party_allow_list: [],
    guardrail: {
      block_threshold: 3,
      alert_threshold: 2,
      cisco_trust_level: 'advisory',
      hilt: { enabled: false, min_severity: 'HIGH' },
      patterns: {},
      severity_mappings: {},
    },
    rule_pack: { name: 'test-policy', files: [] },
    suppressions: { pre_judge_strips: [], finding_suppressions: [], tool_suppressions: [] },
    sensitive_tools: [],
    judges: [],
    firewall: {
      default_action: 'allow',
      blocked_destinations: [],
      allowed_domains: [],
      allowed_ports: [443, 80],
    },
    webhooks: [],
    watch: { rescan_enabled: false, rescan_interval_min: 60 },
    enforcement: { max_enforcement_delay_seconds: 2 },
    audit: { log_all_actions: true, log_scan_results: true, retention_days: 90 },
    scanners: {},
    custom_rego: [],
    correlator: [],
    cisco_ai_defense: {
      enabled: false,
      endpoint: '',
      api_key_env: '',
      scan_hook_surface: true,
    },
    ...overrides,
  };
  return base;
}

// ── share: round trip ───────────────────────────────────────────────

test('share: encode → decode preserves the policy verbatim', async () => {
  const original = makePolicy();
  const payload = await encodePolicyForHash(original);
  assert.match(payload, /^v1\./, 'payload should be version-prefixed');
  const result = await decodePolicyFromHash(payload);
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.deepEqual(result.policy, original);
  }
});

// ── share: failure modes ────────────────────────────────────────────

test('share: payload without "." returns malformed', async () => {
  const result = await decodePolicyFromHash('not-a-versioned-payload');
  assert.deepEqual(result, { ok: false, reason: 'malformed' });
});

test('share: wrong version prefix returns version', async () => {
  // Build a v2 payload so the body is otherwise legitimate base64.
  const result = await decodePolicyFromHash('v2.aGVsbG8');
  assert.deepEqual(result, { ok: false, reason: 'version' });
});

test('share: oversized payload (>MAX_PAYLOAD_CHARS) returns too-large', async () => {
  const huge = 'a'.repeat(__TEST_INTERNALS.MAX_PAYLOAD_CHARS + 10);
  const result = await decodePolicyFromHash(`v1.${huge}`);
  assert.deepEqual(result, { ok: false, reason: 'too-large' });
});

test('share: gzip bomb (small input → giant output) returns too-large', async () => {
  // Build a tiny payload that decompresses to >MAX_DECOMPRESSED_BYTES.
  // ~10 MB of zeros gzip-compresses to ~10 KB.
  const giant = '\u0000'.repeat(__TEST_INTERNALS.MAX_DECOMPRESSED_BYTES + 5_000);
  const stream = new Blob([giant])
    .stream()
    .pipeThrough(new CompressionStream('gzip'));
  const buf = new Uint8Array(await new Response(stream).arrayBuffer());
  // Hand-roll the same base64url encoding used in share.ts so we can
  // synthesize a payload that bypasses encodePolicyForHash's policy
  // shape requirement.
  let bin = '';
  for (let i = 0; i < buf.length; i += 0x8000) {
    bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  }
  const body = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  // Sanity: keep the synthesized URL well under the input cap so we
  // exercise the *output* cap, not the input cap.
  assert.ok(body.length < __TEST_INTERNALS.MAX_PAYLOAD_CHARS, 'gzip-bomb body exceeded input cap; tweak fixture');
  const result = await decodePolicyFromHash(`v1.${body}`);
  assert.deepEqual(result, { ok: false, reason: 'too-large' });
});

test('share: garbage base64 inside a valid v1 envelope returns malformed', async () => {
  // !@# are not legal base64url characters → atob throws → malformed.
  const result = await decodePolicyFromHash('v1.!@#$%');
  assert.deepEqual(result, { ok: false, reason: 'malformed' });
});

test('share: parses JSON but is not a Policy → invalid-shape', async () => {
  // Encode a non-policy object using the same pipeline, then poke the
  // result back through decode.
  const badJson = JSON.stringify({ hello: 'world', nope: true });
  const stream = new Blob([badJson])
    .stream()
    .pipeThrough(new CompressionStream('gzip'));
  const buf = new Uint8Array(await new Response(stream).arrayBuffer());
  let bin = '';
  for (let i = 0; i < buf.length; i += 0x8000) {
    bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  }
  const body = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const result = await decodePolicyFromHash(`v1.${body}`);
  assert.deepEqual(result, { ok: false, reason: 'invalid-shape' });
});

test('share: looksLikePolicy rejects non-Policy shapes and accepts Policy header', () => {
  const f = __TEST_INTERNALS.looksLikePolicy;
  assert.equal(f(null), false);
  assert.equal(f(undefined), false);
  assert.equal(f([]), false);
  assert.equal(f('string'), false);
  assert.equal(f(42), false);
  assert.equal(f({}), false);
  // Pre-#262 share-link fixtures used `metadata.name` / `severity_matrix` —
  // those keys are NOT on the real Policy and must be rejected so we
  // don't silently load garbage from an out-of-date share link.
  assert.equal(f({ metadata: { name: 'x' }, severity_matrix: {} }), false);
  // Missing skill_actions
  assert.equal(f({ name: 'x' }), false);
  // Missing name
  assert.equal(f({ skill_actions: {} }), false);
  // Empty name string is suspicious
  assert.equal(f({ name: '', skill_actions: {} }), false);
  // Minimal real Policy header
  assert.equal(f({ name: 'x', skill_actions: {} }), true);
  // Full real fixture also accepted
  assert.equal(f(makePolicy()), true);
});

// Regression: share links generated before the correlator + Cisco AI
// Defense fields landed must still decode without crashing the wizard.
// The fix is normalizeImportedPolicy filling in safe defaults at decode
// time so downstream code never sees `correlator === undefined` or
// `cisco_ai_defense === undefined`.
test('share: normalizeImportedPolicy backfills correlator + cisco_ai_defense on older shares', () => {
  const norm = __TEST_INTERNALS.normalizeImportedPolicy;
  const legacy = {
    ...makePolicy(),
  } as unknown as Policy & {
    correlator?: unknown;
    cisco_ai_defense?: unknown;
  };
  delete (legacy as { correlator?: unknown }).correlator;
  delete (legacy as { cisco_ai_defense?: unknown }).cisco_ai_defense;

  const fixed = norm(legacy);
  assert.deepEqual(fixed.correlator, [], 'missing correlator must default to []');
  assert.deepEqual(
    fixed.cisco_ai_defense,
    { enabled: false, endpoint: '', api_key_env: '', scan_hook_surface: true },
    'missing cisco_ai_defense must default to an off, hook-surface-on config',
  );
});

test('share: normalizeImportedPolicy preserves cisco_ai_defense fields that ARE set', () => {
  const norm = __TEST_INTERNALS.normalizeImportedPolicy;
  const populated = makePolicy({
    cisco_ai_defense: {
      enabled: true,
      endpoint: 'https://example.com/aid',
      api_key_env: 'TEST_KEY_ENV',
      scan_hook_surface: false,
    },
  });
  const fixed = norm(populated);
  assert.deepEqual(fixed.cisco_ai_defense, {
    enabled: true,
    endpoint: 'https://example.com/aid',
    api_key_env: 'TEST_KEY_ENV',
    scan_hook_surface: false,
  });
});

// E1 invariant: every key the default preset emits must be in
// KNOWN_POLICY_TOP_LEVEL_KEYS so unknownTopLevelKeys() never
// false-positives the wizard's own bundled presets. This is the
// "schema sentry": the day someone adds a field to Policy + the
// preset bundle but forgets to bump KNOWN_POLICY_TOP_LEVEL_KEYS,
// this test fails with a concrete list of the missing keys.
test('share: KNOWN_POLICY_TOP_LEVEL_KEYS matches policyFromPreset("default")', () => {
  const known = __TEST_INTERNALS.KNOWN_POLICY_TOP_LEVEL_KEYS as Set<string>;
  const presetKeys = Object.keys(policyFromPreset('default')) as string[];
  const missing = presetKeys.filter((k) => !known.has(k));
  assert.deepEqual(
    missing,
    [],
    `KNOWN_POLICY_TOP_LEVEL_KEYS is out of sync with Policy. Missing: ${missing.join(', ')}. Update KNOWN_POLICY_TOP_LEVEL_KEYS in lib/share.ts.`,
  );
});

// E1 invariant: unknownTopLevelKeys() must surface keys that aren't
// modeled by the current build but never false-positive on the
// wizard's own preset output. This pins the import-warning UX so a
// future refactor doesn't accidentally start flagging known fields
// (which would cry-wolf the operator) or hide unknown fields
// (which would silently lose data).
test('share: unknownTopLevelKeys flags only unmodeled fields', () => {
  const { unknownTopLevelKeys } = __TEST_INTERNALS as unknown as {
    unknownTopLevelKeys: (v: unknown) => string[];
  };
  // Preset is fully modeled → empty list.
  assert.deepEqual(unknownTopLevelKeys(policyFromPreset('default')), []);
  // Add a hypothetical-future field → it MUST surface.
  const withExtras = {
    ...policyFromPreset('default'),
    futureCapability: { enabled: true },
    anotherExtra: 'string',
  };
  assert.deepEqual(
    unknownTopLevelKeys(withExtras).sort(),
    ['anotherExtra', 'futureCapability'],
  );
  // Non-objects must not crash; just yield empty.
  assert.deepEqual(unknownTopLevelKeys(null), []);
  assert.deepEqual(unknownTopLevelKeys('not an object'), []);
  assert.deepEqual(unknownTopLevelKeys([1, 2, 3]), []);
});

test('share: end-to-end round trip of a legacy payload does not crash', async () => {
  // Build a payload that simulates an older wizard build by stripping
  // the new fields *before* encoding. We hand-roll the gzip body to
  // bypass encodePolicyForHash's typed Policy input.
  const legacy = { ...makePolicy() } as Record<string, unknown>;
  delete legacy.correlator;
  delete legacy.cisco_ai_defense;
  const json = JSON.stringify(legacy);
  const stream = new Blob([json])
    .stream()
    .pipeThrough(new CompressionStream('gzip'));
  const buf = new Uint8Array(await new Response(stream).arrayBuffer());
  let bin = '';
  for (let i = 0; i < buf.length; i += 0x8000) {
    bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  }
  const body = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const result = await decodePolicyFromHash(`v1.${body}`);
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.ok(Array.isArray(result.policy.correlator), 'correlator must be present after decode');
    assert.ok(
      result.policy.cisco_ai_defense && typeof result.policy.cisco_ai_defense === 'object',
      'cisco_ai_defense must be present after decode',
    );
  }
});

// ── emit: correlator edit detection ─────────────────────────────────

test('emit: canonicalCorrelator is deterministic and identifies identical states', () => {
  const baseline = policyFromPreset('strict').correlator;
  const shuffled = [...baseline].reverse();
  assert.equal(
    EMIT_INTERNALS.canonicalCorrelator(baseline),
    EMIT_INTERNALS.canonicalCorrelator(shuffled),
    'canonical signature must be reorder-stable',
  );
});

test('emit: correlatorDiffersFromDefault returns false for an unmodified strict preset', () => {
  const policy = policyFromPreset('strict');
  assert.equal(
    EMIT_INTERNALS.correlatorDiffersFromDefault(policy),
    false,
    'untouched preset must NOT trigger a correlation-patterns.yaml emit',
  );
});

test('emit: correlatorDiffersFromDefault detects edits to a bundled pattern', () => {
  const policy = policyFromPreset('strict');
  if (policy.correlator.length === 0) {
    // The build script feeds the bundled defaults into every preset;
    // if this test stops finding any patterns the test itself is
    // useless. Surface that explicitly rather than passing vacuously.
    throw new Error('strict preset has no correlator patterns — fixture drift');
  }
  // Mutate a single window_events field on the first bundled pattern.
  // This is precisely the silent-data-loss path the previous heuristic
  // missed (only disabled patterns + unknown ids tripped the emit).
  const edited = {
    ...policy,
    correlator: policy.correlator.map((p, i): CorrelationPattern =>
      i === 0 ? { ...p, window_events: p.window_events + 7 } : p,
    ),
  };
  assert.equal(
    EMIT_INTERNALS.correlatorDiffersFromDefault(edited),
    true,
    'editing a bundled pattern must trigger a correlation-patterns.yaml emit',
  );
});

// Regression for the Quick Start "Cannot read properties of undefined
// (reading 'enabled')" crash. A stale localStorage draft from an older
// build is missing `cisco_ai_defense` and `correlator`. PolicyCreator
// now runs the same normalize-on-import pass as share-link decode, so
// downstream consumers (emit, validators, sections, data-projection)
// see fully-populated objects. We also keep a defensive default at the
// emit() entrypoint so any future skipped-normalize path can't crash
// the whole tab — assert both layers here.
test('emit + normalize: stale policy without correlator/cisco_ai_defense survives the pipeline', () => {
  const stale = { ...makePolicy() } as Record<string, unknown>;
  delete stale.correlator;
  delete stale.cisco_ai_defense;

  // Layer 1 — looksLikePolicy gates the localStorage hydrate; the
  // header (`name` + `skill_actions`) is still intact so it must pass.
  assert.equal(looksLikePolicy(stale), true);

  // Layer 2 — normalizeImportedPolicy fills in safe defaults.
  const normalized = normalizeImportedPolicy(stale as unknown as Policy);
  assert.deepEqual(normalized.correlator, []);
  assert.equal(normalized.cisco_ai_defense?.enabled, false);
  assert.equal(normalized.cisco_ai_defense?.scan_hook_surface, true);

  // Layer 3 — even if a caller forgets to normalize (e.g. a future
  // code path imports a Policy from somewhere new), emit() must not
  // crash on the missing fields. We feed in the raw stale object.
  const files = emit(stale as unknown as Policy);
  // Sanity: emit returned a useful file list (policy YAML + opa data
  // at minimum), and none of the entries reference a Cisco AI Defense
  // block when AID is disabled / absent.
  assert.ok(files.length >= 2, 'emit must return at least the policy YAML + data.json');
  const policyYaml = files.find((f) => f.path.endsWith(`${stale.name}.yaml`));
  assert.ok(policyYaml, 'top-level policy YAML must be emitted');
  assert.equal(
    policyYaml!.contents.includes('cisco_ai_defense'),
    false,
    'AID block must be omitted when the lane is off / missing',
  );
});

test('emit: correlatorDiffersFromDefault detects disabled bundled patterns', () => {
  const policy = policyFromPreset('strict');
  const disabled = {
    ...policy,
    correlator: policy.correlator.map((p, i): CorrelationPattern =>
      i === 0 ? { ...p, enabled: false } : p,
    ),
  };
  assert.equal(
    EMIT_INTERNALS.correlatorDiffersFromDefault(disabled),
    true,
    'disabling a bundled pattern must trigger an emit',
  );
});

// ── download-button smoke (B5) ─────────────────────────────────────
// Exercise the headless download path the playground's Download
// Install Script button takes. A full Playwright suite isn't in
// docs-site's CI yet; this node:test smoke covers the two states
// that actually matter for D4 — gated vs. fired — without the
// browser-runner overhead.

test('download-button (B5): disabledReason blocks the download', async () => {
  const { triggerDownload } = await import('../components/policy-creator/ui/download-button.js');
  // Inject a fake DOM minimal enough to satisfy triggerDownload.
  // We only need createElement/appendChild/removeChild plus a
  // body, since the function never reads from real DOM nodes.
  let clicks = 0;
  let revoked = 0;
  const fakeDoc = {
    body: {
      appendChild: () => {},
      removeChild: () => {},
    },
    createElement: () => ({
      href: '',
      download: '',
      click: () => {
        clicks += 1;
      },
    }),
  } as unknown as Document;
  // Stub URL methods on the global object for the duration of this
  // test; restore them at the end so other tests aren't affected.
  const originalCreate = (globalThis.URL as { createObjectURL?: unknown }).createObjectURL;
  const originalRevoke = (globalThis.URL as { revokeObjectURL?: unknown }).revokeObjectURL;
  (globalThis.URL as unknown as { createObjectURL: (b: Blob) => string }).createObjectURL = () =>
    'blob:fake';
  (globalThis.URL as unknown as { revokeObjectURL: (u: string) => void }).revokeObjectURL = () => {
    revoked += 1;
  };
  try {
    const blocked = triggerDownload({
      filename: 'policy.yaml',
      contents: 'name: test\n',
      mime: 'text/plain',
      disabledReason: 'policy has 1 validation error',
      doc: fakeDoc,
    });
    assert.equal(blocked, false, 'disabledReason must short-circuit the download');
    assert.equal(clicks, 0, 'no anchor click expected when disabled');
    const fired = triggerDownload({
      filename: 'policy.yaml',
      contents: 'name: test\n',
      mime: 'text/plain',
      doc: fakeDoc,
    });
    assert.equal(fired, true, 'with no disabledReason the download must fire');
    assert.equal(clicks, 1, 'exactly one anchor click expected');
    assert.equal(revoked, 1, 'createObjectURL must be paired with revokeObjectURL');
  } finally {
    if (originalCreate !== undefined) {
      (globalThis.URL as unknown as { createObjectURL: unknown }).createObjectURL = originalCreate;
    }
    if (originalRevoke !== undefined) {
      (globalThis.URL as unknown as { revokeObjectURL: unknown }).revokeObjectURL = originalRevoke;
    }
  }
});

// ── emit branches (B4) ─────────────────────────────────────────────
// Each branch corresponds to one file emit() conditionally produces.
// Without these tests a refactor of emit() could silently drop a
// whole policy artifact and the operator would only notice at
// activate-time. Keep each test focused on the *presence/absence*
// invariant of that branch; full YAML content is checked elsewhere.

test('emit: AID block omitted when lane is disabled', () => {
  const policy = makePolicy({
    cisco_ai_defense: { enabled: false, endpoint: '', api_key_env: '', scan_hook_surface: true },
  });
  const top = emit(policy).find((f) => f.path.endsWith(`${policy.name}.yaml`));
  assert.ok(top);
  assert.equal(top!.contents.includes('cisco_ai_defense'), false);
});

test('emit: AID block emitted when lane is enabled', () => {
  const policy = makePolicy({
    cisco_ai_defense: {
      enabled: true,
      endpoint: 'https://aid.example.com',
      api_key_env: 'CISCO_AID_KEY',
      scan_hook_surface: false,
    },
  });
  const top = emit(policy).find((f) => f.path.endsWith(`${policy.name}.yaml`));
  assert.ok(top);
  assert.ok(top!.contents.includes('cisco_ai_defense:'));
  assert.ok(top!.contents.includes('endpoint: https://aid.example.com'));
  assert.ok(top!.contents.includes('api_key_env: CISCO_AID_KEY'));
  // scan_hook_surface=false IS opted-out → must be emitted explicitly.
  assert.ok(top!.contents.includes('scan_hook_surface: false'));
});

test('emit: scan_hook_surface omitted when value is the default (true)', () => {
  const policy = makePolicy({
    cisco_ai_defense: {
      enabled: true,
      endpoint: 'https://aid.example.com',
      api_key_env: 'CISCO_AID_KEY',
      scan_hook_surface: true,
    },
  });
  const top = emit(policy).find((f) => f.path.endsWith(`${policy.name}.yaml`));
  assert.ok(top);
  // We DO emit the AID block (lane is enabled) but NOT the hook-surface
  // override (default-on is implied by HookSurfaceEnabled()).
  assert.ok(top!.contents.includes('cisco_ai_defense:'));
  assert.equal(top!.contents.includes('scan_hook_surface'), false);
});

test('emit: custom Rego snippet → custom-<name>.rego file', () => {
  const policy = makePolicy({
    custom_rego: [
      {
        name: 'block-prod-models',
        package: 'defenseclaw.custom.block_prod_models',
        description: 'Disallow prod models for tier-1 skills',
        source: 'package custom\n\ndeny[msg] {\n  input.model == "prod"\n}\n',
      },
    ],
  });
  const files = emit(policy);
  const rego = files.find((f) => f.path.endsWith('custom-block-prod-models.rego'));
  assert.ok(rego, 'expected custom-block-prod-models.rego in emit output');
  assert.ok(rego!.contents.includes('package custom'));
});

test('emit: rejects command-injection characters in custom Rego names', () => {
  const policy = makePolicy({
    custom_rego: [
      {
        name: 'safe; touch /tmp/pwned',
        package: 'defenseclaw.custom.safe',
        description: 'malicious share payload',
        source: 'package defenseclaw.custom.safe\n',
      },
    ],
  });
  assert.throws(() => emit(policy), /custom Rego name must contain only/);
});

test('emit: rejects surrounding whitespace in names used by install-script comments', () => {
  assert.throws(
    () => emit(makePolicy({ name: 'safe-policy\n' })),
    /policy name must not have leading or trailing whitespace/,
  );
  const policy = makePolicy({
    judges: [
      {
        name: 'safe-judge\n',
        enabled: true,
        system_prompt: 'Inspect the request.',
        categories: {},
      },
    ] as unknown as Policy['judges'],
  });
  assert.throws(
    () => emit(policy),
    /judge name must not have leading or trailing whitespace/,
  );
});

test('emit: empty custom_rego source is skipped', () => {
  const policy = makePolicy({
    custom_rego: [{ name: 'no-op', package: 'defenseclaw.custom.no_op', description: 'placeholder', source: '   \n  \n' }],
  });
  const files = emit(policy);
  assert.equal(
    files.find((f) => f.path.endsWith('custom-no-op.rego')),
    undefined,
    'whitespace-only snippet must be dropped from emit output',
  );
});

test('emit: suppressions emitted only when at least one list is non-empty', () => {
  const empty = makePolicy();
  assert.equal(
    emit(empty).find((f) => f.path.endsWith('suppressions.yaml')),
    undefined,
    'all-empty suppressions must NOT emit a file',
  );
  const populated = makePolicy({
    suppressions: {
      pre_judge_strips: [],
      finding_suppressions: [
        {
          id: 'pii-email-allowed-in-support',
          finding_pattern: 'PII-EMAIL',
          entity_pattern: '@support\\.example\\.com$',
          reason: 'allowed in support tools',
        },
      ],
      tool_suppressions: [],
    },
  });
  const f = emit(populated).find((x) => x.path.endsWith('suppressions.yaml'));
  assert.ok(f, 'populated suppressions must emit a file');
  assert.ok(f!.contents.includes('PII-EMAIL'));
});

test('emit: sensitive_tools emitted only when populated', () => {
  const empty = makePolicy();
  assert.equal(
    emit(empty).find((f) => f.path.endsWith('sensitive-tools.yaml')),
    undefined,
  );
  const populated = makePolicy({
    sensitive_tools: [
      { name: 'shell', result_inspection: true, judge_result: true },
    ],
  });
  const f = emit(populated).find((x) => x.path.endsWith('sensitive-tools.yaml'));
  assert.ok(f);
  assert.ok(f!.contents.includes('name: shell'));
});

test('emit: judge file emitted with min_categories_for_critical when set', () => {
  const policy = makePolicy({
    judges: [
      {
        name: 'injection',
        enabled: true,
        system_prompt: 'You are an injection judge.',
        categories: {
          jailbreak: { finding_id: 'jailbreak', enabled: true },
          extraction: { finding_id: 'extraction', enabled: true },
        },
        min_categories_for_critical: 2,
      },
    ],
  });
  const f = emit(policy).find((x) => x.path.endsWith('judge/injection.yaml'));
  assert.ok(f, 'judge file must be emitted when system_prompt is set');
  assert.ok(
    f!.contents.includes('min_categories_for_critical: 2'),
    'A1 regression — JudgeConfig.min_categories_for_critical must round-trip into the judge YAML',
  );
});

test('emit: judge file skipped when system_prompt is empty', () => {
  const policy = makePolicy({
    judges: [
      {
        name: 'pii',
        enabled: true,
        system_prompt: '',
        categories: {},
      },
    ],
  });
  assert.equal(
    emit(policy).find((x) => x.path.endsWith('judge/pii.yaml')),
    undefined,
    'judge without a system prompt must be skipped (gateway would reject it)',
  );
});

test('emit: correlation-patterns.yaml NOT emitted for untouched default preset', () => {
  const policy = policyFromPreset('default');
  assert.equal(
    emit(policy).find((f) => f.path.endsWith('correlation-patterns.yaml')),
    undefined,
    'untouched preset must NOT emit a correlation-patterns override',
  );
});

test('emit: correlation-patterns.yaml emitted when the operator edits a pattern', () => {
  const policy = policyFromPreset('default');
  if (policy.correlator.length === 0) {
    throw new Error('default preset has no correlator patterns — fixture drift');
  }
  const edited = {
    ...policy,
    correlator: policy.correlator.map((p, i): CorrelationPattern =>
      i === 0 ? { ...p, window_events: p.window_events + 3 } : p,
    ),
  };
  const f = emit(edited).find((x) => x.path.endsWith('correlation-patterns.yaml'));
  assert.ok(f, 'edit to a bundled pattern must produce a correlation-patterns.yaml override');
});

// ── differential parity (B2) ────────────────────────────────────────
// Emit the wizard's "default" preset and compare overlapping fields
// against policies/default.yaml shipped by the gateway. If the wizard
// ever ships a policy named "default" whose action matrix or
// scanner_overrides drift from the gateway's bundled default, this
// test fails CI before an operator sees the divergence.
//
// We compare a deliberate subset because the gateway YAML is a
// hand-edited document with comments, ordering, and trailing fields
// (severity_mappings, etc.) that the wizard doesn't model. The
// playground IS authoritative for the fields it owns; the gateway is
// authoritative for the ones it doesn't.
test('parity (B2): default preset emits action matrix consistent with policies/default.yaml', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const yaml = await import('js-yaml');

  const repoRoot = path.resolve(import.meta.dirname ?? __dirname, '../..');
  const defaultYamlPath = path.join(repoRoot, 'policies', 'default.yaml');
  const raw = fs.readFileSync(defaultYamlPath, 'utf8');
  const bundled = yaml.load(raw) as Record<string, unknown>;

  const wizard = policyFromPreset('default');
  const wizardEmitted = emit(wizard).find((f) => f.path.endsWith(`${wizard.name}.yaml`));
  assert.ok(wizardEmitted, 'wizard must emit a policy YAML for the default preset');
  const wizardYaml = yaml.load(wizardEmitted!.contents) as Record<string, unknown>;

  // 1) skill_actions matrix MUST round-trip verbatim — this is what
  // operators see in the activate path and any silent drift here
  // means the wizard is shipping a different default-behavior matrix
  // than the gateway's own bundled policy.
  assert.deepEqual(
    wizardYaml.skill_actions,
    bundled.skill_actions,
    'skill_actions in wizard "default" preset diverges from policies/default.yaml. ' +
      'Either fix the preset bundle in build-policy-assets.ts or update policies/default.yaml ' +
      'to match — they MUST stay in sync.',
  );

  // 2) firewall.default_action MUST round-trip — operators rely on
  // "the playground's default = the gateway's default" so they can
  // download an unmodified preset and get behaviour equivalent to
  // not installing a policy at all.
  const wizardFw = wizardYaml.firewall as Record<string, unknown> | undefined;
  const bundledFw = bundled.firewall as Record<string, unknown> | undefined;
  assert.equal(
    wizardFw?.default_action,
    bundledFw?.default_action,
    'firewall.default_action in wizard default preset diverges from policies/default.yaml',
  );

  // Note: name + description are intentionally NOT compared — the
  // playground preset is a *starting point* the operator will rename
  // (default name: "my-policy") before activating, whereas
  // policies/default.yaml ships under the literal name "default".
  // The structural fields above (action matrix, firewall default)
  // are the ones that must agree.
});

// ── round-trip property (B1) ───────────────────────────────────────
// Generate a sequence of small mutations to the bundled preset and
// assert that each mutated Policy survives:
//
//   normalize(parse(stringify(policy))) ≡ policy (in shape)
//   emit(policy)                        does not throw
//   share-link decode (gzip → json)     produces a Policy whose
//                                       top-level fields are still
//                                       structurally equal.
//
// This is the cheap property test that would have caught the
// "stale localStorage → emit() crash" regression we just shipped.
// Property generators aren't fancy on purpose; we want the test
// to be reproducible (seed-free) and to fail with a concrete diff
// when something breaks.

const MUTATIONS: Array<(p: Policy) => Policy> = [
  (p) => ({ ...p, name: 'mutated-name' }),
  (p) => ({ ...p, description: 'mutated description with quotes "and" newlines\n' }),
  (p) => ({
    ...p,
    cisco_ai_defense: {
      enabled: true,
      endpoint: 'https://x.example/aid',
      api_key_env: 'CISCO_AID_TEST_ENV',
      scan_hook_surface: false,
    },
  }),
  (p) => ({ ...p, correlator: [] }),
  (p) => ({
    ...p,
    custom_rego: [
      {
        name: 'mutated-snippet',
        package: 'defenseclaw.custom.mutated_snippet',
        description: 'unicode \u{1F6E1} + RTL \u200Fhebrew',
        source: 'package custom\n# comment\nallow := false\n',
      },
    ],
  }),
  (p) => ({
    ...p,
    judges: [
      {
        name: 'injection',
        enabled: true,
        system_prompt: 'judge prompt',
        categories: {
          a: { finding_id: 'a', enabled: true },
          b: { finding_id: 'b', enabled: true },
          c: { finding_id: 'c', enabled: true },
        },
        min_categories_for_critical: 3,
        min_categories_for_high: 1,
      },
    ],
  }),
];

for (const mutate of MUTATIONS) {
  test(`round-trip (B1): mutated policy survives emit + share → decode`, async () => {
    const base = policyFromPreset('default');
    const mutated = mutate(base);
    // 1) emit must not throw.
    const files = emit(mutated);
    assert.ok(files.length >= 2, 'emit must produce at least 2 files');
    // 2) share-link round trip must reproduce the mutated policy.
    const payload = await encodePolicyForHash(mutated);
    const result = await decodePolicyFromHash(payload);
    assert.equal(result.ok, true);
    if (!result.ok) return;
    // The decoded policy should structurally equal the mutated input
    // for every field, after we canonicalize through JSON so the
    // "key present but value undefined" cases (e.g. preset judges
    // with optional fields) collapse the same way the gzip+JSON
    // wire format does. We also re-normalize the mutated input on
    // its way in so the comparison happens on idempotent shapes.
    const canonicalize = (p: Policy): Policy => JSON.parse(JSON.stringify(p)) as Policy;
    const expected = canonicalize(normalizeImportedPolicy(mutated));
    const actual = canonicalize(result.policy);
    assert.deepEqual(actual, expected);
    // 3) Decoded policy must also re-emit identical files.
    const filesAgain = emit(result.policy);
    assert.deepEqual(
      filesAgain.map((f) => f.path),
      files.map((f) => f.path),
      'second emit must produce the same file set',
    );
  });
}

// ── validators: new codes ──────────────────────────────────────────

test('validators: empty correlator pattern surfaces CORRELATOR_PATTERN_EMPTY', () => {
  const policy = makePolicy({
    correlator: [
      {
        id: 'EMPTY-PATTERN',
        description: '',
        window_events: 5,
        severity_on_match: 'HIGH',
        enabled: true,
      },
    ],
  });
  const findings = validatePolicy(policy);
  const codes = findings.map((f) => f.code);
  assert.ok(codes.includes('CORRELATOR_PATTERN_EMPTY'), `expected CORRELATOR_PATTERN_EMPTY in ${codes.join(',')}`);
});

test('validators: window_events=0 surfaces CORRELATOR_WINDOW_INVALID as error', () => {
  const policy = makePolicy({
    correlator: [
      {
        id: 'BAD-WINDOW',
        description: '',
        window_events: 0,
        severity_on_match: 'HIGH',
        all_of: [{ axis: 'ingress_untrusted' }],
        enabled: true,
      },
    ],
  });
  const findings = validatePolicy(policy);
  const f = findings.find((x) => x.code === 'CORRELATOR_WINDOW_INVALID');
  assert.ok(f, 'expected CORRELATOR_WINDOW_INVALID');
  assert.equal(f?.level, 'error');
});

test('validators: api_key_env that looks like a literal key surfaces CISCO_AID_KEY_ENV_MISSING', () => {
  const policy = makePolicy({
    cisco_ai_defense: {
      enabled: true,
      endpoint: '',
      // Lowercase + dashes — does not match [A-Z_][A-Z0-9_]+, so the
      // validator must treat this as a probable paste-the-actual-key.
      api_key_env: 'cisco-aid-prod-abc123def456',
      scan_hook_surface: true,
    },
  });
  const findings = validatePolicy(policy);
  const f = findings.find((x) => x.code === 'CISCO_AID_KEY_ENV_MISSING');
  assert.ok(f, 'expected CISCO_AID_KEY_ENV_MISSING');
  assert.equal(f?.level, 'error');
});

test('validators: properly-shaped CISCO env var passes', () => {
  const policy = makePolicy({
    cisco_ai_defense: {
      enabled: true,
      endpoint: 'https://example.com/aid',
      api_key_env: 'CISCO_AI_DEFENSE_API_KEY',
      scan_hook_surface: true,
    },
  });
  const findings = validatePolicy(policy).filter((f) =>
    f.code === 'CISCO_AID_KEY_ENV_MISSING',
  );
  assert.equal(findings.length, 0, 'valid env var name must not trip the secret-paste lint');
});

// ── rego-highlight ──────────────────────────────────────────────────

test('rego-highlight: classifies keywords vs identifiers', () => {
  const tokens = tokenizeRego('package foo\nimport rego.v1');
  const kinds = tokens.map((t) => t.kind);
  assert.ok(kinds.includes('keyword'), 'package/import should be keywords');
  assert.ok(kinds.includes('identifier'), 'foo/v1 should be identifiers');
});

test('rego-highlight: comments win over keyword detection inside them', () => {
  const tokens = tokenizeRego('# package not-a-keyword');
  assert.equal(tokens.length, 1);
  assert.equal(tokens[0].kind, 'comment');
});

test('rego-highlight: HTML-unsafe characters in source are escaped', () => {
  const html = highlightRegoToHtml('a < b && c > d');
  assert.ok(!html.includes('<b'), 'raw < should never reach the DOM');
  assert.ok(!html.includes('& &'), 'raw & should be entity-encoded');
  assert.ok(html.includes('&lt;'));
  assert.ok(html.includes('&gt;'));
  assert.ok(html.includes('&amp;'));
});

test('rego-highlight: strings with embedded quotes tokenize as one string', () => {
  const tokens = tokenizeRego('msg := "hello \\"world\\""');
  const stringToks = tokens.filter((t) => t.kind === 'string');
  assert.equal(stringToks.length, 1);
  assert.equal(stringToks[0].text, '"hello \\"world\\""');
});

// ── json-highlight ──────────────────────────────────────────────────

test('json-highlight: classifies string / number / literal correctly', () => {
  const tokens = tokenizeJson('{"name":"x","count":42,"on":true,"off":null}');
  const byKind = (k: string) => tokens.filter((t) => t.kind === k).map((t) => t.text);
  assert.deepEqual(byKind('literal'), ['true', 'null']);
  assert.deepEqual(byKind('number'), ['42']);
  // 5 string tokens: "name", "x", "count", "on", "off". Highlighter
  // does not distinguish keys from values today.
  assert.deepEqual(
    byKind('string'),
    ['"name"', '"x"', '"count"', '"on"', '"off"'],
  );
});

test('json-highlight: escapes HTML-unsafe chars in raw source', () => {
  const html = highlightJsonToHtml('{"x":"<script>alert(1)</script>"}');
  assert.ok(!html.includes('<script>'), 'raw <script> tag should never reach DOM');
  assert.ok(html.includes('&lt;script&gt;'));
});

test('json-highlight: punctuation chars get the punctuation kind', () => {
  const tokens = tokenizeJson('{}[],:');
  for (const t of tokens) assert.equal(t.kind, 'punctuation');
});

// ── cmdk-filter ─────────────────────────────────────────────────────

const FIXTURE = [
  { sectionId: 'firewall', label: 'Allowed domains', group: 'Firewall', keywords: ['domain', 'allowlist'] },
  { sectionId: 'webhooks', label: 'Splunk HEC sink', group: 'Webhooks', keywords: ['splunk', 'token'] },
  { sectionId: 'guardrail', label: 'HILT', group: 'Guardrail', keywords: ['human in the loop', 'hilt severity'] },
];

test('cmdk-filter: empty / whitespace-only query returns the input unmodified', () => {
  assert.deepEqual(filterIndex(FIXTURE, ''), FIXTURE);
  assert.deepEqual(filterIndex(FIXTURE, '   '), FIXTURE);
});

test('cmdk-filter: substring match in label hits the right entry', () => {
  const out = filterIndex(FIXTURE, 'splunk');
  assert.equal(out.length, 1);
  assert.equal(out[0].sectionId, 'webhooks');
});

test('cmdk-filter: token AND across label and keyword matches', () => {
  // "token" is a keyword, "splunk" is in the label — both must match.
  const out = filterIndex(FIXTURE, 'splunk token');
  assert.equal(out.length, 1);
  assert.equal(out[0].sectionId, 'webhooks');
});

test('cmdk-filter: no matches returns []', () => {
  assert.deepEqual(filterIndex(FIXTURE, 'kubernetes'), []);
});

test('cmdk-filter: label hits rank above keyword-only hits', () => {
  const corpus = [
    // Matches via keyword only.
    { sectionId: 'a', label: 'Other thing', group: 'X', keywords: ['hilt'] },
    // Matches via label.
    { sectionId: 'b', label: 'HILT', group: 'X', keywords: [] },
  ];
  const out = filterIndex(corpus, 'hilt');
  assert.deepEqual(out.map((e) => e.sectionId), ['b', 'a']);
});
