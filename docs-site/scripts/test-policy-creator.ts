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
