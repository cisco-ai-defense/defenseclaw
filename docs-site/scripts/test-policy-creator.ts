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
  __TEST_INTERNALS,
} from '../components/policy-creator/lib/share.js';
import { highlightRegoToHtml, tokenizeRego } from '../components/policy-creator/lib/rego-highlight.js';
import { highlightJsonToHtml, tokenizeJson } from '../components/policy-creator/lib/json-highlight.js';
import { filterIndex } from '../components/policy-creator/playground/cmdk-filter.js';
import type { Policy } from '../components/policy-creator/types.js';

// ── fixtures ────────────────────────────────────────────────────────

// Minimal-but-valid Policy. We only populate fields share.looksLikePolicy
// reads (metadata.name, severity_matrix), plus enough realistic chrome
// to make round-trips meaningful. The rest of the wizard happily fills
// with defaults if a draft omits them.
function makePolicy(overrides: Partial<Policy> = {}): Policy {
  const base = {
    name: 'test-policy',
    basedOn: 'default',
    metadata: {
      name: 'test-policy',
      description: 'unit-test fixture',
      labels: {},
    },
    severity_matrix: {
      critical: { runtime: 'disable', file: 'quarantine', install: 'block' },
      high: { runtime: 'disable', file: 'quarantine', install: 'block' },
      medium: { runtime: 'enable', file: 'none', install: 'allow' },
      low: { runtime: 'enable', file: 'none', install: 'allow' },
      info: { runtime: 'enable', file: 'none', install: 'allow' },
    },
    severity_overrides: {},
    admission: { scan_on_install: true, allow_list_bypass_scan: false },
    first_party: [],
    guardrail: {
      block_threshold: 3,
      alert_threshold: 2,
      cisco_trust_level: 'advisory',
      hilt: { enabled: false, min_severity: 'HIGH' },
      patterns: {},
      severity_mappings: {},
    },
    rules_files: [],
    suppressions: { pre_judge_strips: [], finding: [], tool: [] },
    sensitive_tools: [],
    judges: [],
    custom_rego: [],
    firewall: { default: 'allow', allowed_domains: [], blocked: [] },
    audit: { retention_days: 90 },
    enforcement: { max_delay_seconds: 2 },
    watch: { enabled: false, interval_minutes: 60 },
    scanners: { profiles: [] },
    webhooks: { destinations: [] },
    ...overrides,
  } as unknown as Policy;
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

test('share: looksLikePolicy gates rejects null, arrays, and missing metadata', () => {
  const f = __TEST_INTERNALS.looksLikePolicy;
  assert.equal(f(null), false);
  assert.equal(f(undefined), false);
  assert.equal(f([]), false);
  assert.equal(f('string'), false);
  assert.equal(f(42), false);
  assert.equal(f({}), false);
  assert.equal(f({ metadata: {} }), false);
  assert.equal(f({ metadata: { name: 'x' } }), false);
  assert.equal(f({ metadata: { name: 'x' }, severity_matrix: {} }), true);
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
