// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { loadPolicy } from '@open-policy-agent/opa-wasm';
import { buildCommand, DEFAULT_STATE } from '../components/command-generator';
import { projectPolicyToData, withPolicyInput } from '../components/policy-creator/lib/data-projection';
import { pickVerdictEntrypoint } from '../components/policy-creator/lib/opa-eval';
import { policyFromPreset } from '../components/policy-creator/lib/presets';
import { applyAnswers } from '../components/policy-creator/quick-start/apply';
import { defaultAnswers } from '../components/policy-creator/quick-start/questions';
import recipes from '../data/policy-recipes.json';
import scenarios from '../data/policy-scenarios.json';

for (const shell of ['bash', 'powershell'] as const) {
  test(`Hermes generator explains the closed hook and upstream timeout (${shell})`, () => {
    const built = buildCommand({ ...DEFAULT_STATE, connector: 'hermes', mode: 'action' }, shell);
    const notes = built.warnings.join(' ');
    assert.match(notes, /closed.*gateway.*unusable/i);
    assert.match(notes, /times out or cannot start/);
    assert.doesNotMatch(notes, /does not support fail-closed|failure the request will be allowed/);
  });
}

test('Balanced Quick Start admission replay agrees with its default expectations', async () => {
  const policy = applyAnswers(defaultAnswers());
  const data = projectPolicyToData(policy);
  for (const scenario of scenarios.scenarios.filter((s) => s.domain === 'admission')) {
    const engine = await loadPolicy(readFileSync(new URL(`../public/opa/${scenario.domain}.wasm`, import.meta.url)));
    engine.setData(data);
    const result = engine.evaluate(withPolicyInput(scenario.domain, scenario.input, data), pickVerdictEntrypoint(scenario.domain));
    assert.equal(result[0]?.result, scenario.expectedVerdict, scenario.id);
  }
});

test('guardrail scenarios keep their authored action-mode expectations', async () => {
  const policy = policyFromPreset('default');
  policy.guardrail.mode = 'action';
  const data = projectPolicyToData(policy);
  for (const scenario of scenarios.scenarios.filter((s) => s.domain === 'guardrail')) {
    const engine = await loadPolicy(readFileSync(new URL('../public/opa/guardrail.wasm', import.meta.url)));
    engine.setData(data);
    const result = engine.evaluate(withPolicyInput('guardrail', scenario.input, data), pickVerdictEntrypoint('guardrail'));
    assert.equal(result[0]?.result, scenario.expectedVerdict, scenario.id);
  }
});

test('Quick Start observe mode alerts at HIGH+ and allows MEDIUM', async () => {
  const data = projectPolicyToData(applyAnswers(defaultAnswers()));
  assert.equal(data.guardrail.mode, 'observe');
  assert.equal(data.guardrail.alert_threshold, 3);
  const expected = new Map([
    ['guardrail-critical-prompt', 'alert'],
    ['guardrail-medium-completion', 'allow'],
    ['correlator-lethal-trifecta', 'alert'],
  ]);
  for (const scenario of scenarios.scenarios.filter((s) => s.domain === 'guardrail')) {
    const engine = await loadPolicy(readFileSync(new URL('../public/opa/guardrail.wasm', import.meta.url)));
    engine.setData(data);
    const result = engine.evaluate(withPolicyInput('guardrail', scenario.input, data), pickVerdictEntrypoint('guardrail'));
    assert.ok(expected.has(scenario.id), `add an explicit observe expectation for ${scenario.id}`);
    assert.equal(result[0]?.result, expected.get(scenario.id), scenario.id);
  }
});

test('MEDIUM MCP scan warns under Balanced and is rejected under Strict', async () => {
  const scenario = scenarios.scenarios.find((s) => s.id === 'admission-medium-mcp')!;
  for (const [preset, verdict] of [['default', 'warning'], ['strict', 'rejected']] as const) {
    const data = projectPolicyToData(policyFromPreset(preset));
    const engine = await loadPolicy(readFileSync(new URL('../public/opa/admission.wasm', import.meta.url)));
    engine.setData(data);
    const result = engine.evaluate(withPolicyInput('admission', scenario.input, data), pickVerdictEntrypoint('admission'));
    assert.equal(result[0]?.result, verdict, preset);
  }
});

test('AWS key recipe examples match the required length and pattern', () => {
  const recipe = recipes.recipes.find((r) => r.id === 'RECIPE-SEC-AWS-KEY')!;
  const regex = new RegExp((recipe.body as { pattern: string }).pattern);
  for (const example of recipe.examples ?? []) {
    assert.equal(example.length, 20, 'four prefix characters and sixteen synthetic suffix characters');
    assert.ok(regex.test(example), `positive example ${example}`);
  }
  for (const example of recipe.counterexamples ?? []) assert.ok(!regex.test(example));
});
