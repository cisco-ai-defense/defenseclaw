import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import matrix from '../data/capability-matrix.json' with { type: 'json' };
import { featureDemos } from '../data/feature-demos';
import {
  createInitialPlayerState,
  playerReducer,
} from '../components/feature-demo/reducer';
import type { ScenarioStep } from '../components/feature-demo/types';

const connectorIds = new Set(matrix.connectors.map((connector) => connector.id));
const approvedFixtureHosts = new Set([
  'collector.example.invalid',
  'provider.example.invalid',
  'registry.example.invalid',
]);

function allStepSets(scenario: (typeof featureDemos)[number]): ScenarioStep[][] {
  return [scenario.steps, ...(scenario.variants?.map((variant) => variant.steps) ?? [])];
}

describe('feature demo catalog', () => {
  it('uses unique scenario ids and complete boundaries', () => {
    const ids = featureDemos.map((scenario) => scenario.id);
    assert.equal(new Set(ids).size, ids.length);
    for (const scenario of featureDemos) {
      assert.ok(scenario.boundaries.did.length > 0, `${scenario.id} needs did boundaries`);
      assert.ok(scenario.boundaries.didNot.length > 0, `${scenario.id} needs did-not boundaries`);
      assert.match(scenario.syntheticDataNotice, /guided example/i);
      assert.doesNotMatch(scenario.syntheticDataNotice, /\blive\b/i);
    }
  });

  it('resolves every tab, evidence, outcome, and highlighted line reference', () => {
    for (const scenario of featureDemos) {
      const tabs = new Map(scenario.tabs.map((tab) => [tab.id, tab]));
      const evidenceIds = new Set(scenario.evidence.map((item) => item.id));
      const outcomeIds = new Set(scenario.outcomes.map((item) => item.id));
      assert.equal(tabs.size, scenario.tabs.length, `${scenario.id} has duplicate tab ids`);
      assert.equal(evidenceIds.size, scenario.evidence.length, `${scenario.id} has duplicate evidence ids`);
      assert.equal(outcomeIds.size, scenario.outcomes.length, `${scenario.id} has duplicate outcome ids`);

      for (const steps of allStepSets(scenario)) {
        assert.ok(steps.length > 0, `${scenario.id} has an empty step set`);
        for (const current of steps) {
          assert.ok(tabs.has(current.activeTab), `${scenario.id}/${current.id} has an unknown active tab`);
          current.evidenceIds.forEach((id) => assert.ok(evidenceIds.has(id), `${scenario.id}/${current.id} references unknown evidence ${id}`));
          if (current.outcomeId) assert.ok(outcomeIds.has(current.outcomeId), `${scenario.id}/${current.id} references unknown outcome ${current.outcomeId}`);
          for (const range of current.highlightedLines ?? []) {
            const tab = tabs.get(range.tabId);
            assert.ok(tab, `${scenario.id}/${current.id} highlights an unknown tab`);
            const lines = tab!.source.split('\n').length;
            assert.ok(range.start >= 1 && range.end >= range.start && range.end <= lines, `${scenario.id}/${current.id} has invalid ${range.start}-${range.end} range for ${range.tabId} (${lines} lines)`);
          }
        }
      }
    }
  });

  it('references only connectors in the capability matrix', () => {
    for (const scenario of featureDemos) {
      scenario.connectorIds.forEach((id) => assert.ok(connectorIds.has(id), `${scenario.id} references unknown connector ${id}`));
    }
  });

  it('keeps connector and severity outcomes consistent', () => {
    const cursor = matrix.connectors.find((connector) => connector.id === 'cursor');
    const claude = matrix.connectors.find((connector) => connector.id === 'claudecode');
    const codex = matrix.connectors.find((connector) => connector.id === 'codex');
    assert.equal(cursor?.hooks.canBlock, true);
    assert.equal(claude?.hooks.canBlock, true);
    assert.equal(claude?.hooks.canAskNative, true);
    assert.equal(codex?.hooks.canAskNative, false);

    for (const scenario of featureDemos) {
      const evidence = new Map(scenario.evidence.map((item) => [item.id, item]));
      const outcomes = new Map(scenario.outcomes.map((item) => [item.id, item]));
      for (const steps of allStepSets(scenario)) {
        for (const current of steps) {
          if (!current.outcomeId) continue;
          const hasCriticalEvidence = current.evidenceIds.some((id) => /critical/i.test(`${evidence.get(id)?.value} ${evidence.get(id)?.detail}`));
          if (hasCriticalEvidence) assert.notEqual(outcomes.get(current.outcomeId)?.kind, 'pause', `${scenario.id} pauses a CRITICAL finding`);
        }
      }
    }
  });

  it('preserves admission workflow boundaries', () => {
    const skill = featureDemos.find((scenario) => scenario.id === 'skill-quarantine');
    const skillIds = skill!.steps.map((current) => current.id);
    assert.ok(skillIds.indexOf('skill-quarantine') < skillIds.indexOf('skill-scan'));

    const mcp = featureDemos.find((scenario) => scenario.id === 'mcp-shadow-capability');
    assert.match(mcp!.tabs.map((tab) => tab.source).join('\n'), /local_stdio|stdio/);
    assert.ok(mcp!.boundaries.didNot.some((item) => /remote URL/i.test(item)));

    const registry = featureDemos.find((scenario) => scenario.id === 'registry-promote-require');
    assert.match(registry!.tabs.map((tab) => tab.source).join('\n'), /sync: on_demand/);
    assert.match(registry!.summary + registry!.syntheticDataNotice, /on-demand|on demand/i);
  });

  it('keeps fixtures synthetic and free of credential-shaped values', () => {
    const credentialShape = /(?:sk|token|secret|password|bearer)[-_]?[a-z0-9]{12,}/i;
    for (const scenario of featureDemos) {
      for (const tab of scenario.tabs) {
        assert.doesNotMatch(tab.source, credentialShape, `${scenario.id}/${tab.id} contains a credential-shaped value`);
        for (const match of tab.source.matchAll(/https?:\/\/([^/\s"']+)/g)) {
          assert.ok(approvedFixtureHosts.has(match[1]), `${scenario.id}/${tab.id} uses unapproved fixture host ${match[1]}`);
        }
      }
    }
  });
});

describe('scenario player reducer', () => {
  it('starts server-rendered at the complete state and autoplays from step one', () => {
    const initial = createInitialPlayerState(4);
    assert.deepEqual(initial, { stepIndex: 4, isPlaying: false, completed: true, selectedVariant: undefined });
    const playing = playerReducer(initial, { type: 'AUTOPLAY_START' });
    assert.equal(playing.stepIndex, 0);
    assert.equal(playing.isPlaying, true);
  });

  it('pauses on manual tab and variant selection', () => {
    const playing = { stepIndex: 1, isPlaying: true, completed: false };
    const tabbed = playerReducer(playing, { type: 'SELECT_TAB', tabId: 'policy' });
    assert.equal(tabbed.isPlaying, false);
    assert.equal(tabbed.manualTabId, 'policy');
    const variant = playerReducer(playing, { type: 'SELECT_VARIANT', variantId: 'deny', lastStep: 2 });
    assert.equal(variant.stepIndex, 2);
    assert.equal(variant.completed, true);
  });
});
