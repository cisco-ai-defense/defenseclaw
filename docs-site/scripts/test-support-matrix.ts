import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it, test } from 'node:test';
import contracts from '../../cli/defenseclaw/inventory/hook_contracts.json' with { type: 'json' };
import { connectorById, supportMatrix, withUnlistedPreview } from '../data/support-matrix';
import { HOME_CONNECTORS } from '../components/home/home-data';

describe('support matrix statuses kept outside the generated block', () => {
  it('turns not-offered cells into preview for an unlisted route', () => {
    assert.deepEqual(
      withUnlistedPreview({ linux: 'not-offered', macos: 'supported', windows: 'unsupported' }, true),
      { linux: 'preview', macos: 'supported', windows: 'unsupported' },
    );
  });

  it('leaves statuses alone without an entry', () => {
    const statuses = { linux: 'not-offered', macos: 'not-offered', windows: 'not-offered' } as const;
    assert.deepEqual(withUnlistedPreview({ ...statuses }, undefined), statuses);
  });

  it('shows managed ACP as offered on every OS', () => {
    const acp = supportMatrix.features.find((feature) => feature.id === 'acp');
    assert.ok(acp, 'acp feature row');
    for (const status of Object.values(acp.enterprise)) assert.notEqual(status, 'not-offered');
  });
});

test('Kiro support matrix gives the hook floors and uncovered upgrade state', () => {
  const kiro = connectorById('kiro');
  assert.ok(kiro);

  const { cli_hook_floor: cliFloor, ide_global_hooks_floor: ideFloor } = contracts.connectors.kiro;
  assert.equal(kiro.minVersion, `kiro-cli ${cliFloor}; Kiro IDE ${ideFloor}`);
  assert.match(kiro.versionNote ?? '', /managed status.*uncovered and verify fails/i);
  assert.match(kiro.versionNote ?? '', /earlier managed CLI enrollments keep their interactive hooks/i);
});

test('OpenCode V2 does not inherit V1 live certification on any displayed platform', () => {
  const opencode = connectorById('opencode');
  assert.ok(opencode);
  assert.equal(opencode.minVersion, '2.0.0');
  const home = HOME_CONNECTORS.find((connector) => connector.id === 'opencode');
  assert.ok(home);
  for (const os of ['linux', 'macos', 'windows'] as const) {
    assert.equal(opencode.oss[os].status, 'preview');
    assert.equal(opencode.oss[os].observability, 'preview');
    assert.equal(opencode.enterprise[os].status, 'preview');
    assert.equal(home.os[os], 'preview');
  }
  assert.equal(connectorById('claudecode')?.oss.linux.status, 'supported');
});

test('Kiro IDE floor and unknown Kiro versions read the same on every page', () => {
  const kiro = connectorById('kiro');
  assert.ok(kiro);
  const connectorPage = readFileSync(new URL('../content/docs/connectors/kiro.mdx', import.meta.url), 'utf8');
  const contractsPage = readFileSync(new URL('../content/docs/connectors/compatibility.mdx', import.meta.url), 'utf8');

  for (const source of [kiro.versionNote ?? '', connectorPage, contractsPage]) {
    assert.match(source, /refuse[^.]*older IDE/i);
    assert.match(source, /unknown\s+and\s+not\s+protected/i);
    assert.doesNotMatch(source, /per-user setup (still )?accepts an older IDE|older IDE in every profile/i);
  }
});
