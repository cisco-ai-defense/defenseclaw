import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import contracts from '../../cli/defenseclaw/inventory/hook_contracts.json' with { type: 'json' };
import { connectorById } from '../data/support-matrix';

test('Kiro support matrix gives the hook floors and uncovered upgrade state', () => {
  const kiro = connectorById('kiro');
  assert.ok(kiro);

  const { cli_hook_floor: cliFloor, ide_global_hooks_floor: ideFloor } = contracts.connectors.kiro;
  assert.equal(kiro.minVersion, `kiro-cli ${cliFloor}; Kiro IDE ${ideFloor}`);
  assert.match(kiro.versionNote ?? '', /managed status.*uncovered and verify fails/i);
  assert.match(kiro.versionNote ?? '', /earlier managed CLI enrollments keep their interactive hooks/i);
});

test('Kiro IDE floor and unknown Kiro versions read the same on every page', () => {
  const kiro = connectorById('kiro');
  assert.ok(kiro);
  const connectorPage = readFileSync(new URL('../content/docs/connectors/kiro.mdx', import.meta.url), 'utf8');
  const compatibilityPage = readFileSync(new URL('../content/docs/connectors/compatibility.mdx', import.meta.url), 'utf8');

  for (const source of [kiro.versionNote ?? '', connectorPage, compatibilityPage]) {
    assert.match(source, /refuse[^.]*older IDE/i);
    assert.match(source, /unknown\s+and\s+not\s+protected/i);
    assert.doesNotMatch(source, /per-user setup (still )?accepts an older IDE|older IDE in every profile/i);
  }
});
