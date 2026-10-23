import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const guide = readFileSync(
  new URL('../content/docs/get-started/upgrade.mdx', import.meta.url),
  'utf8',
);
const removed = guide.split('## Renamed and removed connectors\n')[1]?.split(/^## /m)[0];
const normalized = removed?.replace(/\s+/g, ' ');

test('retired connector upgrade guide gives the hard-link refusal and uninstall recovery steps', () => {
  assert.ok(removed, 'retired connector section must exist');
  assert.ok(/on every OS[^.]*hard link/i.test(normalized), 'hard-linked marked scripts are refused on every OS');
  assert.ok(/delete (?:the |its )?other names/i.test(normalized), 'other hard-link names must be removed');
  assert.ok(/defenseclaw-gateway connector teardown --connector openhands/.test(normalized), 'rerun teardown');
  assert.ok(/defenseclaw uninstall[^.]*before stopping the gateway/i.test(normalized), 'uninstall keeps the gateway running');
  assert.ok(/Windows Setup[^.]*retry-required[^.]*intent pending/i.test(normalized), 'Setup keeps a pending retry intent');
  assert.ok(!/every other name of\s+the file \(a hard link\) blocks too/i.test(removed), 'do not promise all names block');
});
