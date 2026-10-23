import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { supportMatrix, withUnlistedPreview } from '../data/support-matrix';

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
