import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

// Docs claims that must match what the product does. Each check reads the
// page as one line of words, so a reflowed paragraph still matches.

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(site, '..');
const docs = join(site, 'content/docs');

function page(name: string): string {
  return readFileSync(join(site, 'content/docs', name), 'utf8').split(/\s+/).join(' ');
}

function mdxPages(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? mdxPages(path) : entry.name.endsWith('.mdx') ? [path] : [];
  });
}

describe('recovery and repair advice', () => {
  it('describes recovery and data loss for a failed MicroVM', () => {
    const body = page('troubleshooting/sandboxes/runs-and-sessions.mdx');
    const section = body.split('## A sandbox is in OpenShell\'s error state')[1]?.split('## ')[0];
    assert.ok(section, 'error-state troubleshooting section is missing');
    for (const text of ['Docker', 'MicroVM', 'MainProcessFailed', '--end-vm', 'has not written to its disk is lost',
      'defenseclaw sandbox status NAME', 'defenseclaw sandbox stop NAME', 'defenseclaw sandbox delete NAME',
      'deletes it and its work', 'process exited',
      'stopped after ending and stopping a failed VM', 'absent after deletion']) {
      assert.ok(section.includes(text), `error-state recovery must describe ${text}`);
    }
    assert.ok(!section.includes('which keep the sandbox and its work'), 'error-state recovery promises to keep unwritten VM work');
    const exited = section.split('For a MicroVM whose process exited')[1]?.split('For a MicroVM whose main process failed')[0];
    assert.ok(exited, 'exited-VM recovery needs its own advice');
    assert.ok(exited.includes('last successful disk sync'), 'an exited VM may have unsynced work');
    assert.ok(!exited.includes('keep the sandbox and its work'), 'an exited VM has no confirmed disk sync');
    assert.ok(section.includes('ProcessPollFailed') && section.includes('a stop that OpenShell refuses does not release the VM'),
      'another held VM error must not promise stop/start recovery');
    const refusedStart = body.split('## A sandbox is not as DefenseClaw prepared it')[1]?.split('## ')[0];
    assert.ok(refusedStart?.includes('last successful disk sync'), 'refused-start advice must qualify MicroVM work');
    assert.ok(!refusedStart?.includes('(its work is kept)'), 'refused-start advice promises unsynced work');
    const handoff = page('reference/sandboxes/cli.mdx').split('Handing the gateway over stops the sandboxes it runs')[1]?.split('</Callout>')[0];
    assert.ok(handoff?.includes('last successful disk sync'), 'gateway handoff advice must qualify copy-mode MicroVM work');
    assert.ok(!handoff?.includes('a copy keeps its work in the sandbox'), 'gateway handoff promises unsynced copy-mode work');
    const managed = page('enterprise/runtime/sandboxes.mdx');
    assert.ok(managed.includes('last successful disk sync'), 'managed upgrade advice must qualify failed-VM work');
    assert.ok(!managed.includes('a completed or failed MicroVM on 0.1.5 is started'),
      'managed upgrade advice must not send every failed VM through --end-vm');
    assert.ok(!managed.includes('the user stops and starts a MicroVM that was in the error state'),
      'managed upgrade advice promises a failed VM can always stop and start');
    const upgrade = page('troubleshooting/sandboxes/setup-and-gateway.mdx');
    assert.ok(upgrade.includes('It does not stop that legacy guest for you'), 'legacy guest recovery must leave the stop to its user');
    assert.ok(!upgrade.includes('DefenseClaw stops it as soon as it sees it'), 'legacy guest recovery promises an automatic stop');
    assert.ok(upgrade.includes('`openshell sandbox stop` does not sync its guest disk'), 'raw OpenShell stops need their own disk warning');
    for (const [name, claim] of [
      ['troubleshooting/sandboxes/setup-and-gateway.mdx', 'last successful disk sync'],
      ['troubleshooting/sandboxes/disk-and-telemetry.mdx', 'last successful disk sync'],
      ['reference/sandboxes/cli.mdx', 'last successful one'],
      ['enterprise/runtime/sandbox-reference.mdx', 'last successful disk sync'],
    ]) {
      assert.ok(page(name).includes(claim), `${name} must qualify what a failed sync preserves`);
    }
  });

  it('keeps the saved guardrail mode', () => {
    const remediation = /recover|repair|restore|troubleshoot|turn it (?:off|back on)/i;
    const modeCommand = /defenseclaw\s+(?:setup\b[^\n`]*--mode(?:\s|=)|guardrail\s+mode\s+(?:observe|action)\b)/i;
    const modeProse = /\b(?:re-?run|run|repeat)\b[^.\n]*\bsetup\b[^.\n]*\bin (?:observe|action) mode\b/i;
    const violations: string[] = [];
    let checked = 0;
    for (const file of mdxPages(docs)) {
      const body = readFileSync(file, 'utf8');
      const headings = [...body.matchAll(/^## (.+)$/gm)];
      for (let i = 0; i < headings.length; i++) {
        const title = headings[i][1];
        // This section deliberately teaches a switch from observe to action.
        // It is not a repair of an existing posture.
        if (title === 'Nothing is blocked') continue;
        const section = body.slice(
          headings[i].index! + headings[i][0].length,
          i + 1 < headings.length ? headings[i + 1].index : undefined,
        );
        if (!remediation.test(title) && !section.includes('**Fix.**') && !section.includes('Turn it back on')) {
          continue;
        }
        checked++;
        const normalized = section.replace(/\\\r?\n/g, ' ');
        for (const pattern of [modeCommand, modeProse]) {
          const found = pattern.exec(normalized);
          if (found) violations.push(relative(docs, file) + ': ' + title + ': ' + found[0]);
        }
      }
    }
    assert.ok(checked > 0, 'no recovery or repair sections were checked');
    assert.deepEqual(violations, []);
  });
});

describe('Intune base config versus the signed bundle', () => {
  it('names exactly the blocks the packager compares', () => {
    const packager = readFileSync(
      join(repo, 'packaging/mdm/intune/windows/New-DefenseClawIntunePackage.ps1'),
      'utf8',
    );
    assert.ok(packager.includes('No other key is compared'), 'packager no longer says what it compares');
    const list = /foreach \(\$key in ((?:'[a-z_]+'(?:, )?)+)\)/.exec(packager);
    assert.ok(list, 'packager hook-block key list not found');
    const compared = [...list[1].matchAll(/'([a-z_]+)'/g)].map((match) => match[1]);
    assert.ok(compared.length > 0);
    const reference = readFileSync(join(site, 'content/docs/enterprise/mdm/intune/windows-reference.mdx'), 'utf8');
    const row = reference.split('\n').find((line) => line.startsWith('| `-BaseConfigPath` |'));
    assert.ok(row, 'windows-reference has no -BaseConfigPath row');
    assert.ok(row.includes('No other setting is compared'), 'the -BaseConfigPath row does not say nothing else is compared');
    for (const key of ['guardrail', ...compared]) {
      assert.ok(row.includes(`\`${key}:\``), `the -BaseConfigPath row does not name the compared ${key}: block`);
    }
  });
});

describe('fail mode of Copilot CLI and Antigravity hooks', () => {
  it('says the hooks follow a closed fail mode', () => {
    const failModes = page('reference/configuration/fail-modes.mdx');
    assert.ok(!failModes.includes('The generated hooks stay open even when the effective mode is `closed`'));
    assert.ok(failModes.includes('Copilot and Antigravity still run a call when the hook times out or cannot start'));
    assert.ok(failModes.includes('Under Secure Client they stay open'));
    for (const name of ['reference/connectors/copilot.mdx']) {
      const text = page(name);
      assert.ok(!/no fail-closed hook transport/i.test(text), name);
      assert.ok(text.includes('in fail mode `closed`, the default'), name);
    }
    for (const name of ['reference/connectors/antigravity.mdx']) {
      const text = page(name);
      assert.ok(!text.includes('A gateway failure lets the call run'), name);
      assert.ok(!text.includes('normal fail-open operation'), name);
      assert.ok(text.includes('In fail mode `closed`, the default'), name);
    }
  });

  it('keeps fail-open wording out of the connector summaries', () => {
    const matrix = JSON.parse(readFileSync(join(site, 'data/capability-matrix.json'), 'utf8')) as {
      connectors: { id: string; summary?: string }[];
    };
    for (const connector of matrix.connectors) {
      assert.ok(!/fail(ure)?-open/i.test(connector.summary ?? ''), `${connector.id} summary`);
    }
  });

  it('says an upgrade keeps only an open the config sets', () => {
    assert.ok(page('get-started/upgrade.mdx').includes("An upgrade sets each hook's fail mode from your config before the new hook runs"));
    assert.ok(page('reference/configuration/fail-modes.mdx').includes('`closed` outside Secure Client; `open` under it'));
    assert.ok(page('reference/configuration/fail-modes.mdx').includes('Hooks follow an open fail mode only when your config sets it'));
  });
});
