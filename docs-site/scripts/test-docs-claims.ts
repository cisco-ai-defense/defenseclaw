import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

// Docs claims and release security requirements. Each check reads the
// page as words, so a reflowed paragraph still matches.

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(site, '..');

function page(name: string): string {
  return readFileSync(join(site, 'content/docs', name), 'utf8').split(/\s+/).join(' ');
}

function enterprisePages(path = join(site, 'content/docs/enterprise')): string[] {
  return readdirSync(path, { withFileTypes: true }).flatMap((entry) => {
    const child = join(path, entry.name);
    if (entry.isDirectory()) return enterprisePages(child);
    return entry.isFile() && entry.name.endsWith('.mdx') ? [child] : [];
  });
}

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

describe('setup and rollback recovery guides', () => {
  it('says a refused Cursor action setup makes no change and gives an explicit observe command', () => {
    const setup = readFileSync(join(repo, 'cli/defenseclaw/commands/cmd_setup.py'), 'utf8');
    assert.ok(setup.includes('connector was not detected locally; refusing action-mode hook setup.'));
    const guide = page('how-to/guardrail/stop-a-secret-upload.mdx');
    assert.match(guide, /Cursor was not detected locally.*refuses action mode.*(?:no|nothing) (?:setup or configuration )?change/i);
    assert.ok(guide.includes('defenseclaw setup cursor --yes --mode observe'));
    assert.doesNotMatch(guide, /refuses action mode and configures observe mode/i);
  });

  it('explains a failed Windows rollback, its undo, and pending installer recovery', () => {
    const installer = readFileSync(join(repo, 'scripts/install.ps1'), 'utf8');
    assert.ok(installer.includes('return Undo-Rollback "DefenseClaw $backTo is not proven running'));
    assert.ok(installer.includes('Assert-LifecycleRestored (Get-Variable -Name Manifest'));
    assert.ok(installer.includes('fix the cause, then run: $(Get-LifecycleNextStep)'));
    const rollback = page('get-started/upgrade.mdx').split('## Rollback', 2)[1].split('## Update notices', 1)[0];
    assert.match(rollback, /does not start or, on Windows, cannot be proven.*undoes the rollback/i);
    assert.match(rollback, /restart and prove the install.*started from/i);
    assert.match(rollback, /lifecycle record.*install lock/i);
    assert.match(rollback, /recovery command.*installer prints/i);
    assert.doesNotMatch(rollback, /agent hooks are not guarded until `defenseclaw-gateway start` succeeds/i);
  });

  it('describes every Windows and Unix pending recovery hook state', () => {
    const installer = readFileSync(join(repo, 'scripts/install.ps1'), 'utf8');
    const closeHooks = /function Close-UnfinishedInstallHooks \{([\s\S]*?)\n\}\n\nfunction Clear-SetupDataDir/.exec(installer)?.[1];
    assert.ok(closeHooks, 'Windows installer hook closure path not found');
    assert.match(closeHooks, /\(-not \$unfinished\.Count -and -not \$pending\) -or \(Get-GatewayProcess\)/);
    assert.match(closeHooks, /-not \(Test-Path -LiteralPath \(Join-Path \$DataDir "hooks"\) -PathType Container\)/);
    assert.match(closeHooks, /if \(Close-AllHooks \$gateways\)/);
    assert.match(closeHooks, /every agent hook blocks tool calls until the gateway runs again/);
    assert.match(closeHooks, /agent hooks could not be closed: until the gateway runs, they follow the outage fail mode/);

    const unixInstaller = readFileSync(join(repo, 'scripts/install.sh'), 'utf8');
    const unixRestore = /restore_snapshot\(\) \{([\s\S]*?)\n\}\n\nrestart_old\(\)/.exec(unixInstaller)?.[1];
    assert.ok(unixRestore, 'Unix installer incomplete restore path not found');
    assert.match(unixRestore, /The snapshot stays \(with COMPLETE\), so the next run puts the rest back first/);
    const unixRestart = /restart_old\(\) \{([\s\S]*?)\n\}\n\n# A 1\.0\.0 gateway/.exec(unixInstaller)?.[1];
    assert.ok(unixRestart, 'Unix installer failed gateway restart path not found');
    assert.match(unixRestart, /connectors in fail-closed mode block tool calls/);
    const unixUndo = /undo_rollback\(\) \{([\s\S]*?)\n\}\n\n# A 0\.x release/.exec(unixInstaller)?.[1];
    assert.ok(unixUndo, 'Unix installer failed rollback undo path not found');
    assert.match(unixUndo, /gateway is not running, so agent hooks are not guarded/);
    assert.match(installer, /is installed, but its gateway is not running, so agent hooks are not guarded/);

    const rollback = page('get-started/upgrade.mdx').split('## Rollback', 2)[1].split('## Update notices', 1)[0];
    assert.match(rollback, /on Windows.*gateway is down.*installed hooks.*if (?:that|hook closure) succeeds, (?:they|hooks) block tool calls until the gateway runs again/i);
    assert.match(rollback, /if the gateway is running or no hooks directory exists.*does not force hooks closed/i);
    assert.match(rollback, /if the installer warns that hooks could not be closed, they follow the configured outage fail mode.*configured open may allow tool calls/i);
    assert.match(rollback, /on Linux and macOS.*does not force hooks closed.*gateway.*down.*closed.*block.*open.*allow/i);
    assert.match(rollback, /unfinished snapshot.*run the same install command again/i);
    assert.match(rollback, /if undoing the rollback also fails.*gateway down.*hooks not guarded/i);
    assert.match(rollback, /stop agent activity, fix the reported cause and run the recovery command the installer prints/i);
    assert.doesNotMatch(rollback, /hooks block tool calls until recovery finishes/i);
  });
});

describe('Windows Hermes failure guidance', () => {
  it('matches the native hook fail mode and names the managed outage exception', () => {
    const hook = readFileSync(join(repo, 'internal/gateway/connector/hookexec/managed_hermes.go'), 'utf8');
    const failMode = /func hermesFailsClosed\(opts Options\) bool \{([\s\S]*?)\n\}/.exec(hook)?.[1];
    assert.ok(failMode, 'native Hermes failure mode not found');
    assert.match(failMode, /opts\.ManagedEnterprise && !managedNativeDecision\(opts\)/);
    assert.match(failMode, /opts\.StrictAvailability \|\| !strings\.EqualFold\(strings\.TrimSpace\(opts\.FailMode\), "open"\)/);
    const windows = page('troubleshooting/windows.mdx');
    assert.doesNotMatch(windows, /Hermes.*(?:fail-open setting|always shows failures as open)/i);
    assert.match(windows, /Hermes.*closed by default.*explicitly.*open/i);
    assert.match(windows, /managed host.*administrator.*open.*gateway outage/i);
    assert.match(windows, /Secure Client.*open.*default/i);
  });
});

describe('managed-host enrollment protection', () => {
  const guides = [
    'enterprise/plan/threat-model.mdx',
    'enterprise/configure/enrollment.mdx',
    'enterprise/configure/reference.mdx',
    'enterprise/configure/machine-policy.mdx',
    'enterprise/install/reference/windows.mdx',
    'enterprise/operate/lifecycle.mdx',
  ];
  for (const name of guides) {
    it(`${name} describes zero-enrollment refusal`, () => {
      const paragraphs = readFileSync(join(site, 'content/docs', name), 'utf8')
        .split(/\n\s*\n/)
        .map((text) => text.split(/\s+/).join(' '));
      const closure = paragraphs.find((text) =>
        /Claude Code, Codex and Cursor/i.test(text) &&
        /(?:no|zero|last).{0,60}enrolled user/i.test(text) &&
        /(?:refus|fail closed)/i.test(text),
      );
      assert.ok(closure, `${name} must describe refusal even with no enrolled user`);
    });
  }

  it('does not present a missing machine hook as an intended enrollment state', () => {
    for (const path of enterprisePages()) {
      const paragraphs = readFileSync(path, 'utf8')
        .split(/\n\s*\n/)
        .map((text) => text.split(/\s+/).join(' '));
      for (const paragraph of paragraphs) {
        if (!/(?:Claude Code|Codex|Cursor)/i.test(paragraph)) continue;
        assert.doesNotMatch(
          paragraph,
          /(?:no|none|last|at least one|another).{0,100}enrolled user.{0,260}(?:without DefenseClaw hooks|no hooks|not published|policy is removed)/i,
          `${path} presents missing machine policy as an intended enrollment state`,
        );
        assert.doesNotMatch(
          paragraph,
          /(?:Claude Code|Codex|Cursor).{0,120}(?:policy|hooks).{0,120}(?:only while|needs? at least one|requires? at least one).{0,120}enrolled/i,
          `${path} conditions managed policy on another user's enrollment`,
        );
      }
    }
  });

  it('explains Windows protection before first enrollment, after last removal, and repair', () => {
    const windows = page('enterprise/install/reference/windows.mdx');
    assert.match(windows, /configured Claude Code, Codex and Cursor machine hooks.{0,260}before the first (?:user )?enrollment.{0,260}after the last enrolled (?:user|SID) is removed/i);
    assert.match(windows, /unenrolled (?:account|SID).{0,120}refus/i);
    assert.match(windows, /missing (?:machine )?policy.{0,150}protection failure/i);
    assert.match(windows, /enterprise policy verify.{0,300}enterprise windows (?:reconcile|repair) --profile standalone/i);

    const policy = page('enterprise/configure/machine-policy.mdx');
    assert.match(policy, /configured Claude Code, Codex and Cursor.{0,260}before the first (?:user )?enrollment.{0,260}after the last enrolled (?:user|SID) is removed/i);
    const ownershipOffRow = readFileSync(join(site, 'content/docs/enterprise/configure/machine-policy.mdx'), 'utf8')
      .split('\n').find((line) => line.startsWith('| `off` |'));
    assert.ok(ownershipOffRow);
    assert.match(ownershipOffRow, /Windows.{0,150}Claude Code, Codex and Cursor.{0,180}verified even with zero enrolled users/i);

    const configuration = page('enterprise/configure/configuration.mdx');
    assert.match(configuration, /On Windows.{0,150}ownership.{0,50}off.{0,180}Claude Code, Codex and Cursor.{0,100}machine hooks/i);
    const reference = page('enterprise/configure/reference.mdx');
    assert.match(reference, /configured Claude Code, Codex and Cursor.{0,260}before the first (?:user )?enrollment.{0,260}after the last enrolled (?:user|SID) is removed/i);
  });

  it('describes the installed Windows policy as a product change', () => {
    const changelog = readFileSync(join(repo, 'CHANGELOG.md'), 'utf8');
    assert.match(
      changelog,
      /Windows.{0,160}(?:keeps|retains|remain.{0,40}installed|stays in force).{0,160}(?:no|zero) enrolled users/i,
      'the release note must describe the installed zero-enrollment machine policy',
    );
    assert.doesNotMatch(changelog, /no Claude Code user is enrolled.{0,160}without DefenseClaw hooks/i);
    assert.match(changelog, /before Guardian activation.{0,300}authenticated.{0,150}empty (?:machine )?guards/i);
  });

  it('requires full Windows verification before use after hook executable loss', () => {
    for (const name of [
      'enterprise/configure/machine-policy.mdx',
      'enterprise/install/reference/windows.mdx',
      'enterprise/mdm/intune/windows-reference.mdx',
    ]) {
      const guide = page(name);
      const recovery = /missing hook executable.{0,700}/i.exec(guide)?.[0];
      assert.ok(recovery, `${name} needs missing hook executable recovery guidance`);
      assert.match(recovery, /Claude Code.{0,100}Codex.{0,100}Cursor.{0,100}Copilot/i, `${name} must name every Windows hook executable consumer`);
      assert.match(recovery, /enterprise windows verify --profile standalone --json/i, `${name} needs the full verify command`);
      assert.match(recovery, /(?:before allowing|before resuming) (?:Claude Code|agent) use/i, `${name} must keep agent use stopped until verification passes`);
    }
  });
});

describe('docs claim CI coverage', () => {
  it('runs when any product source read by these checks changes', () => {
    const testSource = readFileSync(fileURLToPath(import.meta.url), 'utf8');
    const dependencies = [...testSource.matchAll(/join\(repo,\s*'([^']+)'/g)].map((match) => match[1]);
    assert.ok(dependencies.includes('scripts/install.ps1'));
    assert.ok(dependencies.includes('cli/defenseclaw/commands/cmd_setup.py'));
    const workflow = readFileSync(join(repo, '.github/workflows/docs-site.yml'), 'utf8');
    for (const [event, next] of [['push', 'pull_request'], ['pull_request', 'workflow_dispatch']]) {
      const paths = workflow.split(`  ${event}:\n`, 2)[1]?.split(`  ${next}:\n`, 1)[0];
      assert.ok(paths, `${event} path triggers not found`);
      const patterns = [...paths.matchAll(/- '([^']+)'/g)].map((match) => match[1]);
      for (const dependency of dependencies) {
        assert.ok(patterns.some((pattern) => pattern === dependency ||
          (pattern.endsWith('/**') && dependency.startsWith(pattern.slice(0, -2)))),
        `${event} does not trigger docs claims for ${dependency}`);
      }
    }
  });
});
