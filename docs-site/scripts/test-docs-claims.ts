import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

// Docs claims and release security requirements. Page checks read the page
// as words, so a reflowed paragraph still matches; source checks tie the
// wording to the CLI and Go paths that implement it.

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(site, '..');
const docs = join(site, 'content/docs');
const hookConnectors = [
  { id: 'claudecode', command: 'claude-code', name: 'Claude Code' },
  { id: 'codex', command: 'codex', name: 'Codex' },
  { id: 'cursor', command: 'cursor', name: 'Cursor' },
  { id: 'devin', command: 'devin', name: 'Devin' },
  { id: 'copilot', command: 'copilot', name: 'Copilot' },
  { id: 'hermes', command: 'hermes', name: 'Hermes' },
  { id: 'antigravity', command: 'antigravity', name: 'Antigravity' },
  { id: 'opencode', command: 'opencode', name: 'OpenCode' },
  { id: 'kiro', command: 'kiro', name: 'Kiro' },
  { id: 'amp', command: 'amp', name: 'Amp' },
] as const;

function page(name: string): string {
  return readFileSync(join(site, 'content/docs', name), 'utf8').split(/\s+/).join(' ');
}

describe('Rollback gateway state', () => {
  it('qualifies automatic startup and names the command for a stopped gateway', () => {
    const text = page('get-started/upgrade.mdx').split('## Rollback')[1].split('## Update notices')[0];
    assert.match(text, /stopped[^.]*stopped/);
    assert.match(text, /`defenseclaw-gateway start`/);
  });
});

function enterprisePages(path = join(site, 'content/docs/enterprise')): string[] {
  return readdirSync(path, { withFileTypes: true }).flatMap((entry) => {
    const child = join(path, entry.name);
    if (entry.isDirectory()) return enterprisePages(child);
    return entry.isFile() && entry.name.endsWith('.mdx') ? [child] : [];
  });
}

function source(name: string): string {
  return readFileSync(join(repo, name), 'utf8');
}

function docsPages(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return docsPages(path);
    return entry.isFile() && /\.mdx?$/.test(entry.name) ? [path] : [];
  });
}

describe('Cursor observe outage mode', () => {
  it('keeps the rendered hook closed unless the config explicitly opens it', () => {
    const hooks = source('internal/gateway/connector/subprocess.go');
    const outage = hooks.split('func OutageHookFailMode(')[1]?.split('\n}')[0] ?? '';
    assert.match(outage, /perUserCursorRender\(opts, conn\)/);
    assert.match(outage, /!strings\.EqualFold\(strings\.TrimSpace\(opts\.ConfiguredHookFailMode\), "open"\)/);
    assert.match(outage, /return "closed"/);
    assert.match(hooks, /func renderedHookFailMode\([\s\S]*?OutageHookFailMode\(opts, conn\)/);
    const failModes = page('reference/configuration/fail-modes.mdx').split('## Controls')[0] ?? '';
    const cursor = page('reference/connectors/cursor.mdx').split('## Fail mode')[1]?.split('## Limits')[0] ?? '';
    assert.match(failModes, /Per-user Cursor in observe mode.{0,100}blocks supported events during a gateway outage by default/i);
    assert.match(cursor, /observe mode.{0,100}blocks supported events on a gateway outage by default/i);
    const coverage = page('appendix/coverage-by-layer.mdx');
    assert.match(coverage, /Per-user Cursor in observe mode.{0,130}running hook blocks supported events during a gateway outage/i);
    assert.match(page('features/guardrail.mdx'), /Per-user Cursor in observe mode still blocks a supported event during a gateway outage/i);
    assert.match(page('reference/commands/installer.mdx'), /Per-user Cursor observe also blocks supported events during a gateway outage/i);
    const managedRegistration = source('internal/gateway/connector/cursor_enterprise_hooks.go');
    assert.match(managedRegistration, /"failClosed": true,/);
    assert.match(page('reference/connectors/cursor.mdx'), /sets `failClosed: true`, so a hook process that never answers blocks the call. The administrator's resolved fail mode decides/i);
    assert.ok(!/per-user Cursor in observe mode fails open/i.test(failModes));

    const overview = page('connectors/cursor.mdx').split('## What it can block or ask')[1]?.split('## Files it changes')[0] ?? '';
    assert.match(overview, /Observe mode.{0,120}policy findings without blocking/i);
    assert.match(overview, /gateway outage.{0,100}blocks supported events by default/i);
    const mapping = page('reference/connectors/cursor.mdx').split('## Verdict mapping')[1]?.split('## Native ask')[0] ?? '';
    assert.match(mapping, /\| Observe \| `failClosed: true` \|[^|]*policy findings[^|]*gateway outage/i);
    assert.ok(!/observe cannot become blocking/i.test(mapping));
  });
});

describe('Observe mode policy findings and gateway outages', () => {
  it('qualifies Antigravity reference verdict mapping for a gateway outage', () => {
    const hooks = source('internal/gateway/connector/subprocess.go');
    assert.match(hooks, /const defaultHookFailMode = "closed"/);
    const antigravity = source('internal/gateway/connector/hooks/antigravity-hook.sh');
    assert.match(antigravity, /PreToolUse\)[\s\S]*?if \[ "\$closed" = "1" \]; then[\s\S]*?"decision":"deny"/);
    const mapping = page('reference/connectors/antigravity.mdx').split('## Verdict mapping')[1]?.split('## Native ask')[0] ?? '';
    assert.match(mapping, /`observe` records policy findings without blocking on those findings/i);
    assert.match(mapping, /default fail mode `closed`.{0,120}gateway is unreachable.{0,80}denies `PreToolUse`/i);
    assert.ok(!/always permits tool execution/i.test(mapping));
  });

  it('does not pair observe with blocks nothing on any content page', () => {
    const content = join(site, 'content');
    const offenders = docsPages(content).flatMap((path) => {
      const paragraphs = readFileSync(path, 'utf8').split(/\n\s*\n/);
      return paragraphs.some((paragraph) => /\bobserve\b[\s\S]*?\bblocks nothing\b/i.test(paragraph))
        ? [path.slice(content.length + 1)] : [];
    });
    assert.deepEqual(offenders, []);
  });

  it('qualifies hook connector claims for Claude Code and Antigravity', () => {
    const outage = source('internal/gateway/connector/subprocess.go').split('func OutageHookFailMode(')[1]?.split('\n}')[0] ?? '';
    assert.match(outage, /return mode/);
    for (const connector of ['claudecode', 'antigravity']) {
      const section = page(`connectors/${connector}.mdx`).split('## What it can block or ask')[1]?.split('## Files it changes')[0] ?? '';
      assert.match(section, /Observe mode.{0,120}policy findings without blocking/i, connector);
      assert.match(section, /default fail mode `closed`.{0,140}gateway is unreachable/i, connector);
    }
  });

  it('qualifies proxy connector claims for OpenClaw and ZeptoClaw', () => {
    assert.match(source('internal/gateway/proxy.go'), /verdict.Action == "block" && mode == "action"/);
    for (const connector of ['openclaw', 'zeptoclaw']) {
      const setup = page(`connectors/${connector}.mdx`).split('## Set up')[1]?.split('## Check it')[0] ?? '';
      assert.match(setup, /Observe records policy findings without blocking on those findings/i, connector);
      assert.match(setup, /gateway outage still stops proxied requests/i, connector);
      assert.match(page(`reference/connectors/${connector}.mdx`), /While the gateway is down, requests are blocked/i, connector);
    }
  });

  it('scopes general guardrail observe guidance to policy findings', () => {
    assert.match(page('features/guardrail.mdx'), /Observe mode does not enforce policy findings/i);
    assert.match(page('features/guardrail.mdx'), /Hook fail mode and proxy availability still apply/i);
    assert.ok(!/\*\*Observe\*\*[^.]*blocks nothing/i.test(page('features/guardrail.mdx')));
    assert.match(page('reference/policy/thresholds.mdx'), /Observe mode does not enforce policy findings/i);
    const commands = source('docs-site/content/docs/reference/commands/cli.mdx');
    const modeRow = commands.split('\n').find((line) => line.startsWith('| `defenseclaw guardrail mode observe')) ?? '';
    assert.match(modeRow, /observe \(logs policy findings without enforcing them\)/i);
    assert.match(modeRow, /Hook fail mode and proxy availability still apply/i);
  });

  it('names the ACP observe failure exception', () => {
    const proxy = source('internal/acp/proxy.go').split('func observeRefuses(')[1]?.split('\n}')[0] ?? '';
    assert.match(proxy, /state\.profileFailsClosed\(\)/);
    assert.match(proxy, /!opts\.Managed/);
    assert.match(proxy, /!state\.sessionFailsOpen\(promptSessionID\(msg\)\)/);
    const guide = page('features/acp-guard.mdx');
    assert.match(guide, /observe mode.{0,100}policy findings without blocking/i);
    assert.match(guide, /standalone managed guard.{0,100}refuses an unevaluated frame by default/i);
  });
});

describe('ZeptoClaw removal', () => {
  it('documents the last-connector gate and the forced removal command', () => {
    const removal = source('cli/defenseclaw/commands/cmd_setup.py').split('# WU8 D2=A — last-connector gate.')[1]?.split('elif not yes')[0] ?? '';
    assert.match(removal, /if not remaining:[\s\S]*?if not force and not unshipped:/);
    assert.match(removal, /Pass --force to fully unconfigure enforcement/);
    const turnOff = page('connectors/zeptoclaw.mdx').split('## Turn it off')[1]?.split('## Details')[0] ?? '';
    assert.match(turnOff, /setup remove zeptoclaw --yes`/);
    assert.match(turnOff, /last connector.{0,100}removal refuses/i);
    assert.match(turnOff, /defenseclaw setup remove zeptoclaw --yes --force/);
  });
});

function mdxPages(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? mdxPages(path) : entry.name.endsWith('.mdx') ? [path] : [];
  });
}

describe('recovery and repair advice', () => {
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
      assert.match(text, /in fail mode `closed`, the default/i, name);
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

describe('Hook connector setup and teardown', () => {
  it('limits the observe default to first setup in every CLI row and connector page', () => {
    const setupCode = source('cli/defenseclaw/commands/cmd_setup.py');
    const alias = setupCode.split('def _setup_observability_alias(')[1]?.split('def _')[0] ?? '';
    assert.match(alias, /mode = gc\.effective_mode\(connector\) if connector in _configured_connector_set\(gc\) else "observe"/);
    assert.match(alias, /if interactive and not mode_from_flag:\s+normalized_mode = _prompt_connector_mode\(connector, default_mode=normalized_mode\)/);
    const reference = readFileSync(join(site, 'content/docs/reference/commands/cli.mdx'), 'utf8');
    for (const { id, command } of hookConnectors) {
      const row = reference.split('\n').find((line) => line.startsWith(`| \`defenseclaw setup ${command}\` |`));
      assert.ok(row, `${id} CLI reference row is missing`);
      assert.match(row, /first setup.*observe|observe.*first setup/i, `${id} CLI row must qualify the default`);
      assert.match(row, /re-run.*keeps the current mode/i, `${id} CLI row must explain reruns`);

      const setup = page(`connectors/${id}.mdx`).split('## Set up')[1]?.split('## Check it')[0];
      assert.ok(setup, `${id} setup section is missing`);
      assert.match(setup, /first setup.*observe|observe.*first setup/i, `${id} page must qualify the default`);
      assert.match(setup, /re-run without `--mode` keeps the current mode/i, `${id} page must explain scripted reruns`);
    }
  });

  it('says what teardown removes and what it preserves on every connector page', () => {
    const guardrailCode = source('cli/defenseclaw/commands/cmd_guardrail.py');
    const sharedTeardown = source('internal/gateway/connector/hook_only.go');
    assert.match(guardrailCode, /def disable_cmd\([\s\S]*?if connector_flag:\s+_toggle_connector_guardrail\(/);
    assert.match(guardrailCode, /gc\.enabled = False[\s\S]*?if restart:[\s\S]*?_restart_services\(/);
    assert.match(sharedTeardown, /func \(c \*hookOnlyConnector\) Teardown\([\s\S]*?c\.teardown\(ctx, opts, ""\)/);
    assert.match(sharedTeardown, /case !restored:[\s\S]*?c\.removeConfigEntriesWithManagedBackup\(/);
    assert.match(sharedTeardown, /if c\.pluginArtifact \{\s+return c\.teardownPluginArtifact\(opts\)/);
    for (const connector of ['cursor', 'devin', 'copilot', 'hermes', 'antigravity', 'opencode', 'amp']) {
      const factory = connector === 'devin' || connector === 'amp'
        ? source(`internal/gateway/connector/${connector}.go`)
        : sharedTeardown;
      assert.match(factory, new RegExp(`name:\\s*"${connector}"`), `${connector} must use the shared teardown`);
    }
    for (const connector of ['claudecode', 'codex', 'kiro']) {
      const implementation = source(`internal/gateway/connector/${connector}.go`);
      assert.match(implementation, /func \(c \*\w+Connector\) Teardown\(/, `${connector} must own its documented teardown`);
    }
    for (const { id, name } of hookConnectors) {
      const turnOff = page(`connectors/${id}.mdx`).split('## Turn it off')[1]?.split('## Details')[0];
      assert.ok(turnOff, `${id} turn-off section is missing`);
      assert.ok(!new RegExp(`This keeps ${name}'s settings`, 'i').test(turnOff), `${id} must not imply hooks stay installed`);
      if (id === 'opencode' || id === 'amp') {
        assert.match(turnOff, /removes? DefenseClaw's plugin/i, `${id} must name plugin removal`);
        assert.match(turnOff, /edited plugin.*(?:is left|is kept)/i, `${id} must explain edited plugins`);
        assert.match(turnOff, /guardrail enable.*(?:restores?|reinstalls?) DefenseClaw's plugin/i, `${id} must explain re-enable`);
      } else {
        assert.match(turnOff, /removes? DefenseClaw(?:'s)? hook/i, `${id} must name hook removal`);
        assert.match(turnOff, /guardrail enable.*(?:restores?|reinstalls?) DefenseClaw(?:'s)? hook/i, `${id} must explain re-enable`);
      }
      assert.match(turnOff, new RegExp(`preserves? (?:your|the) other ${name} settings`, 'i'), `${id} must preserve unrelated settings`);
    }
    const claude = page('connectors/claudecode.mdx').split('## Turn it off')[1]?.split('## Details')[0];
    assert.match(claude ?? '', /removes? DefenseClaw(?:'s)? hooks and OpenTelemetry settings/i);
    const kiro = page('connectors/kiro.mdx').split('## Turn it off')[1]?.split('## Details')[0];
    assert.match(kiro ?? '', /inert stub/i);
  });

  it('distinguishes whole-guardrail --no-restart from connector hot reload', () => {
    const guardrailCode = source('cli/defenseclaw/commands/cmd_guardrail.py');
    const gatewayCode = source('internal/gateway/sidecar.go');
    assert.match(guardrailCode, /def disable_cmd\([\s\S]*?if connector_flag:\s+_toggle_connector_guardrail\(/);
    assert.match(guardrailCode, /def _toggle_connector_guardrail\([\s\S]*?entry\.enabled = bool\(enable\)/);
    assert.match(guardrailCode, /gateway will continue running with the old policy[\s\S]*?until you restart it manually/);
    assert.match(gatewayCode, /guardrailRestart := connectorSetChanged\(oldCfg, newCfg\)/);
    assert.match(gatewayCode, /signalRestart\(s\.guardrailRestartCh\)/);
    const setup = page('connectors/claudecode.mdx').split('## Set up')[1]?.split('## Check it')[0];
    assert.match(setup ?? '', /re-run without `--mode` keeps the current mode/i);
    const turnOff = page('connectors/claudecode.mdx').split('## Turn it off')[1]?.split('## Details')[0];
    assert.match(turnOff ?? '', /whole-guardrail disable.*`--no-restart`.*restart the gateway/i);
    assert.match(turnOff ?? '', /`--connector claudecode`.*`--no-restart`.*running gateway.*(?:at once|without a restart)/i);
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

describe('1.0.4 operator routes and limits', () => {
  it('keeps managed readers off per-user HITL commands', () => {
    const ask = page('how-to/guardrail/ask-before-risky-calls.mdx');
    assert.match(ask, /managed computer.*guardrail\.connectors\.<id>\.hilt/i);
    assert.match(ask, /per-user.*refus/i);
  });

  it('shows the managed OpenCode route', () => {
    const opencode = page('connectors/opencode.mdx');
    assert.match(opencode, /on a managed computer/i);
    assert.match(opencode, /guardrail\.connectors\.opencode/);
    assert.match(opencode, /enterprise policy verify/);
    assert.match(opencode, /\/etc\/opencode\/opencode\.json/);
  });

  it('points managed identity checks to the administrator command', () => {
    const identity = page('enterprise/identity/sources.mdx');
    const childDomain = identity.split('On a managed Linux host, check an account as root:')[1]?.split('### Windows')[0] ?? '';
    const groupRow = readFileSync(join(site, 'content/docs/enterprise/identity/sources.mdx'), 'utf8')
      .split('\n').find((line) => line.startsWith('| A group assignment never matches |')) ?? '';
    assert.match(identity, /administrator runs.*defenseclaw-gateway config validate/);
    assert.match(childDomain, /enterprise linux profile-explain --user/);
    assert.match(childDomain, /\/etc\/defenseclaw\/config\.yaml/);
    assert.match(childDomain, /per-user.*commands refuse/);
    assert.match(groupRow, /per-user install.*defenseclaw guardrail profile explain --user/);
    assert.match(groupRow, /managed Linux.*defenseclaw-gateway enterprise linux profile-explain --user/);
    assert.match(groupRow, /managed macOS.*defenseclaw-gateway enterprise macos profile-explain --user/);
    assert.match(groupRow, /managed Windows.*defenseclaw\.exe.*enterprise windows profile-explain --user/);
  });

  it('uses the managed Windows administrator route instead of a config-only shell', () => {
    const hooks = page('reference/commands/cli.mdx').split('### Per-user hooks (`enterprise hooks`)')[1]?.split('### ACP')[0] ?? '';
    const envVars = page('reference/configuration/env-vars.mdx');
    assert.match(hooks, /On managed Windows.*enterprise windows status.*enterprise windows verify/i);
    assert.match(hooks, /DEFENSECLAW_CONFIG.*alone.*does not.*guardian/i);
    assert.match(envVars, /On managed Windows.*elevated.*enterprise policy show --json.*without setting `DEFENSECLAW_CONFIG`/i);
    assert.doesNotMatch(envVars, /On Windows, set.*\$env:DEFENSECLAW_CONFIG/i);
  });

  it('keeps native-hook warnings and names the managed OpenCode code gap', () => {
    const guard = page('enterprise/configure/foreign-hook-guard.mdx');
    assert.match(guard, /foreign_hooks: report.*enterprise policy show/i);
    assert.match(guard, /Cursor, Copilot and Devin.*defenseclaw-hook.*warning.*file and digest.*stderr/i);
    assert.match(guard, /Hermes.*stderr warning.*without the file and digest/i);
    assert.match(guard, /Amp.*drops.*warnings/i);
    assert.match(guard, /GAP-0697.*OpenCode.*drops.*warnings/i);
  });

  it('gives a working managed restart route without promising it in the refusal', () => {
    const lifecycle = page('enterprise/operate/lifecycle.mdx');
    assert.match(lifecycle, /Windows \| Run the installed release's Setup with `\/repair JSON=1`/);
    assert.doesNotMatch(lifecycle, /the refusal names the commands below/i);
  });

  it('does not promise a Fleet error message that payload inspection cannot reach', () => {
    const fleet = page('reference/edge-connector/configuration.mdx');
    assert.match(fleet, /payload_invalid/);
    assert.match(fleet, /--payload <dir>/);
    assert.doesNotMatch(fleet, /`fleet\.enabled is set but the managed payload has no policy_compiler\.py`/);
  });

  it('matches the Windows Claude Code version floor', () => {
    const machine = page('enterprise/configure/machine-policy.mdx');
    assert.match(machine, /Windows.*2\.1\.219.*2\.1\.163.*2\.1\.218/);
    assert.doesNotMatch(machine, /floor stops no build/);
  });

  it('treats bare off as a YAML portability issue', () => {
    const machine = page('enterprise/configure/machine-policy.mdx');
    assert.doesNotMatch(machine, /bare `off`.*config refuses/);
    assert.match(machine, /Quote `"off"`.*YAML 1\.1/);
  });

  it('distinguishes config validation from OpenShell install checks', () => {
    for (const name of ['enterprise/runtime/sandboxes.mdx', 'enterprise/runtime/sandbox-reference.mdx']) {
      const sandboxes = page(name);
      assert.match(sandboxes, /config validate.*(?:schema|profile).*ensure.*(?:install|pin)/i, name);
      assert.match(sandboxes, /ensure.*install prerequisites.*exact OpenShell.*install: setup/i, name);
      assert.doesNotMatch(sandboxes, /exits 1 where the gateway would refuse/, name);
    }
  });

  it('gives an executable uninstall route after sandbox teardown', () => {
    const uninstall = page('get-started/uninstall.mdx');
    assert.match(uninstall, /If you already ran `defenseclaw sandbox teardown`.*add `--stop-sandboxes`/);
    assert.match(uninstall, /--stop-sandboxes.*running sandboxes/i);
  });

  it('only names Agent360 panels that ship', () => {
    const dashboard = readFileSync(
      join(repo, 'bundles/local_observability_stack/grafana/dashboards/defenseclaw-agent-360.json'),
      'utf8',
    );
    const agent360 = page('reference/observability/dashboards.mdx');
    assert.equal(agent360.includes('Last seen'), dashboard.includes('Last seen'));
  });

  it('omits the retired Omnigent bridge from current receipt paths', () => {
    const agent360 = page('reference/observability/dashboards.mdx');
    assert.doesNotMatch(agent360, /Omnigent policy bridge/i);
  });

  it('pins the workspace route for older Kiro IDEs', () => {
    const kiro = page('connectors/kiro.mdx');
    assert.match(kiro, /before 1\.0\.182.*setup kiro --workspace/i);
    assert.doesNotMatch(kiro, /Set `claw\.workspace_dir` to the project root before setup/);
  });

  it('states that CEL static cost can reject a regex below the size ceiling', () => {
    const engine = page('reference/policy/cel/engine.mdx');
    assert.match(engine, /512-byte CEL regex limit.*static cost limit can reject/i);
  });

  it('runs gateway examples on the pinned Go version through the shard runner', () => {
    for (const name of ['reference/policy/cel/engine.mdx', 'reference/policy/cel/authoring.mdx']) {
      const example = page(name);
      assert.match(example, /Go 1\.26\.4/, name);
      assert.match(example, /go test -timeout 30m \.\/internal\/guardrail\/semantic \.\/internal\/guardrail/, name);
      assert.match(example, /python3 scripts\/go_test_shards\.py --package-dir internal\/gateway --shard-count 16 -- go test -timeout 30m \.\/internal\/gateway/, name);
      assert.doesNotMatch(example, /go test -timeout 30m \.\/internal\/guardrail\/semantic \.\/internal\/guardrail \.\/internal\/gateway/, name);
    }
  });
});
