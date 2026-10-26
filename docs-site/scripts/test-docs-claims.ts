import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
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

describe('Managed custom rule-pack apply', () => {
  it('describes when ensure keeps the gateway running and when it restarts', () => {
    const hotApply = source('internal/enterpriseunix/hotapply.go')
      .split('func (l *lifecycle) hotConfigApply(')[1]?.split('// installedConfigReplaced')[0] ?? '';
    assert.match(hotApply, /l\.opts\.Action != ActionEnsure/);
    assert.match(hotApply, /l\.opts\.NoStart/);
    assert.match(hotApply, /configwrite\.ManagedConfigRestartRequired\(/);
    assert.match(hotApply, /!env\.Services\.Active\(ctx, gateway\)/);
    assert.match(hotApply, /gatewayPolicyDigest\(body\) != ""/);
    const lifecycle = source('internal/enterpriseunix/lifecycle.go');
    assert.match(lifecycle, /hot := l\.hotConfigApply\(ctx, record, p, adopting\)/);
    assert.match(lifecycle, /if gateway, ok := gatewayUnitOf\(units\); hot && ok \{\s*keep\[gateway\.Name\] = true/);
    assert.match(lifecycle, /if !l\.opts\.NoStart \{\s*if err := l\.activate\(ctx, units, restartSockets, hot, p\)/);
    const activate = lifecycle.split('func (l *lifecycle) activate(')[1]?.split('// unitActivationError')[0] ?? '';
    assert.match(activate, /if err := env\.Services\.Start\(ctx, unit\)/);
    const settle = source('internal/enterpriseunix/hotapply.go')
      .split('func (l *lifecycle) settleHotGateway(')[1]?.split('func (', 1)[0] ?? '';
    assert.match(settle, /if applied \{[\s\S]*?gatewayKeptRunning = true/);
    assert.match(settle, /if err := restartUnit\(ctx, env\.Services, gateway\)/);

    const reference = page('enterprise/configure/reference.mdx');
    const customPack = reference.split('### Custom rule packs')[1]?.split('### Network proxy')[0] ?? '';
    assert.match(customPack, /without `--no-start`.{0,250}custom pack switch.{0,250}without a restart/i);
    assert.match(customPack, /gateway was running.{0,250}restarts it/i);
    assert.match(customPack, /gateway was stopped.{0,100}starts it/i);
    assert.match(customPack, /with `--no-start`.{0,100}does not start or restart/i);
    assert.match(customPack, /hot reload cannot be confirmed/i);
    assert.doesNotMatch(customPack, /applies the new pack in the running gateway without a restart/);
  });
});

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
    // The per-user render carries the saved choice or tier fallback in
    // opts.HookFailMode; a managed one resolves the administrator's.
    assert.match(outage, /if perUserOutageRender\(opts\) \{\s*return normalizeHookFailMode\(opts\.HookFailMode\)/);
    assert.match(outage, /return resolveHookFailMode\(opts, conn\)/);
    const resolve = hooks.split('func resolveHookFailMode(')[1]?.split('\n}')[0] ?? '';
    assert.match(resolve, /return defaultHookFailMode/);
    assert.match(hooks, /func renderedHookFailMode\([\s\S]*?OutageHookFailMode\(opts, conn\)/);
    const failModes = page('reference/configuration/fail-modes.mdx').split('## Controls')[0] ?? '';
    const cursor = page('reference/connectors/cursor.mdx').split('## Fail mode')[1]?.split('## Limits')[0] ?? '';
    const perUser = page('reference/configuration/fail-modes.mdx').split('### Per-user installs')[1]?.split('\n## ')[0] ?? '';
    assert.match(perUser, /`default` \(balanced, the out-of-the-box policy\) or `permissive` \| The call runs/i);
    assert.match(perUser, /\| `strict` \(`defenseclaw guardrail use-pack strict`\) \| Block/i);
    assert.match(perUser, /The guardrail mode does not change the outage mode: observe and action mode fail the same way/i);
    assert.match(cursor, /per-user Cursor hook uses an explicit saved outage mode; when unset, its policy tier decides in observe and action mode/i);
    const coverage = page('appendix/coverage-by-layer.mdx');
    assert.match(coverage, /On a per-user install an explicit saved mode wins; when unset, the policy tier decides in observe and action mode alike: default and permissive run the call with a warning/i);
    for (const stale of ['features/guardrail.mdx', 'reference/commands/installer.mdx', 'appendix/coverage-by-layer.mdx']) {
      assert.ok(!/Per-user Cursor (?:in )?observe (?:mode )?(?:still|also) blocks/i.test(page(stale)), stale);
    }
    assert.match(failModes, /On a per-user install, an explicit saved `guardrail\.hook_fail_mode` selects the outage mode.{0,600}Every other failure blocks in every tier/i);
    const managedRegistration = source('internal/gateway/connector/cursor_enterprise_hooks.go');
    assert.match(managedRegistration, /"failClosed": true,/);
    assert.match(page('reference/connectors/cursor.mdx'), /sets `failClosed: true`, so a hook process that never answers blocks the call. The administrator's resolved fail mode decides/i);
    assert.ok(!/per-user Cursor in observe mode fails open/i.test(failModes));

    const overview = page('connectors/cursor.mdx').split('## What it can block or ask')[1]?.split('## Files it changes')[0] ?? '';
    assert.match(overview, /Observe mode.{0,120}policy findings without blocking/i);
    assert.match(overview, /gateway outage lets the call run with a warning in the default and permissive policies and blocks it in strict/i);
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
    // oss-outage-open: a per-user outage follows the policy tier; strict and managed deny it.
    assert.match(mapping, /gateway is not running, a per-user install in the default or permissive policy lets `PreToolUse` run with one warning/i);
    assert.match(mapping, /strict policy and a managed install in the default fail mode `closed` deny it/i);
    assert.ok(!/always permits tool execution/i.test(mapping));
  });

  it('states the per-user outage tier on every hook connector reference page', () => {
    // oss-outage-open review (loop round 2): these pages said a per-user
    // outage blocks by default. The default and permissive policies run it
    // with one warning; strict blocks it.
    for (const connector of ['amp', 'antigravity', 'claudecode', 'codex', 'copilot', 'devin', 'hermes', 'kiro', 'opencode']) {
      const text = page(`reference/connectors/${connector}.mdx`).replace(/\s+/g, ' ');
      assert.match(text, /per-user install.{0,120}?(?:default and permissive|default or permissive) polic(?:y|ies).{0,40}?lets?.{0,80}?run with one warning/i, connector);
      assert.match(text, /strict policy.{0,80}?(?:blocks|denies|deny) it/i, connector);
      assert.ok(text.includes('/docs/reference/apis/capability-matrix#gateway-outage'), connector);
      assert.ok(!/per-user host (?:bridge blocks|failures block)/i.test(text), connector);
      assert.ok(!/even if an older sidecar still says `open`|including when an older sidecar says `open`/i.test(text), connector);
      assert.ok(!/default fail mode `closed`, when the gateway is unreachable the running hook denies/i.test(text), connector);
      assert.ok(!/unless `guardrail\.hook_fail_mode` is `open`\. The default is `closed`/i.test(text), connector);
    }
  });

  it('keeps no per-user fail-mode claim the outage tier replaced on any connector page', () => {
    // oss-outage-open review (loop round 3): the Amp, Hermes and Kiro
    // references (and the Copilot and Antigravity connector pages) still
    // said a per-user gateway failure fails closed by default, or that only
    // an explicit `open` lets a call run. A per-user outage follows the
    // policy tier; a sentence about a fail mode `open` or a `closed` default
    // must name the managed host, the administrator, Secure Client or a
    // sandbox it is about.
    const stale = /explicit `open`|fail mode `open`|With `open`|hook_fail_mode` is `open`|default when no `hook_fail_mode`|fail mode `closed`, the default|per-user gateway failures\b.{0,60}?\bfail closed|per-user (?:host )?hooks? fail closed on gateway failure/i;
    const scoped = /managed|administrator|Secure Client|sandbox|OpenShell/i;
    const offenders = ['reference/connectors', 'connectors'].flatMap((folder) => docsPages(join(docs, folder))
      .flatMap((path) => readFileSync(path, 'utf8').replace(/\s+/g, ' ').split(/(?<=[.|])\s+/)
        .filter((sentence) => stale.test(sentence) && !scoped.test(sentence))
        .map((sentence) => `${relative(docs, path)}: ${sentence.slice(0, 160)}`)));
    assert.deepEqual(offenders, []);
  });

  it('describes the live OSS outage decision in the guide and fail-mode reference', () => {
    const guide = page('connectors/opencode.mdx');
    assert.match(guide, /per-user.*default and permissive.*run with one warning.*strict.*blocks/i);
    const failModes = page('reference/configuration/fail-modes.mdx');
    assert.match(failModes, /reads `config\.yaml` next to its own hooks on each call/i);
    assert.doesNotMatch(failModes, /effective mode is installed with the hooks|A hook's fail mode is the one installed with it|reads only its outage mode from its record/i);
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
    assert.match(outage, /return resolveHookFailMode\(opts, conn\)/);
    for (const connector of ['claudecode', 'antigravity']) {
      const section = page(`connectors/${connector}.mdx`).split('## What it can block or ask')[1]?.split('## Files it changes')[0] ?? '';
      assert.match(section, /Observe mode.{0,120}policy findings without blocking/i, connector);
      assert.match(section, /when the gateway is not running, the default and permissive policies let the call run with one warning(?: and strict|; strict and managed installs) (?:blocks? it|denies `PreToolUse`)/i, connector);
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
  it('describes recovery and data loss for a failed MicroVM', () => {
    const body = page('troubleshooting/sandboxes/runs-and-sessions.mdx');
    const section = body.split('## A sandbox is in OpenShell\'s error state')[1]?.split('## ')[0];
    assert.ok(section, 'error-state troubleshooting section is missing');
    for (const text of ['Docker', 'MicroVM', 'MainProcessFailed', '--end-vm', 'fails with Conflict', 'keep the VM while you need what it holds',
      'defenseclaw sandbox status NAME', 'defenseclaw sandbox stop NAME', 'defenseclaw sandbox delete NAME',
      'deletes it and its work', 'process exited',
      'absent after deletion']) {
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
    assert.ok(upgrade.includes('On OpenShell 0.1.5 or later, `openshell sandbox stop` requests a guest flush'),
      'raw OpenShell stops must name the release that flushes the guest');
    assert.ok(upgrade.includes('gateway older than OpenShell 0.1.5, save its work'),
      'raw OpenShell stops on older gateways need a save-first warning');
    assert.ok(!upgrade.includes('`openshell sandbox stop` does not sync its guest disk'),
      'raw OpenShell stop must not be described as never syncing');
    for (const [name, claim] of [
      ['troubleshooting/sandboxes/setup-and-gateway.mdx', 'last successful disk sync'],
      ['troubleshooting/sandboxes/disk-and-telemetry.mdx', 'last successful disk sync'],
      ['reference/sandboxes/cli.mdx', 'last successful one'],
      ['enterprise/runtime/sandbox-reference.mdx', 'last successful disk sync'],
    ]) {
      assert.ok(page(name).includes(claim), `${name} must qualify what a failed sync preserves`);
    }
  });

  it('keeps legacy guest stop advice aligned with the manager', () => {
    const manager = readFileSync(join(repo, 'internal/openshell/manager/box.go'), 'utf8');
    const autoStops = manager.includes('func (m *Manager) stopOldSupervisor(');
    const userStops = manager.includes('func (m *Manager) reconcileOldSupervisor(');
    assert.notEqual(autoStops, userStops, 'the legacy guest stop mechanism needs an explicit docs check');
    const upgrade = page('troubleshooting/sandboxes/setup-and-gateway.mdx');
    assert.equal(upgrade.includes('It does not stop that legacy guest for you'), userStops,
      'manual legacy-guest stop advice requires the no-auto-stop manager');
    assert.equal(upgrade.includes('run `defenseclaw sandbox stop <name>` yourself'), userStops,
      'manual stop instructions require the no-auto-stop manager');
    assert.equal(upgrade.includes('`connect` refuses until you stop it'), userStops,
      'legacy connect advice must follow the manager behavior');
  });

  it('separates raw MicroVM errors by gateway release and phase reason', () => {
    const body = readFileSync(join(docs, 'troubleshooting/sandboxes/setup-and-gateway.mdx'), 'utf8');
    const section = body.split('## A raw `openshell` sandbox stops a restart or rollback')[1]?.split('## ')[0];
    assert.ok(section, 'raw sandbox restart section is missing');
    for (const text of ['OpenShell 0.1.5', 'ProcessPollFailed', 'openshell sandbox stop NAME',
      'MainProcessFailed', 'ProvisioningTimedOut', 'ProcessExited', 'openshell sandbox delete NAME',
      'older or unknown', 'save its work']) {
      assert.ok(section.includes(text), `raw restart advice must explain ${text}`);
    }
    assert.ok(!section.includes('one that is completed or in its error state: `openshell sandbox delete NAME`'),
      'a stoppable raw error state must not be sent directly to deletion');
    const recoverable = section.split('\n').find((line) => line.includes('completed, or has `MainProcessFailed` on OpenShell 0.1.5 or later'));
    assert.ok(recoverable && recoverable.includes('fails with Conflict') && recoverable.indexOf('save') >= 0 &&
      recoverable.indexOf('save') < recoverable.indexOf('`openshell sandbox delete NAME`') && !recoverable.includes('ends the lingering VM'),
    'a completed raw MicroVM on 0.1.5 cannot start or stop: save first, then delete (GAP-1795)');
    const old = section.split('\n').find((line) => line.includes('completed, or in its error state with a VM still running on a gateway older than 0.1.5'));
    assert.ok(old && old.indexOf('save') < old.indexOf('`openshell sandbox delete NAME`') &&
      !old.includes('`openshell sandbox stop NAME`'),
    'known old gateway must not suggest an impossible stop of an ended MicroVM');
    const uncertain = section.split('\n').find((line) => line.includes('completed, or in its error state with a VM that may still run on an unknown gateway release'));
    assert.ok(uncertain && uncertain.includes('or still does not report the VM stopped') &&
      uncertain.indexOf('may not flush') >= 0 &&
      uncertain.indexOf('may not flush') < uncertain.indexOf('`openshell sandbox stop NAME`') &&
      uncertain.indexOf('`openshell sandbox stop NAME`') >= 0 &&
      uncertain.indexOf('`openshell sandbox stop NAME`') < uncertain.indexOf('`openshell sandbox delete NAME`'),
    'try a raw stop and save accessible work before suggesting deletion when the gateway release is unknown');
    for (const label of ['a raw OpenShell sandbox that is ready', 'a raw OpenShell sandbox in its error state', 'a DefenseClaw sandbox:']) {
      const line = section.split('\n').find((row) => row.startsWith('- ' + label));
      assert.ok(line && line.indexOf('save') >= 0 && line.indexOf('save') < line.indexOf('sandbox stop NAME`'),
        `${label} must name the save-first path before a stop command`);
    }
  });

  it('names the save-first path before upgrade and guest stop commands', () => {
    for (const [name, claim] of [
      ['troubleshooting/sandboxes/setup-and-gateway.mdx', 'save or sync its work first, then `defenseclaw sandbox stop NAME`'],
      ['reference/commands/tui.mdx', 'save or sync each guest’s work first, then stop it with `defenseclaw sandbox stop NAME`'],
      ['reference/sandboxes/cli.mdx', 'Save or sync accessible work first. In copy mode, pull work you need on the host; then stop the guest'],
      ['enterprise/runtime/sandboxes.mdx', 'Users save or pull accessible work first, then stop a running sandbox with `defenseclaw sandbox stop`'],
      ['troubleshooting/sandboxes/runs-and-sessions.mdx', 'Before following a stop step below, save or sync accessible guest work'],
    ] as const) {
      assert.ok(page(name).includes(claim), `${name} must give save-first advice`);
    }
    assert.ok(!page('troubleshooting/sandboxes/setup-and-gateway.mdx').includes('or `defenseclaw sandbox delete NAME` deletes it with its work'),
      'do not advise deleting a DefenseClaw guest with a stop recovery path');
    assert.ok(page('troubleshooting/sandboxes/setup-and-gateway.mdx').includes('save accessible work outside a MicroVM whose VM still runs before deleting it for the upgrade'),
      'legacy MicroVM upgrade summary must put saving work before deletion');
    assert.ok(!page('enterprise/runtime/sandboxes.mdx').includes('and stopped, or deleted'),
      'do not advise deleting a managed guest with a stop recovery path');
    assert.ok(page('reference/commands/tui.mdx').includes('| `U` | Save work you want to keep first, then undo:'),
      'the Undo action must tell users to save work before it stops a running guest');
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

function repoText(name: string): string {
  return readFileSync(join(repo, name), 'utf8').split(/\s+/).join(' ');
}

describe('1.0.4 audit flood and upgrade claims', () => {
  it('describes the WAL hold and alarm actually used by the gateway', () => {
    const wal = page('reference/observability/index.mdx');
    const enterprise = page('troubleshooting/enterprise/index.mdx');
    const changelog = source('CHANGELOG.md').split('- **The audit log catches up during a hook flood on a slow disk')[1]?.split('\n- **')[0] ?? '';
    for (const body of [wal, enterprise, changelog]) {
      assert.match(body, /audit\.db-wal[\s\S]*?176 MiB[\s\S]*?256 MiB/i);
      assert.match(body, /100 ms[\s\S]*?1 second/i);
      assert.match(body, /256 MiB[\s\S]*?warn/i);
      assert.doesNotMatch(body, /at most 2 s|doubles the next one's wait and cap|up to 10 s and 30 s|never wait for it|up to two seconds|up to 30 seconds|over its 1024 MiB bound|stays near 256 MiB under load/i);
    }
    assert.match(source('internal/audit/sqlite_wal_guard.go'), /WALEmergencyArmBytes\s*=\s*WALHardLimitBytes\s*-\s*48\s*<<\s*20/);
    assert.match(source('internal/gateway/audit_wal_guard.go'), /auditWALGuardTriggerBytes\s*=\s*audit\.WALHardLimitBytes\s*-\s*80\s*<<\s*20/);
    assert.match(source('internal/gateway/audit_wal_guard.go'), /auditWALAlarmBytes\s*=\s*auditWALLimitBytes/);
  });

  it('describes bounded Windows WAL catch-up and the remaining hook delay', () => {
    const enterprise = page('troubleshooting/enterprise/index.mdx');
    assert.match(enterprise, /Windows.*audit\.db-wal.*catch-up/i);
    assert.match(enterprise, /176 MiB.*256 MiB/i);
    assert.match(enterprise, /0\.9.to.1\.2 GB.*10 calls a second/i);
    assert.match(enterprise, /hook answers.*(?:slow|wait|delay).*default.*closed/i);
    assert.doesNotMatch(enterprise, /audit\.db-wal.*20 GB|fix needs a change to how the audit store indexes hook records and is deferred/i);
  });

  it('keeps one supervisor upgrade entry with manual stop and guarded restart', () => {
    const changelog = repoText('CHANGELOG.md');
    assert.equal((changelog.match(/\*\*Sandboxes run only on OpenShell 0\.1\.5 or later\.\*\*/g) ?? []).length, 1);
    assert.match(changelog, /DefenseClaw never stops such a sandbox on its own.*Your own `sandbox stop` ends it/);
    assert.doesNotMatch(changelog, /DefenseClaw stops it as soon as it sees it|A stop that fails is a second finding/);
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
      // oss-outage-open: a per-user outage follows the policy tier; every other failure denies.
      assert.match(text, /On a per-user install a gateway that is not running follows the policy tier/i, name);
      assert.match(text, /the strict policy denies it/i, name);
      assert.match(text, /Every other failure DefenseClaw sees \(an unusable answer, a missing token\) is denied/i, name);
      // Oversized input is not an outage: default and permissive judge a bounded review (fail-modes.mdx).
      assert.match(text, /Oversized input is denied on a managed host and in the strict policy/i, name);
    }
    for (const name of ['reference/connectors/antigravity.mdx']) {
      const text = page(name);
      assert.ok(!text.includes('A gateway failure lets the call run'), name);
      assert.ok(!text.includes('normal fail-open operation'), name);
      assert.ok(text.includes('On a managed host the administrator\'s fail mode decides an outage: `closed`, the default, denies it'), name);
      assert.ok(text.includes('Every other failure, an authentication or decoding failure or an unusable answer, denies `PreToolUse`'), name);
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

  it('says an upgrade preserves saved choices, including a 1.0.x Cursor open', () => {
    assert.ok(page('get-started/upgrade.mdx').includes('Per-user hooks honor an explicitly saved outage mode'));
    assert.ok(page('get-started/upgrade.mdx').includes('The upgrade keeps that saved `open`, so strict does not close it'));
    assert.ok(source('cli/defenseclaw/migrations.py').includes('defenseclaw config unset {path}'));
    assert.ok(page('get-started/upgrade.mdx').includes('Every other failure blocks'));
    assert.ok(page('reference/configuration/fail-modes.mdx').includes('`closed` outside Secure Client; `open` under it'));
    assert.ok(page('reference/configuration/fail-modes.mdx').includes('A per-user 1.0.4 hook reads `config.yaml` next to its own hooks on each call'));
    assert.ok(page('reference/configuration/fail-modes.mdx').includes('A per-user (OSS) install honors a saved connector or global'));
  });
});

describe('per-user outage wording on connector pages (rel-1-0-4 GAP-1301, GAP-1317, GAP-1324)', () => {
  it('says the default and permissive policies let an outage call run on Antigravity, Copilot and Devin', () => {
    for (const name of ['connectors/antigravity.mdx', 'reference/connectors/antigravity.mdx', 'reference/connectors/copilot.mdx', 'reference/connectors/devin.mdx']) {
      assert.match(page(name), /default (?:and|or) permissive polic(?:y|ies) lets? (?:the call|`PreToolUse`) run with one warning/i, name);
    }
  });

  it('never opens a Fail mode section with an unqualified closed claim', () => {
    for (const entry of readdirSync(join(docs, 'reference/connectors'))) {
      if (!entry.endsWith('.mdx')) continue;
      const name = `reference/connectors/${entry}`;
      const text = page(name);
      assert.ok(!text.includes('Fail closed: yes'), `${name} still opens with Fail closed: yes`);
      assert.ok(!/closed by default/i.test(text.split('## Fail mode')[1]?.split(' ## ')[0] ?? ''), `${name} Fail mode promises a closed default`);
    }
  });

  it('never says per-user hooks default to closed on any page (GAP-1797)', () => {
    for (const file of enterprisePages(docs)) {
      const text = readFileSync(file, 'utf8').split(/\s+/).join(' ');
      assert.ok(!/per-user hooks? defaults? to closed/i.test(text), `${relative(docs, file)} says per-user hooks default to closed`);
    }
  });
});

describe('admission presets table (rel-1-0-4 GAP-1655)', () => {
  it('gives the shipped default MCP overrides', () => {
    const preset = source('policies/default.yaml').split('scanner_overrides:')[1]?.split('\n  plugin:')[0] ?? '';
    for (const level of ['HIGH', 'MEDIUM', 'LOW']) {
      assert.match(preset, new RegExp(`${level}:\\s*runtime: allow\\s*file: none\\s*install: none`), `default.yaml mcp ${level}`);
    }
    const row = page('reference/policy/defaults.mdx').split('| `scanner_overrides.mcp` |')[1]?.split(' | `scanner_overrides.plugin`')[0] ?? '';
    const cells = row.split('|').map((cell) => cell.trim());
    assert.equal(cells[1], 'HIGH, MEDIUM and LOW install and run (CRITICAL follows `skill_actions.critical`)');
    assert.equal(cells[2], 'MEDIUM blocks and quarantines; LOW disables at runtime');
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
        assert.match(turnOff, /(?:edited plugin.*(?:is left|is kept)|modified (?:the plugin|bridge).*refuse)/i, `${id} must explain edited plugins`);
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

describe('Amp rejected command display', () => {
  it('explains the collapsed summary without treating an attempted call as execution', () => {
    const plugin = source('internal/gateway/connector/hooks/amp-plugin.ts');
    const amp = page('connectors/amp.mdx');
    assert.match(plugin, /case "block":[\s\S]*?action: "reject-and-continue",\s*message: verdict\.reason/);
    assert.match(amp, /Ran 1 command/);
    assert.match(amp, /Tool rejected by plugin/);
    assert.match(amp, /command did not execute/i);
    assert.match(amp, /audit.*block/i);
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
    assert.match(closeHooks, /if \(-not \$unfinished\.Count -and -not \$pending\) \{ return \$false \}/);
    assert.match(closeHooks, /if \(\(Get-InstallGatewayState\) -ne "down"\) \{ return \$false \}/);
    assert.match(closeHooks, /-not \(Test-Path -LiteralPath \(Join-Path \$DataDir "hooks"\) -PathType Container\)/);
    assert.match(closeHooks, /if \(Close-AllHooks \$gateways\)/);
    assert.match(closeHooks, /every agent hook blocks tool calls until the gateway runs again/);
    assert.match(closeHooks, /The install is not finished and the agent hooks could not be closed\. Run the installer again to finish it/);

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
    // rel-1-0-4 GAP-0746: a per-user outage follows the policy tier (perUserOutageMode), as for every agent.
    assert.match(source('internal/gateway/connector/hookexec/hookexec.go'), /func perUserOutageMode\(opts \*Options, failMode string\) string \{/);
    assert.doesNotMatch(windows, /Hermes[^.]*closed by default/i);
    // r105 docs refix 1: outage behaviour is stated only in the capability matrix (Go TestOutageBehaviourIsStatedOnlyInTheCapabilityMatrix).
    assert.match(windows, /Hermes follows the same gateway outage rule as the other agents \(\[gateway outage table\]\(\/docs\/reference\/apis\/capability-matrix#gateway-outage\)\)\. A running DefenseClaw hook blocks every other failure; for a timed-out or killed hook see \[Hermes fail mode\]\(\/docs\/reference\/connectors\/hermes#fail-mode\)\./);
    assert.ok(!windows.includes('Every other failure blocks.'), 'GAP-1796: a killed or timed-out Hermes hook can let the call run');
    assert.doesNotMatch(windows, /stopped gateway lets a Hermes call run/i);
    assert.match(windows, /managed host.*administrator.*open.*gateway outage/i);
    assert.match(windows, /Secure Client.*open.*default/i);
  });
});

describe('Hermes process failure guidance', () => {
  it('scopes timeout and spawn outcomes to the loaded hook contract', () => {
    const entry = /func hermesHookEntry\([^)]*\)[^{]*\{([\s\S]*?)\n\}/
      .exec(source('internal/gateway/connector/hook_only.go'))?.[1];
    assert.ok(entry, 'Hermes Setup registration not found');
    assert.match(entry, /if event == "pre_tool_call" && contractID == "hermes-hooks-v2" && !shellHookSecureClientProfile\(opts\) \{[\s\S]*?entry\["fail_closed"\] = true/);

    const limits = page('connectors/hermes.mdx').split('## Limits')[1]?.split('## On a managed computer')[0] ?? '';
    assert.match(limits, /0\.19\/0\.20.{0,150}times out or cannot start/i);
    assert.match(limits, /reviewed 0\.21 contract.{0,200}`fail_closed: true`.{0,200}timeout or spawn error blocks/i);
    assert.match(limits, /restart.*Hermes host/i);
    assert.match(limits, /killed hook.{0,150}non-2 exit with empty stdout/i);
    assert.doesNotMatch(limits, /Hermes runs the call when a hook times out or cannot start/i);
  });
});

describe('Hermes install-lock attribution', () => {
  it('reports the observed permission error without assigning unproved file ownership', () => {
    const limits = readFileSync(join(docs, 'reference/connectors/hermes.mdx'), 'utf8');
    const lockLine = limits.split('\n').find((line) => line.includes('.install.lock'));
    assert.ok(lockLine, 'Hermes install-lock guidance is missing');
    assert.match(lockLine, /pm-runtime.*install-stamp\.json.*\.install\.lock/);
    assert.match(lockLine, /Inspect the resolved path, owner, and permissions/);
    assert.match(lockLine, /No DefenseClaw verdict was recorded/);
    assert.doesNotMatch(lockLine, /(?:its own|its tools installer|vendor runtime errors)/i);
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

  it('matches Claude Code missing-policy guidance to status and policy verify', () => {
    const enumerator = readFileSync(join(repo, 'internal/enterprisehooks/enumerator_standalone_windows.go'), 'utf8');
    const consequence = /func windowsUnenrolledConsequence\(connector string\) string \{([\s\S]*?)\n\}/.exec(enumerator)?.[1];
    assert.ok(consequence, 'Windows unenrolled-user consequence not found');
    assert.match(consequence, /case "cursor":\s*if !windowsCursorMachinePolicyPublished\(\)/);
    assert.match(consequence, /case "codex":\s*if !windowsCodexMachinePolicyPublished\(\)/);
    assert.doesNotMatch(consequence, /case "claudecode"|windowsClaudeMachinePolicyPublished/);
    assert.match(consequence, /machine-policy hooks refuse this user's tool calls until it is enrolled/);

    const verifier = readFileSync(join(repo, 'internal/enterprisepolicy/claude.go'), 'utf8');
    const verify = /func \(t claudeTarget\) Verify\(opts Options\) \(State, error\) \{([\s\S]*?)\n\}/.exec(verifier)?.[1];
    assert.ok(verify, 'Claude Code policy verification not found');
    assert.match(verify, /if !exists \{\s*state\.conflict\(/);
    assert.match(verify, /state\.finish\(\)/);

    const reference = page('enterprise/configure/reference.mdx');
    const claude = /On Windows, Claude Code's .*?(?= On Windows, the guardian keeps Cursor's)/.exec(reference)?.[0];
    assert.ok(claude, 'Windows Claude Code policy paragraph not found');
    assert.match(claude, /status.*does not name a missing Claude Code machine policy/i);
    assert.match(claude, /enterprise policy verify.*fails.*missing machine hook/i);
    assert.match(claude, /Stop Claude Code use.*repair.*verify.*passes/i);
    assert.doesNotMatch(claude, /status.*names missing policy/i);
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

describe('1.0.4 operator routes and limits', () => {
  it('keeps the TUI host-port ask row aligned with the UI and sandbox guide', () => {
    const tui = source('docs-site/content/docs/reference/commands/tui.mdx');
    const asksRow = tui.split('\n').find((line) => line.startsWith('| Asks |')) ?? '';
    const ui = source('cli/defenseclaw/tui/services/sandbox_state.py');
    const sandboxGuide = page('reference/sandboxes/cli.mdx');
    const manager = source('internal/openshell/manager/hostport.go');
    assert.match(ui, /A port on this machine asks only if the run named it [^\n]*\n[^\n]*with --host-port PORT; approve that ask to open the port/);
    assert.match(sandboxGuide, /A `--host-port` port reads `asks` until you approve its first connection/);
    assert.match(manager, /func \(m \*Manager\) hostPortAsk\(/);
    assert.match(asksRow, /A port on this machine asks only if the run named it with `--host-port PORT`; approve that ask to open the port\./);
    assert.doesNotMatch(asksRow, /port on this machine never asks/i);
  });

  it('derives the MCP-description YARA signature count from the shipped rules', () => {
    const rules = readFileSync(join(repo, 'policies/yara/mcp-tools/description_injection.yara'), 'utf8');
    const count = (rules.match(/^rule\s+\w+/gm) ?? []).length;
    assert.ok(count > 0, 'no bundled MCP-description YARA rules found');
    const words = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine',
      'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen'];
    const expected = words[count] ?? String(count);
    assert.match(page('reference/policy/detection.mdx'), new RegExp(`\\b${expected} MCP-description YARA signatures\\b`));
  });

  it('states that unknown connectors make profile explain fail with valid names', () => {
    const thresholds = page('reference/policy/thresholds.mdx');
    assert.match(thresholds, /profile explain.*unknown connector.*(?:HTTP 400|400 Bad Request).*valid connectors/i);
    assert.doesNotMatch(thresholds, /unknown connector.*(?:uses|falls back to|resolves to) (?:the )?(?:default|global) (?:profile|threshold)/i);
  });

  it('limits proxy replacement to Linux and macOS', () => {
    const agents = page('how-to/agents/add-or-remove-an-agent.mdx');
    assert.match(agents, /setup openclaw --replace.*Linux and macOS.*native Windows.*(?:unsupported|no guardrail proxy)/i);
  });

  it('aligns the TUI footer and status Policy line with the applied config counter', () => {
    const tui = page('reference/commands/tui.mdx');
    const cli = page('reference/commands/cli.mdx').split('### Policy generation and digest')[1]?.split('### ')[0] ?? '';
    assert.match(tui, /`gen`.*config\.generation\.json.*(?:survives|persists).*gateway restart/i);
    assert.doesNotMatch(tui, /`gen` is the gateway's policy generation|restarts at 1 when the gateway starts/i);
    assert.match(tui, /Policy line.*same.*policy\.config_generation.*config generation N/i);
    assert.match(tui, /per-user.*applied hand edit.*(?:moves|increments).*counter/i);
    assert.doesNotMatch(tui, /prints a different, gateway-local policy generation|hand edit can change the policy digest without moving/i);
    assert.match(cli, /Policy:.*config generation 2/i);
    assert.match(cli, /plain `defenseclaw status`.*policy\.config_generation.*TUI footer/i);
    assert.match(cli, /separate `policy\.generation`.*restarts at 1/i);
    assert.match(cli, /per-user.*hand edit.*(?:next|moves|increments).*config generation/i);
    assert.doesNotMatch(cli, /The generation number is the gateway's own counter and restarts at 1/i);
  });

  it('does not promise enrollment for an extension without an engine version', () => {
    const enrollment = page('enterprise/configure/enrollment.mdx');
    assert.match(enrollment, /extension.*engine version.*(?:no engine version|without an engine version).*surface_unverified.*not enrolled/i);
    assert.match(enrollment, /Codex.*Windows.*reported.*not enrolled/i);
    const risk = repoText('docs/ENTERPRISE-THREAT-MODEL.md').split('| R25 |')[1]?.split('| R26 |')[0] ?? '';
    assert.match(risk, /engine version.*surface_unverified.*not enrolled/i);
    assert.doesNotMatch(risk, /enrollment finds an agent only through its CLI install/i);
  });

  it('ties threat-model B17 to the installed hook fail mode', () => {
    const row = source('docs/ENTERPRISE-THREAT-MODEL.md')
      .split('\n').find((line) => line.startsWith('| B17 |')) ?? '';
    const hook = source('internal/gateway/connector/hooks/_hardening.sh');
    assert.match(hook, /DEFENSECLAW_FAIL_MODE in the agent's environment is not[\s\S]*?read/);
    assert.match(row, /DEFENSECLAW_FAIL_MODE.*1\.0\.4 hooks do not read.*installed.*mode/i);
    assert.doesNotMatch(row, /DEFENSECLAW_FAIL_MODE[^|]*honored only when stricter/i);
  });

  it('describes the managed Unix hook socket directory and listener checks', () => {
    const transport = source('internal/gateway/connector/hookexec/managed_standalone_transport.go');
    const row = source('docs-site/content/docs/troubleshooting/enterprise/index.mdx')
      .split('\n').find((line) => line.startsWith('| `enterprise_managed_gateway_peer_unverified` |')) ?? '';
    assert.match(transport, /hook socket directory .* is not owned by root or the gateway service account/);
    assert.match(transport, /hook socket listener uid .* is neither root nor the gateway service uid/);
    assert.match(row, /Linux and macOS:.*socket directory.*root or the gateway account.*listener UID.*kernel/i);
    assert.doesNotMatch(row, /hook socket is not owned by root or the gateway account/);
  });

  it('does not advertise local files as MCP scan targets', () => {
    const api = page('reference/apis/gateway-api.mdx');
    assert.match(api, /`POST`\s*\|\s*`\/v1\/mcp\/scan`[^\n]*Path or JSON-file targets[^\n]*HTTP 400[^\n]*bare identifier without path or file syntax[^\n]*configured server name/i);
    assert.doesNotMatch(api, /MCP scanner against a target URL or local path/i);
  });

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

  it('uses the installed standalone administrator route on every OS', () => {
    const hooks = page('reference/commands/cli.mdx').split('### Per-user hooks (`enterprise hooks`)')[1]?.split('### ACP')[0] ?? '';
    const envVars = page('reference/configuration/env-vars.mdx');
    const policy = source('internal/cli/enterprise_policy.go');
    const unixPin = source('internal/cli/enterprise_policy_platform_unix.go');
    assert.match(policy, /pinStandaloneManagedEnv\(\)/);
    assert.match(unixPin, /managedStandaloneAdminDeployment\(\)/);
    assert.match(unixPin, /managed\.ConfigPathEnv:\s+layout\.ConfigPath/);
    assert.match(unixPin, /"DEFENSECLAW_HOME":\s+layout\.DataDir/);
    assert.match(envVars, /On standalone managed Linux and macOS.*without setting `DEFENSECLAW_CONFIG`/is);
    assert.match(envVars, /sudo \/opt\/defenseclaw\/bin\/defenseclaw-gateway enterprise policy show --json/);
    assert.match(envVars, /sudo \/opt\/cisco\/defenseclaw\/bin\/defenseclaw-gateway enterprise policy show --json/);
    assert.doesNotMatch(envVars, /sudo DEFENSECLAW_CONFIG=.*enterprise policy show --json/);
    assert.match(hooks, /On managed Windows.*enterprise windows status.*enterprise windows verify/i);
    assert.match(hooks, /DEFENSECLAW_CONFIG.*alone.*does not.*guardian/i);
    assert.match(envVars, /On managed Windows.*elevated.*enterprise policy show --json.*without setting `DEFENSECLAW_CONFIG`/i);
    assert.doesNotMatch(envVars, /On Windows, set.*\$env:DEFENSECLAW_CONFIG/i);
  });

  it('keeps native-hook warnings and gives plugin readers a working report route', () => {
    const guard = page('enterprise/configure/foreign-hook-guard.mdx');
    assert.match(guard, /foreign_hooks: report.*enterprise policy show/i);
    assert.match(guard, /Cursor, Copilot and Devin.*defenseclaw-hook.*warning.*file and digest.*stderr/i);
    assert.match(guard, /Hermes.*stderr warning.*without the file and digest/i);
    assert.match(guard, /OpenCode and Amp.*enterprise policy show.*file and digest/i);
    assert.doesNotMatch(guard, /GAP-0697|(?:OpenCode|Amp).*drops.*warnings/i);
  });

  it('gives managed profile-explain routes in every identity troubleshooting row', () => {
    const rows = readFileSync(join(site, 'content/docs/enterprise/identity/sources.mdx'), 'utf8')
      .split('\n').filter((line) => line.startsWith('| ') && /profile explain/.test(line));
    assert.ok(rows.length >= 4, 'identity troubleshooting rows are missing');
    for (const row of rows) {
      assert.match(row, /managed.*enterprise .*profile-explain/i, row);
    }
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

  it('states the kiro-cli setup floor from the connector (GAP-1402)', () => {
    assert.ok(source('internal/gateway/connector/kiro.go').includes('const KiroCLIHookFloor = "2.27.1"'));
    assert.ok(page('reference/connectors/kiro.mdx').includes('it needs 2.27.1 or later (`KiroCLIHookFloor`)'));
    assert.ok(!page('reference/connectors/kiro.mdx').includes('per-user installs are not version-gated'));
  });

  it('describes the per-user fail-mode setter the CLI accepts (GAP-1411, GAP-1601)', () => {
    const cmd = source('cli/defenseclaw/commands/cmd_guardrail.py');
    assert.ok(cmd.includes('"On a per-user install an explicit saved mode wins. When unset, the gateway-outage mode follows the "'));
    const cli = page('reference/commands/cli.mdx');
    assert.ok(!cli.includes('so a value is refused with exit 1'));
    assert.ok(cli.includes('`open` or `closed` saves your choice, which wins over the policy tier'));
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

describe('agent identity rows (rel-1-0-4 GAP-0596)', () => {
  it('documents every JSON field the row has, on every OS', () => {
    const record = source('internal/inventory/agent_identity_store.go');
    const api = page('reference/apis/gateway-api.mdx');
    for (const field of ['upn', 'subagents_seen', 'last_subagent_id']) {
      assert.ok(new RegExp('json:"' + field + '[,"]').test(record), `AgentIdentityRecord has no ${field} JSON field`);
      assert.ok(api.includes(`"${field}":`), `the agents/identities example shows no ${field}`);
      assert.ok(api.includes(`\`${field}\``), `the agents/identities text does not explain ${field}`);
    }
    assert.ok(api.includes('Linux, macOS and Windows rows carry the same fields'));
  });

  it('explains when a cold Windows AD UPN reaches an existing row', () => {
    const identity = source('internal/gateway/agent_identity.go');
    const recorder = source('internal/gateway/agent_identity_recorder.go');
    const store = source('internal/inventory/agent_identity_store.go');
    const windows = source('internal/gateway/identity_resolve_windows.go');
    const cache = source('internal/gateway/identity_directory_cache.go');
    const ad = source('internal/useridentity/directory_windows_facts.go');
    const spool = source('internal/enterprisehooks/identity_spool_windows.go');
    assert.match(identity, /func agentIdentityAccountUPN\(userID string\) \(upn string, known bool\)[\s\S]*?peerDirectoryCache\(\)\.peekCurrent\(userID\)/);
    assert.ok(identity.includes('readIdentitySpoolFacts(userID, time.Now())'));
    assert.ok(cache.includes('!entry.failedSince.IsZero()'));
    assert.ok(cache.includes('entry.fetchedAt.Add(c.lifetime(entry.facts))'));
    assert.ok(ad.includes('return entry.kept || entry.superseded || entry.upn != upn'));
    assert.ok(spool.includes('KeepLastKnownUPN(record, entry.previous)'));
    assert.ok(identity.includes('if record.UPNKept() {'));
    assert.ok(identity.includes('if facts.UPNKept {'));
    assert.match(windows, /wait := time\.Duration\(0\)[\s\S]*?if identityLookupBlocking\.Load\(\)/);
    assert.ok(recorder.includes('sighting := agentIdentityUPN{read: facts.UPNRead, upn: facts.UserUPN, unavailable: facts.UPNUnavailable}'));
    assert.ok(recorder.includes('rec.UPN, rec.UPNUnavailable = sighting.upn, sighting.unavailable'));
    assert.ok(recorder.includes('rec.UPN = buffered.UPN'));
    assert.ok(store.includes('user_upn = excluded.user_upn'));

    const api = page('reference/apis/gateway-api.mdx');
    const upn = api.slice(api.indexOf('`upn` is the account'), api.indexOf('`total` counts'));
    assert.ok(upn.includes('current Windows guardian record takes precedence'));
    assert.ok(upn.includes('an expired or failed directory answer omits'));
    assert.ok(upn.includes('profile matching still uses the last good UPN'));
    assert.ok(upn.includes('an earlier value is not carried into the row'));
    assert.ok(upn.includes('A completed background lookup does not update the row by itself; another hook must run'));

    const reference = page('enterprise/identity/reference.mdx');
    assert.ok(reference.includes('another hook runs after the directory cache has a current UPN'));
    assert.ok(reference.includes('profile matching still uses that last good UPN'));
    assert.ok(reference.includes("Each hook replaces the row's UPN"));
  });
});

describe('Windows AD UPN outage wording', () => {
  it('keeps policy continuity separate from current identity rows', () => {
    const sources = page('enterprise/identity/sources.mdx');
    const row = sources.split('| AD UPN |')[1]?.split('| Verified |')[0];
    assert.ok(row, 'the Windows AD UPN source row is missing');
    assert.ok(row.includes('the last good answer is kept during the outage for profile matching'), 'the outage policy behavior is missing');
    assert.ok(row.includes('Agent identity rows leave that kept UPN out'), 'the current row behavior is missing');
    // GAP-0129 and GAP-0284: the cache and the guardian keep the last good UPN.
    const ad = source('internal/useridentity/directory_windows_facts.go');
    // A failed newest lookup keeps the last good answer, marked kept, for the failure TTL.
    assert.match(ad, /kept: [\w.]+ != "", expires: c\.now\(\)\.Add\(adUPNFailureTTL\)/);
    const spool = source('internal/enterprisehooks/identity_spool.go');
    assert.ok(spool.includes('record.Facts.UPN = previous.Facts.UPN'));
    assert.ok(spool.includes('func MarkWindowsKeptUPN('));
    const changelog = source('CHANGELOG.md');
    assert.ok(changelog.includes('Profile matching is unchanged'));
    assert.ok(changelog.includes('rows leave out that kept UPN'));
  });
});

describe('managed launcher refusal on every page (GAP-1387, GAP-1569)', () => {
  it('quotes launcherRefusal wherever a page quotes the refusal', () => {
    const refusal = /launcherRefusal = "([^"]+)"/.exec(source('internal/cli/launcher.go'))?.[1];
    assert.ok(refusal, 'launcher refusal not found');
    let quoted = 0;
    for (const file of enterprisePages(docs)) {
      const text = readFileSync(file, 'utf8').split(/\s+/).join(' ');
      assert.ok(!text.includes('commands are available here'), `${relative(docs, file)} quotes the retired launcher refusal`);
      if (text.includes(refusal)) quoted += 1;
    }
    assert.ok(quoted >= 10, `expected the launcher refusal on at least 10 pages, found ${quoted}`);
  });
});

describe('the TUI page on a managed computer (rel-1-0-4 GAP-0597)', () => {
  it('quotes the launcher refusal and links the managed-device steps', () => {
    const refusal = /launcherRefusal = "([^"]+)"/.exec(source('internal/cli/launcher.go'));
    assert.ok(refusal, 'launcher refusal not found');
    const tui = page('features/tui.mdx');
    assert.ok(tui.includes(refusal[1]), 'features/tui.mdx does not quote the launcher refusal');
    assert.ok(tui.includes('/docs/reference/commands/tui#on-a-managed-device'));
    assert.ok(page('reference/commands/tui.mdx').includes('#### On a managed device'));
  });
});

describe('Windows event log check (rel-1-0-4 GAP-0598)', () => {
  it('names enterprise windows events and each of its flags', () => {
    const command = source('internal/cli/windows_enterprise_event_check.go');
    assert.ok(command.includes('Use:   "events"'));
    const flags = [...command.matchAll(/Flags\(\)\.\w+Var\(&\w+, "([a-z-]+)"/g)].map((match) => match[1]);
    assert.deepEqual(flags.sort(), ['application', 'json', 'max']);
    const operations = page('enterprise/operate/operations.mdx');
    assert.ok(operations.includes('enterprise windows events'), 'operations.mdx does not name enterprise windows events');
    for (const flag of flags) {
      assert.ok(operations.includes(`--${flag}`), `operations.mdx does not explain --${flag}`);
    }
    assert.ok(command.includes('within two minutes') && operations.includes('within two minutes'));
    assert.ok(page('reference/commands/cli.mdx').includes('| `events` | Standalone |'));
  });
});

describe('Hermes tool-call state (rel-1-0-4 GAP-0599)', () => {
  it('keeps committed steps across the per-turn on_session_end, as the contract does', () => {
    const contracts = JSON.parse(source('cli/defenseclaw/inventory/hook_contracts.json')) as {
      connectors: Record<string, { contracts: { contract_id: string; tool_call_lifecycle: Record<string, unknown> }[] }>;
    };
    for (const contract of contracts.connectors.hermes.contracts) {
      const lifecycle = contract.tool_call_lifecycle;
      assert.equal(lifecycle.stateful_enforcement_level, 'paired-outcomes', contract.contract_id);
      assert.deepEqual(lifecycle.authoritative_pending_discard_events, ['on_session_end'], contract.contract_id);
      assert.ok(!(lifecycle.authoritative_terminal_events as string[]).includes('on_session_end'), contract.contract_id);
    }
    const state = page('reference/policy/cel/tool-call-state.mdx');
    assert.ok(state.includes('Hermes `on_session_end` (which Hermes sends at the end of every turn'));
    assert.ok(/\| \[Hermes\][^\n]*\| `paired-outcomes` \|/.test(readFileSync(join(site, 'content/docs/reference/policy/cel/tool-call-state.mdx'), 'utf8')));
  });
});

// Lead and owner decisions in plans/r104/P1-RECONCILE.md turned these gaps
// into known limits. Each must keep its own entry on the known-limits page,
// and each connector page must link to it. The source checks pin the claim
// that the refusal text is the vendor's, not DefenseClaw's.
const knownLimitEntries = [
  {
    gaps: 'GAP-1196, GAP-1240',
    section: 'Codex',
    phrases: ['`rm -f style commands are not permitted. Use a safer approach`', 'It is a Codex limit, not a DefenseClaw block', 'Run the cleanup yourself in a terminal.'],
    from: ['connectors/codex.mdx'],
  },
  {
    gaps: 'GAP-0794, GAP-1006',
    section: 'Codex',
    phrases: ['Codex runs the tool when its `PreToolUse` hook is stopped, killed or times out.', 'If the hook stopped before it reached the gateway', 'If it reached the gateway first, the gateway can still record the call', 'It does not prevent a timeout', '`hook_process_fail_open`', '/docs/enterprise/configure/reference#vendor-limits'],
    from: ['connectors/codex.mdx'],
  },
  {
    gaps: 'GAP-1222',
    section: 'Copilot CLI',
    phrases: ['`Session host did not acknowledge permission.requested delivery within 5 seconds`', 'It is a Copilot CLI limit.', 'quit Copilot and start a new session'],
    from: ['connectors/copilot.mdx'],
  },
  {
    gaps: 'the approved Copilot CLI hook-timeout limit',
    section: 'Copilot CLI',
    phrases: ["Copilot CLI runs the tool when its `preToolUse` hook times out or cannot start, even when DefenseClaw's fail mode is `closed`.", 'per-user and managed installs on every OS', 'If it reached the gateway first, the gateway can still record the call', '`hook_process_fail_open`', '/docs/enterprise/configure/reference#vendor-limits'],
    from: ['connectors/copilot.mdx'],
  },
  {
    gaps: 'the approved Antigravity hook-timeout limit',
    section: 'Antigravity',
    phrases: ["Antigravity can run a tool when its `PreToolUse` hook times out or cannot start, even when DefenseClaw's fail mode is `closed`.", 'every install on every OS', 'If it reached the gateway first, the gateway can still record the call', '`hook_process_fail_open`'],
    from: ['connectors/antigravity.mdx'],
  },
  {
    gaps: 'GAP-1164',
    section: 'Linux sign-out',
    phrases: ['Without linger, signing out of your last session stops the gateway and its MicroVMs', 'This is how systemd works', '`sudo loginctl enable-linger USER`', '/docs/troubleshooting/sandboxes/setup-and-gateway#a-linux-sign-out-ends-a-running-microvm'],
    from: [],
  },
  { gaps: 'GAP-1194', section: 'Claude Code shell', phrases: ['shell mode', 'on every OS, to per-user and managed installs, in observe and action mode', 'It is a Claude Code limit'], from: ['connectors/claudecode.mdx'] },
  { gaps: 'GAP-1163', section: 'Upgrade and policy limits', phrases: ['**Legacy MicroVM guests:**'], from: [] },
  {
    gaps: 'GAP-0716, GAP-0716-MAC, GAP-0716-WIN',
    section: 'Upgrade and policy limits',
    phrases: ['**Managed policy before launch:**', 'on managed Linux, macOS and Windows', 'a process device map on Windows', 'This is an operating system limit', '`unprivileged_user_namespaces`', '`user.max_user_namespaces=0`', '/docs/enterprise/install/reference/linux#user-namespaces', '/docs/enterprise/install/reference/macos#machine-policy', '/docs/enterprise/install/reference/windows#inspect-machine-policy'],
    from: [],
  },
  {
    gaps: 'GAP-0565',
    section: 'Codex',
    phrases: ['the `Sandbox ready` step', '`approval required by policy, but AskForApproval::Granular.sandbox_approval is false`', 'Codex does this with or without DefenseClaw', 'It is a Codex limit.', 'Quit Codex and start it again once'],
    from: ['connectors/codex.mdx', 'reference/connectors/codex.mdx'],
  },
  { gaps: 'GAP-1110', section: 'Local Splunk', phrases: ['works only with an x86_64 Docker engine', 'published for x86_64 (amd64) only', 'This is a Splunk image limit.', '/docs/how-to/observability/send-to-splunk#before-you-start'], from: [] },
  { gaps: 'GAP-1565', section: 'Upgrade and policy limits', phrases: ['**Restored hook records on managed macOS:**', '`hook_contract_lock.json`', 'the guardian and gateway rewrite them at the next check', 'compare the hook commands, not the file bytes'], from: [] },
  { gaps: 'GAP-0999', section: 'Sandboxes', phrases: ['**Raw OpenShell during a gateway restart:**', 'OpenShell has no admission barrier that raw clients honor', 'one started after the last check is ended by the restart', 'This is an OpenShell limit.', '/docs/troubleshooting/sandboxes/setup-and-gateway#a-raw-openshell-sandbox-stops-a-restart-or-rollback'], from: [] },
  { gaps: 'GAP-1177', section: 'Sandboxes', phrases: ['**No network cutoff for a contained MicroVM:**', 'the VM stays reported as unprotected and new DefenseClaw runs are refused', 'OpenShell has no VM pause or network-off operation', 'This is an OpenShell and platform limit.', '/docs/troubleshooting/sandboxes/setup-and-gateway#a-contained-vm-has-no-confirmed-network-withdrawal'], from: [] },
] as const;

function knownLimitSection(heading: string): string {
  const raw = readFileSync(join(docs, 'troubleshooting/known-limits.mdx'), 'utf8');
  const parts = raw.split(/^## /m);
  const body = parts.find((part) => part.split('\n')[0].trim() === heading);
  assert.ok(body, `known-limits.mdx has no "## ${heading}" section`);
  return body.split(/\s+/).join(' ');
}

function anchor(heading: string): string {
  return heading.toLowerCase().replace(/[^a-z0-9 -]/g, '').trim().replace(/ +/g, '-');
}

function trackedProductHits(text: string): string[] {
  try {
    return execFileSync('git', ['grep', '-l', '-F', text, '--', '.', ':!docs-site', ':!docs'], { cwd: repo, encoding: 'utf8' })
      .split('\n').filter(Boolean);
  } catch (error) {
    if ((error as { status?: number }).status === 1) return [];
    throw error;
  }
}

describe('Known limits by lead decision (rel-1-0-4 P1 reconcile)', () => {
  for (const entry of knownLimitEntries) {
    it(`documents ${entry.gaps} under "${entry.section}" and links it from the connector page`, () => {
      const text = knownLimitSection(entry.section);
      for (const phrase of entry.phrases) {
        assert.ok(text.includes(phrase), `known-limits "${entry.section}" lacks: ${phrase}`);
      }
      const target = `/docs/troubleshooting/known-limits#${anchor(entry.section)}`;
      for (const name of entry.from) {
        const limits = page(name).split('## Limits')[1]?.split(' ## ')[0] ?? '';
        assert.ok(limits.includes(target), `${name} Limits does not link ${target}`);
      }
    });
  }

  it('keeps the page title free of a release number', () => {
    const raw = readFileSync(join(docs, 'troubleshooting/known-limits.mdx'), 'utf8');
    assert.match(raw, /^title: Known limits$/m);
    for (const name of ['troubleshooting/index.mdx', 'connectors/codex.mdx', 'connectors/copilot.mdx']) {
      assert.ok(!page(name).includes('Known limits in 1.0'), `${name} names an old release in the known-limits link`);
    }
  });

  it('lists every section in the troubleshooting index summary', () => {
    const index = page('troubleshooting/index.mdx');
    const line = index.split('[Known limits](/docs/troubleshooting/known-limits):')[1]?.split(' - [')[0] ?? '';
    for (const words of ['Codex', 'Copilot CLI', 'Antigravity', 'Linux sign-out', 'sandboxes', 'scanners on macOS', 'identity', 'agent messages that are not from DefenseClaw']) {
      assert.ok(line.includes(words), `troubleshooting index summary omits ${words}`);
    }
  });

  it('keeps the vendor refusal text out of DefenseClaw source', () => {
    for (const text of ['style commands are not permitted', 'did not acknowledge permission.requested', 'Granular.sandbox_approval is false']) {
      assert.deepEqual(trackedProductHits(text), [], `DefenseClaw source emits "${text}"; it is not a vendor limit`);
    }
  });

  it('names the Linux namespace warning the product emits (GAP-0716)', () => {
    assert.ok(source('internal/enterpriseunix/userns.go').includes('codeUserNamespaces               = "unprivileged_user_namespaces"'));
    // GAP-1763: the ptrace variant of the same class.
    assert.ok(source('internal/enterpriseunix/userns.go').includes('codeUnprivilegedPtrace           = "unprivileged_ptrace"'));
    assert.ok(source('internal/enterpriseunix/userns.go').includes('kernel.yama.ptrace_scope=2'));
  });

  it('matches the managed hook_process_fail_open warning for Codex, Copilot and Antigravity', () => {
    const status = source('internal/enterprisestatus/hook_process_failure.go');
    assert.ok(status.includes('CodeHookProcessFailOpen = "hook_process_fail_open"'));
    assert.match(status, /case "claudecode", "codex":\s*behavior = "a killed PreToolUse hook or PreToolUse timeout is non-blocking"/);
    assert.match(status, /case "copilot":\s*behavior = "a timed-out preToolUse hook is non-blocking; a later permission hook may still deny"/);
    assert.match(status, /case "antigravity":\s*behavior = "a command hook that cannot start or reaches its timeout has no vendor-guaranteed deny"/);
    assert.match(status, /r\.SecurityComplete = false/);
  });

  // A hook that times out may already have reached the gateway, which can then
  // record the call. Every timeout entry must keep the "no audit row" claim to
  // hooks that never reached it, and must not offer signal protection as a cure
  // for timeouts.
  it('scopes every hook-timeout entry on the page', () => {
    const raw = readFileSync(join(docs, 'troubleshooting/known-limits.mdx'), 'utf8');
    const entries = raw.split(/\n(?=- |\n)/).map((part) => part.split(/\s+/).join(' '))
      .filter((part) => /\btimes? out\b|\btimed-out\b/.test(part) && /hook/.test(part));
    assert.ok(entries.length >= 3, `expected the Codex, Copilot CLI and Antigravity timeout entries, found ${entries.length}`);
    for (const entry of entries) {
      assert.ok(!/never reaches the gateway/.test(entry), `unscoped no-request claim: ${entry.slice(0, 120)}`);
      if (/no pre-tool audit row/.test(entry)) {
        assert.match(entry, /If the hook (never reached|stopped before it reached) the gateway/, `no-audit claim is not scoped: ${entry.slice(0, 120)}`);
        assert.ok(entry.includes('If it reached the gateway first, the gateway can still record the call'), `reached-gateway case missing: ${entry.slice(0, 120)}`);
      }
      if (/signall?ing hook processes/.test(entry)) {
        assert.ok(entry.includes('It does not prevent a timeout'), `signal protection offered as a timeout fix: ${entry.slice(0, 120)}`);
      }
    }
  });
});
// 1.0.5 docs rows (r105 docs group): one row per gap. `section` is a "## "
// heading of the page; the row reads only that section and its subsections.
type DocRow = { gap: string; page: string; section?: string; has?: string[]; lacks?: string[] };
const r105Rows: DocRow[] = [
  { gap: "GAP-1795", page: "troubleshooting/known-limits.mdx", section: "Upgrade and policy limits", has: ["fails with Conflict and leaves it starting", "keep the VM while you need what it holds"], lacks: ["can use `defenseclaw sandbox start NAME --end-vm`, then stop it"] },
  { gap: "GAP-1795", page: "troubleshooting/sandboxes/setup-and-gateway.mdx", has: ["fails with Conflict and leaves it starting"], lacks: ["`start NAME --end-vm` starts it", "or on 0.1.5 start it with `--end-vm`", "can refuse the recovery above", "ends the lingering VM without a flush", "(which ends its VM without a flush)"] },
  { gap: "GAP-1795", page: "troubleshooting/sandboxes/runs-and-sessions.mdx", section: "A sandbox is in OpenShell's error state", has: ["fails with Conflict and leaves it starting"], lacks: ["run `defenseclaw sandbox stop NAME` once it is ready"] },
  { gap: "GAP-1795", page: "enterprise/runtime/sandboxes.mdx", has: ["its `--end-vm` start fails with Conflict"], lacks: ["is started with `defenseclaw sandbox start <name> --end-vm`"] },
  { gap: "GAP-1795", page: "reference/sandboxes/cli.mdx", has: ["OpenShell 0.1.5 refuses this start with Conflict."] },
  { gap: "GAP-1762", page: "troubleshooting/known-limits.mdx", section: "Claude Code shell", has: ["no hook decision and no hook audit row", "the Tetragon runtime layer can still record it (`hook_seen=false`)"], lacks: ["the audit log has no row for it"] },
  { gap: "GAP-1763", page: "troubleshooting/known-limits.mdx", section: "Upgrade and policy limits", has: ["a process tracer such as PRoot on Linux", "`unprivileged_ptrace`", "`kernel.yama.ptrace_scope=2`"] },
  { gap: "GAP-1764", page: "troubleshooting/windows.mdx", section: "Codex refuses every command in its first session", has: ["Granular.sandbox_approval is false", "Quit Codex and start it again once", "/docs/troubleshooting/known-limits#codex"] },
  { gap: "GAP-0552", page: "troubleshooting/known-limits.mdx", section: "Scanners on macOS", has: ["run as you, with a timeout", "can escape that tracking and keep running after the scan and after `defenseclaw-gateway stop`", "This is a macOS limit."] },
  { gap: "GAP-1158", page: "troubleshooting/known-limits.mdx", section: "Codex", has: ["**Shared daemon keeps its model key:**", "fail with `401` until the daemon restarts", "Run `codex app-server daemon restart` from a shell that has the new key."] },
  { gap: "GAP-1203", page: "troubleshooting/known-limits.mdx", section: "Identity", has: ["utmp keeps only the first 32 characters of a user name", "omit `defenseclaw.session.kind` and `client.address`", "Keep systemd-logind running"] },
  { gap: "r103:GAP-0214", page: "troubleshooting/known-limits.mdx", section: "Upgrade and policy limits", has: ["**Hermes config changed and put back quickly:**", "within about 3 seconds", "one Hermes session can start without the DefenseClaw hook", "records the change in the audit log"] },
  { gap: "GAP-1209", page: "troubleshooting/known-limits.mdx", section: "Sandboxes", has: ["**Rejected model key in a sandbox:**", "retries a rejected request for up to about three minutes", "cannot warn before the retries end"] },
  { gap: "GAP-1641", page: "reference/scanning/registries.mdx", has: ["`openclaw package metadata is missing the plugins map`", "without one the fetch fails with `401 Client Error: Unauthorized`", "Both are upstream changes"] },
  { gap: "GAP-1191, GAP-1198, GAP-1199, GAP-1220, GAP-1223, GAP-1224, GAP-1242, GAP-1247, GAP-1248, GAP-1249, GAP-1250, GAP-1251, GAP-1252, GAP-1262, GAP-1265, GAP-1275, GAP-1276, GAP-1285, GAP-1290", page: "troubleshooting/known-limits.mdx", section: "Agent messages that are not from DefenseClaw", has: ["`Model metadata for <model> not found. Defaulting to fallback metadata`", "`api_key_model_discovery`", "`Workspace (granular)`", "`Auto-update failed: no write permission to npm prefix`", "`Unknown command: /NAME`", "`Contains brace with quote character (expansion obfuscation)`", "automatic update fails with `EACCES`", "lists command words such as `exit`, `test` or `run` as paths", "is not in the built-in catalog", "`Security scan — [HIGH] Pipe to interpreter`", "Hermes can then say DefenseClaw blocked the step", "`This foreground command appears to start a long-lived server/watch process`", "`node not available (Hermes-managed Node not installed)`", "`pygount: command not found`", "`pm-runtime: invalid package install stamp`", "`.install.lock`", "`npm warn install-scripts: postinstall ... is not covered by allowScripts`", "`codex exec --full-auto`", "its audit log has no block for it"] },
  { gap: "GAP-1543", page: "connectors/claudecode.mdx", has: ["strict and managed installs block it", "a killed or timed-out hook lets the call run"], lacks: ["every other hook failure blocks", "During an outage the default and permissive policies let the call run with a warning, strict blocks it."] },
  { gap: "GAP-1544", page: "connectors/claudecode.mdx", section: "Turn it off", has: ["It asks `Proceed? [Y/n]`; add `--yes` in scripts or when stdin is not a terminal."] },
  { gap: "GAP-1566", page: "connectors/copilot.mdx", section: "On a managed computer", has: ["are per-user commands", "/docs/enterprise/operate/lifecycle#change-the-config", "refuses `setup copilot`"] },
  { gap: "GAP-1571", page: "connectors/copilot.mdx", section: "Files it changes", has: ["The registration runs `%USERPROFILE%\\.defenseclaw\\hooks\\copilot-hook.ps1`, which calls"] },
  { gap: "GAP-1675", page: "connectors/opencode.mdx", section: "On a managed computer", has: ["`C:\\ProgramData\\opencode\\opencode.json`", "`C:\\Program Files\\Cisco\\DefenseClaw\\share\\opencode\\defenseclaw.js`", "on Windows too", "`guardrail.connectors.opencode.enabled: false`"] },
  { gap: "GAP-1701", page: "connectors/hermes.mdx", has: ["| Hook program, managed Windows | `C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw-hook.exe`", "the administrator sets `guardrail.connectors.hermes.enabled: false` in the managed `config.yaml` and runs `ensure`"] },
  { gap: "GAP-1598", page: "reference/connectors/antigravity.mdx", has: ["`antigravity-hook.sh PreToolUse`", "a per-user install in the default or permissive policy lets `PreToolUse` run with one warning"], lacks: ["With the default fail mode closed", "binds each registration to a trusted `--event` argument"] },
  { gap: "GAP-1637", page: "reference/connectors/kiro.mdx", section: "Fail mode", has: ["the default and permissive policies let the call run with one warning, and the strict policy blocks it"] },
  { gap: "GAP-1590", page: "reference/connectors/amp.mdx", section: "Fail mode", has: ["the default and permissive policies let the call run with one warning"], lacks: ["closed by default"] },
  { gap: "GAP-1670", page: "connectors/cursor.mdx", has: ["a gateway outage lets the call run with a warning in the default and permissive policies and blocks it in strict"], lacks: ["a gateway outage blocks supported events by default"] },
  { gap: "GAP-1670", page: "reference/connectors/cursor.mdx", section: "Fail mode", has: ["the default and permissive policies let the call run with a warning, strict blocks it"], lacks: ["still blocks supported events during a gateway outage by default"] },
  { gap: "GAP-1683", page: "reference/connectors/codex.mdx", has: ["host setup removes only exporters that carry a DefenseClaw credential", "your own exporters stay"], lacks: ["host upgrades remove old exporters"] },
  { gap: "GAP-1702", page: "reference/connectors/codex.mdx", section: "Install surface", has: ["`/etc/codex/requirements.toml` with `/opt/defenseclaw/bin/defenseclaw-hook` on Linux"] },
  { gap: "GAP-1315", page: "connectors/codex.mdx", section: "On a managed computer", has: ["when it reconciles an enrolled account", "for an account that is not enrolled the preference stays"], lacks: ["removes that conflicting user preference during reconciliation"] },
  { gap: "GAP-1582", page: "connectors/zeptoclaw.mdx", has: ["`ncat`", "those seven commands"] },
  { gap: "GAP-1582", page: "reference/connectors/zeptoclaw.mdx", has: ["seven PATH shims", "`ncat` (a link to the `nc` shim)"] },
  { gap: "GAP-1644", page: "reference/connectors/zeptoclaw.mdx", has: ["`4000`, or the free port `init` chose when another account holds 4000"] },
  { gap: "GAP-1645", page: "reference/connectors/zeptoclaw.mdx", has: ["unless you pass `--replace`", "`no usable providers found`"] },
  { gap: "GAP-0108, GAP-1524", page: "get-started/quickstart.mdx", has: ["its hook lets a call run with one warning while the gateway is not running", "a running hook blocks every other failure it detects"], lacks: ["With the default fail mode closed", "The hook fail mode is closed on a new install", "every other hook failure blocks"] },
  { gap: "GAP-1620", page: "get-started/quickstart.mdx", has: ["On an install that already guards other agents, `init --connector claudecode` keeps only Claude Code.", "use `defenseclaw setup <agent>` instead"] },
  { gap: "GAP-1660", page: "reference/commands/cli.mdx", has: ["Fields that are not set (`connector`, `command`, `url` and the others) are left out."], lacks: ["\"source_path_contains\": [],"] },
  { gap: "GAP-1626", page: "reference/commands/cli.mdx", has: ["`5` when run from a standard account", "`elevation_required`"] },
  { gap: "GAP-1604", page: "index.mdx", has: ["the shipped default blocks CRITICAL and alerts on MEDIUM and above."], lacks: ["alerts on HIGH."] },
  { gap: "GAP-1606", page: "reference/policy/index.mdx", has: ["regex rules and suppressions of the bundled strict pack"] },
  { gap: "GAP-1607", page: "enterprise/configure/enrollment.mdx", has: ["sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise hooks status # macOS"] },
  { gap: "GAP-0885", page: "enterprise/configure/enrollment.mdx", has: ["under `unenrolled_users: inspect` (the default) an extension-only user of it gets no target row", "with `deny` the user becomes a target"] },
  { gap: "GAP-1609", page: "reference/commands/tui.mdx", has: ["The **Blocks** filter chip (move between chips with `h` and `l`; `3` still opens Skills)"], lacks: ["`3` (Blocks) lists"] },
  { gap: "GAP-1610", page: "how-to/guardrail/catch-prompt-injection.mdx", has: ["Host setup does not wire Codex's native OpenTelemetry; only an isolated OpenShell sandbox uses it."], lacks: ["Setup also wires Codex's native OpenTelemetry."] },
  { gap: "GAP-1618", page: "enterprise/install/reference/macos.mdx", has: ["`enterprise macos status --json` and `enterprise macos verify` report `tetragon_not_applicable`"] },
  { gap: "GAP-1618", page: "enterprise/configure/settings.mdx", has: ["on macOS `status --json` and `verify` report `tetragon_not_applicable`"] },
  { gap: "GAP-1591", page: "reference/policy/cel/engine.mdx", has: ["`exists`, `all`, `map` and `filter` comprehensions; nesting is limited to two levels"] },
  { gap: "GAP-1587", page: "how-to/guardrail/allow-a-blocked-call.mdx", has: ["fails the **Config validation** and **Rule pack** rows and skips **Policy**"], lacks: ["fails the Policy row until you pin the new digest"] },
  { gap: "GAP-1656", page: "reference/policy/rules.mdx", has: ["`live state was not checked while config.yaml is invalid`"], lacks: ["fails the **Policy** row: `generation 2"] },
  { gap: "GAP-1652", page: "troubleshooting/hooks-and-blocking.mdx", has: ["pin the `files digest` value it prints (the guardrail.custom_packs pin, not the `digest` line)", "set both its `path` and `digest`"] },
  { gap: "GAP-1649", page: "troubleshooting/gateway-and-keys.mdx", has: ["`DefenseClaw blocked this because its gateway is stopped`", "`defenseclaw: gateway unreachable, blocking <agent> tool (fail mode closed)`"] },
  { gap: "GAP-1667", page: "troubleshooting/gateway-and-keys.mdx", has: ["Under the default and permissive policies a per-user call runs with one warning instead"], lacks: ["the hook is fail-closed. This holds in observe mode too."] },
  { gap: "GAP-1666", page: "troubleshooting/gateway-and-keys.mdx", has: ["(on Windows the row is `Config file`)", "`Gateway token env`, `Gateway token drift` and `Gateway PID identity`"] },
  { gap: "GAP-1691", page: "reference/configuration/fail-modes.mdx", has: ["accept only `open` or `closed`, in lower case"], lacks: ["Any value other than `open` (in any case) is `closed`."] },
  { gap: "GAP-1698", page: "enterprise/operate/operations.mdx", has: ["`/var/lib/defenseclaw-enterprise/last-package-result.json` (the package"], lacks: ["and `last-package-result.log` beside it"] },
  { gap: "GAP-1517", page: "appendix/benchmarks.mdx", has: ["title=\"Eleven YARA signatures\""], lacks: ["Ten YARA signatures"] },
  { gap: "GAP-1404", page: "reference/configuration/index.mdx", has: ["`%LOCALAPPDATA%\\hermes\\config.yaml` on native Windows"] },
  { gap: "GAP-1307", page: "reference/observability/redaction.mdx", has: ["move needs at least two routes on the destination;"] },
  { gap: "GAP-1382", page: "features/acp-guard.mdx", has: ["On a per-user install `defenseclaw acp catalog` prints the list. On a managed computer it is refused (exit 2)"] },
  { gap: "GAP-1631", page: "how-to/agents/add-or-remove-an-agent.mdx", has: ["`Fail` is `open` under the default policy"], lacks: ["enabled observe closed default"] },
  { gap: "GAP-1673", page: "troubleshooting/enterprise/index.mdx", section: "Lifecycle error codes", has: ["| `hook_process_fail_open` | Linux, macOS, Windows |", "| `status_detail_unavailable` |", "| `claude_state_unreadable` |"] },
  { gap: "GAP-1696", page: "troubleshooting/enterprise/hooks.mdx", section: "`security_complete` is `false` on Windows", has: ["`status_detail_unavailable`", "`claude_state_unreadable`", "ATTESTCLAUDEEFFECTIVEPOLICY=1", "`security_incomplete` lists the reasons"] },
  { gap: "GAP-1700", page: "troubleshooting/enterprise/hooks.mdx", section: "`security_complete` is `false` on Linux or macOS", has: ["`unprivileged_user_namespaces`", "with only `hook_process_fail_open`, `unprivileged_user_namespaces` and `unprivileged_ptrace` warnings"] },
  { gap: "GAP-1697", page: "troubleshooting/enterprise/hooks.mdx", has: ["On managed Windows `defenseclaw.exe` exits `3` and writes no audit row"] },
  { gap: "GAP-1707", page: "enterprise/plan/rollout.mdx", has: ["On Linux and macOS a healthy install keeps it at `false` with only `hook_process_fail_open`", "`unprivileged_ptrace` while the kernel allows them"] },
  { gap: "GAP-1630", page: "how-to/policies/use-a-different-rule-pack.mdx", section: "Undo", has: ["defenseclaw policy activate default", "with `strict` a call is blocked while the gateway is not running, and `default` lets it run with a warning again"] },
  { gap: "GAP-1653", page: "reference/configuration/llm-providers.mdx", has: ["'remove <ENV_NAME>': {"] },
  { gap: "GAP-1623", page: "how-to/guardrail/block-a-destructive-command.mdx", has: ["Select-String -Path", "ConvertFrom-Json"], lacks: ["`closed` (the default) blocks"] },
  { gap: "GAP-1624", page: "appendix/windows-security-model.mdx", has: ["`audit.db` and `.env` grant access only to the user (`OWNER RIGHTS` or the account) and SYSTEM", "only after taking ownership"], lacks: ["readable only by that user, Administrators, and SYSTEM"] },
  { gap: "GAP-1712", page: "appendix/windows-security-model.mdx", has: ["`C:\\ProgramData\\Cisco\\DefenseClaw\\runtime\\audit.db`", "`enterprise windows verify --profile standalone`"] },
  { gap: "GAP-1665", page: "reference/configuration/paths.mdx", has: ["on Windows `installer\\` holds only `install.ps1`", "`skill-scanner.cmd`, `mcp-scanner.cmd`", "`defenseclaw-hook-state.json`"] },
  { gap: "GAP-1713", page: "reference/configuration/paths.mdx", has: ["On a managed Windows computer none of these per-user paths are used", "`C:\\ProgramData\\Cisco\\DefenseClaw\\etc\\config.yaml`"] },
  { gap: "GAP-1671", page: "enterprise/plan/managed-policy.mdx", has: ["| Attempt on managed Windows | Result |", "config set did not change it", "not a command of the administrator's `defenseclaw.exe`"] },
  { gap: "GAP-1678", page: "troubleshooting/doctor.mdx", section: "Observability rows", has: ["| Codex OTel environment |", "| Connector OTLP: CONNECTOR |", "| Native OTLP credentials |"] },
  { gap: "GAP-1689", page: "enterprise/configure/ai-defense-key.mdx", has: ["`! secret set: done with N warnings`", "The warnings are the host's normal status, not a failed store."] },
  { gap: "GAP-1568", page: "enterprise/configure/reference.mdx", has: ["`! secret remove: done with N warnings`", "`! secret remove: nothing to do (up_to_date), N warnings`"] },
  { gap: "GAP-1573", page: "get-started/install.mdx", section: "Check it worked", has: ["`✓ All components in sync.`", "piped to another command, as above, they use text"] },
  { gap: "GAP-1581", page: "get-started/upgrade.mdx", section: "Rollback", has: ["Rollback needs a previous install that was initialized.", "undoes itself and exits 1"] },
  { gap: "GAP-1567", page: "for-agents/write-a-rule.mdx", has: ["In action mode DefenseClaw blocks an agent that copies into `~/.defenseclaw` (`tamper.detector_state_write`"] },
  { gap: "GAP-1613", page: "enterprise/runtime/sandbox-reference.mdx", has: ["`sandboxes are unavailable: OpenShell 0.1.3 runs no DefenseClaw sandbox:"], lacks: ["OpenShell 0.1.3 is installed, but that release is unsupported"] },
  { gap: "GAP-1619", page: "how-to/policies/give-a-group-its-own-policy.mdx", has: ["`defenseclaw-gateway config validate FILE`", "`enterprise macos ensure --config FILE`", "`enterprise macos profile-explain`"] },
  { gap: "GAP-1635", page: "reference/scanning/admission.mdx", has: ["`tool list` prints one table per connector", "`UPDATED` shows `-` for an entry until it is changed"] },
  { gap: "GAP-1659", page: "reference/policy/guardrail-profiles.mdx", section: "A complete example", has: ["hilt: {enabled: true, min_severity: LOW}"], lacks: ["hilt: {enabled: true, min_severity: HIGH}"] },
  { gap: "GAP-0595", page: "how-to/scanning/find-ai-on-this-machine.mdx", has: ["It asks `Proceed? [Y/n]` first; add `--yes` in scripts.", "It asks `Proceed? [Y/n]`; `--yes` skips the question."] },
  { gap: "GAP-0633", page: "reference/configuration/env-vars.mdx", has: ["where the profile is standalone, the Linux default; on Windows and macOS", "the writers keep writing"] },
  { gap: "GAP-0669", page: "how-to/guardrail/stop-a-secret-upload.mdx", has: ["defenseclaw setup cursor --yes --mode action --rule-pack default --no-human-approval --restart", "`--yes` re-applies hooks when Cursor is already configured and skips the optional LLM judge prompt", "✓ cursor mode=action"] },
  { gap: "GAP-0520", page: "reference/commands/guardrail-setup.mdx", has: ["**Select action connector(s) for LLM judge.**"] },
  { gap: "GAP-0388", page: "how-to/observability/run-grafana-locally.mdx", has: ["18 DefenseClaw dashboards (19 with the Fleet assets)"] },
  { gap: "GAP-0388", page: "reference/observability/dashboards.mdx", has: ["DefenseClaw provisions 18 Grafana dashboards", "it is not in the installed package and is added with the separate Fleet assets"] },
  { gap: "GAP-1716", page: "get-started/windows.mdx", section: "Upgrade and roll back", has: ["exit code 0 means the installer started, not that it finished", "-Rollback -Yes`, which waits and sets the exit code"] },
  { gap: "GAP-1716", page: "troubleshooting/known-limits.mdx", section: "Upgrade and policy limits", has: ["**Windows upgrade and rollback return before the installer finishes:**"] },
  { gap: "GAP-0922, GAP-0923", page: "troubleshooting/known-limits.mdx", section: "Upgrade and policy limits", has: ["macOS has no setting that stops a user's sandbox profile", "DefenseClaw does not see or audit its tool calls"], lacks: ["unshare -Urm"] },
  { gap: "GAP-0725", page: "enterprise/identity/sources.mdx", has: ["the same entry selects the account of that name in each of those domains", "The strict policy tier refuses a request when that ambiguity could change its profile."] },
  { gap: "GAP-0725", page: "reference/policy/guardrail-profiles.mdx", has: ["the entry selects the account of that name in each domain"] },
  { gap: "GAP-0755", page: "enterprise/configure/enrollment.mdx", has: ["Excluding an enrolled account also removes its guardian identity record at the next guardian pass"] },
  { gap: "GAP-1163", page: "reference/sandboxes/cli.mdx", has: ["If that sync fails, DefenseClaw does not stop the VM"] },
  { gap: "GAP-1550", page: "troubleshooting/sandboxes/runs-and-sessions.mdx", section: "A MicroVM stop is held because its disk could not sync", has: ["Signing out without linger, `sandbox teardown` and an administrator"] },
  { gap: "GAP-1595", page: "reference/commands/tui.mdx", has: ["the TUI asks whether to stop it anyway"] },
  { gap: "GAP-0868", page: "enterprise/runtime/sandboxes.mdx", has: ["the package pauses each account's old sandbox daemon before it replaces any file"] },
  { gap: "GAP-0546", page: "enterprise/runtime/sandbox-reference.mdx", has: ["`ensure` fails with `config_invalid` and keeps the previous config and the running gateway"] },
  { gap: "GAP-0691", page: "enterprise/runtime/sandbox-reference.mdx", has: ["can be written in any letter case: `VM` is `vm`"] },
  { gap: "GAP-0714", page: "enterprise/runtime/sandbox-reference.mdx", has: ["read and write access to `/dev/kvm` (the `kvm` group, a user ACL entry or an open mode)"] },
  { gap: "GAP-1693", page: "reference/sandboxes/cli.mdx", has: ["can reach your account's request limit"] },
  { gap: "GAP-1552", page: "enterprise/runtime/sandboxes.mdx", has: ["a run first waits up to 10 seconds for your sandbox policy"] },
  { gap: "GAP-0701", page: "troubleshooting/sandboxes/setup-and-gateway.mdx", has: ["offers the next free port and writes it as `openshell.ingress_port` or `openshell.egress_port`"] },
  { gap: "GAP-0831", page: "troubleshooting/known-limits.mdx", section: "Upgrade and policy limits", has: ["it cannot cut that guest off below OpenShell's own network broker", "adds none back (approvals included)"] },
  { gap: "GAP-1173, GAP-1188", page: "enterprise/mdm/intune/linux.mdx", has: ["the script first writes what it replaces to a root-only journal"] },
  { gap: "GAP-1536", page: "enterprise/mdm/intune/macos.mdx", has: ["about 108 KB (2,091 lines)"] },
  { gap: "GAP-1584, GAP-1616", page: "enterprise/mdm/reference.mdx", has: ["including the rotation journal and the staging folders of wrapper runs that were killed", "`--purge` also removes the wrapper's empty state folder `/var/db/defenseclaw-mdm`", "every ensure exits `mdm_secret_failed`"] },
  { gap: "GAP-0727", page: "enterprise/operate/reference.mdx", has: ["`--purge` leaves that folder and the install's binaries exactly as they are"], lacks: ["to a new `~/.defenseclaw-backup-<UTC time>` folder"] },
  { gap: "GAP-0727", page: "reference/commands/cli.mdx", lacks: ["is moved to `~/.defenseclaw-backup-<UTC time>` first"] },
  { gap: "GAP-1654", page: "enterprise/install/reference/linux.mdx", has: ["Accounts the deployment never enrolled keep their DefenseClaw files"] },
  { gap: "GAP-1542", page: "enterprise/operate/lifecycle.mdx", has: ["`--purge` removes everything DefenseClaw installed", "`eDSPermissionError`"] },
  { gap: "GAP-0286", page: "troubleshooting/known-limits.mdx", section: "Upgrade and policy limits", has: ["the old gateway's audit row can still say allow", "the gateway records such a call as unconfirmed"] },
  { gap: "GAP-1563", page: "troubleshooting/known-limits.mdx", section: "Codex", has: ["shows `Config check: not run` because the sandbox hides who owns your folders"] },
  { gap: "GAP-1600, GAP-1748", page: "how-to/observability/send-to-splunk.mdx", has: ["setup stops with exit 1 and saves nothing", "run `defenseclaw observability destination test <name>`"] },
  { gap: "GAP-1398, GAP-1750", page: "how-to/observability/send-to-splunk.mdx", has: ["In Splunk Free mode Splunk Web opens as admin with no login"] },
  { gap: "GAP-1663", page: "how-to/scanning/find-ai-on-this-machine.mdx", has: ["The selected planes are kept for the next `enable`."] },
  { gap: "GAP-1589", page: "reference/apis/acp-guard.mdx", has: ["the last line then ends with `new profile NAME`", "takes out the profiles setup wrote for that pair"] },
  { gap: "GAP-1677", page: "troubleshooting/doctor.mdx", has: ["says there is nothing to acknowledge and exits 0"] },
  { gap: "GAP-1366", page: "reference/commands/cli.mdx", has: ["one warning says the change was saved"] },
  { gap: "GAP-1274", page: "reference/commands/tui.mdx", has: ["WATCHING means every selected plane is running"] },
  { gap: "GAP-1539", page: "troubleshooting/known-limits.mdx", section: "Upgrade and policy limits", has: ["`user_registrations_failed`"] },
  { gap: "GAP-1703", page: "reference/connectors/hermes.mdx", section: "Managed verification", has: ["`connector hermes cannot be verified: session-only HERMES_HOME cannot be observed by the managed service`"] },
  { gap: "GAP-1603, GAP-1627", page: "enterprise/operate/operations.mdx", has: ["the bounded scan of this account's private agent installs was incomplete", "`audit_write_failed` stays for 16 minutes"] },
  { gap: "GAP-1753", page: "troubleshooting/known-limits.mdx", section: "Managed macOS private agent scan", has: ["On macOS 15.8 the managed scan also skips these folders"] },
  { gap: "GAP-1714", page: "troubleshooting/enterprise/hooks.mdx", section: "An account on a stalled network or FUSE mount", has: ["`fusermount -uz`"] },
  { gap: "GAP-1503", page: "reference/policy/detection.mdx", has: ["instruction-file writes are HIGH, so they are reported, not blocked"] },
  { gap: "GAP-1254", page: "reference/connectors/copilot.mdx", has: ["removes the `enabledPlugins` entry `defenseclaw@defenseclaw`"] },
  // r105-rows-end
];

function pageSection(name: string, heading?: string): string {
  const text = page(name);
  if (!heading) return text;
  const body = text.split(`## ${heading} `)[1];
  assert.ok(body !== undefined, `${name} has no "## ${heading}" section`);
  return body.split(' ## ')[0];
}

describe('first-run report sample matches cmd_init (GAP-1605)', () => {
  it('shows the outage line init prints and the default fail mode', () => {
    const init = source('cli/defenseclaw/commands/cmd_init.py');
    assert.ok(init.includes('"  While the gateway is not running, hooks let calls run with a warning"'));
    assert.ok(init.includes('" (strict policy blocks them: defenseclaw guardrail use-pack strict)."'));
    const sample = readFileSync(join(site, 'content/snippets/first-run-report.mdx'), 'utf8');
    assert.ok(sample.includes('While the gateway is not running, hooks let calls run with a warning (strict policy blocks them: defenseclaw guardrail use-pack strict).'));
    assert.ok(sample.includes('fail mode=open') && !sample.includes('fail mode=closed'));
  });
});

describe('scanner settings warning (GAP-1648)', () => {
  it('quotes the text scanner/settings.py returns', () => {
    assert.ok(source('cli/defenseclaw/scanner/settings.py').includes('return f"the skill-scanner LLM judge is off; {ADD_JUDGE_HINT}"'));
    assert.ok(page('reference/scanning/scanners.mdx').includes('[WARN] Scanner settings — the skill-scanner LLM judge is off;'));
  });
});

describe('edge API examples carry every response field (GAP-1632)', () => {
  it('names each Device JSON field and the list paging keys', () => {
    const fields = [...source('internal/fleet/manager/manager.go').split('type Device struct')[1].split('\n}')[0].matchAll(/json:"([a-z_]+)"/g)].map((m) => m[1]);
    assert.ok(fields.length >= 25, `Device has ${fields.length} JSON fields`);
    const api = page('reference/edge-connector/api.mdx');
    for (const field of fields) assert.ok(api.includes(`"${field}":`), `api.mdx device example lacks ${field}`);
    for (const key of ['"limit": 10000', '"offset": 0', '"total": 150']) assert.ok(api.includes(key), key);
  });
});

describe('edge connector variables and the registry (GAP-1639)', () => {
  it('names exactly the adapter variables the registry lacks', () => {
    const registry = source('internal/envvars/registry.json');
    const adapters = ['DCLAW_LIB_PATH', 'DCLAW_SOCKET_PATH', 'DCLAW_LOG_PATH', 'DCLAW_FAIL_OPEN', 'DCLAW_FAIL_OPEN_TOKEN', 'DCLAW_MCP_UPSTREAM', 'DCLAW_MCP_TRANSPORT', 'DCLAW_MCP_PORT'];
    for (const name of adapters) assert.ok(!registry.includes(`"${name}"`), `${name} is in the registry now; update the page`);
    assert.ok(registry.includes('"DCLAW_FLEET_API_URL"'));
    const text = page('reference/edge-connector/configuration.mdx');
    assert.ok(text.includes('are read only by the adapters and are listed only on this page'));
  });
});

describe('1.0.5 docs rows', () => {
  for (const row of r105Rows) {
    it(`${row.gap}: ${row.page}${row.section ? ` "${row.section}"` : ''}`, () => {
      const text = pageSection(row.page, row.section);
      for (const phrase of row.has ?? []) assert.ok(text.includes(phrase), `${row.page} lacks: ${phrase}`);
      for (const phrase of row.lacks ?? []) assert.ok(!text.includes(phrase), `${row.page} still says: ${phrase}`);
    });
  }
});
