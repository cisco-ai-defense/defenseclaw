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

    const reference = page('enterprise/configuration.mdx');
    const customPack = reference.split('## Custom rule packs')[1]?.split('## Network proxy')[0] ?? '';
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
    const failModes = page('reference/fail-modes.mdx').split('## Controls')[0] ?? '';
    const cursor = page('connectors/cursor.mdx').split('## Fail mode')[1]?.split('## Limits')[0] ?? '';
    const perUser = page('reference/fail-modes.mdx').split('### Per-user installs')[1]?.split('\n## ')[0] ?? '';
    assert.match(perUser, /`default` \(balanced, the out-of-the-box policy\) or `permissive` \| The call runs/i);
    assert.match(perUser, /\| `strict` \(`defenseclaw guardrail use-pack strict`\) \| Block/i);
    assert.match(perUser, /The guardrail mode does not change the outage mode: observe and action mode fail the same way/i);
    assert.match(cursor, /per-user Cursor hook uses an explicit saved outage mode; when unset, its policy tier decides in observe and action mode/i);
    const coverage = page('segmentation.mdx');
    assert.match(coverage, /On a per-user install an explicit saved mode wins; when unset, the policy tier decides in observe and action mode alike: default and permissive run the call with a warning/i);
    for (const stale of ['guardrail/index.mdx', 'reference/setup-commands.mdx', 'segmentation.mdx']) {
      assert.ok(!/Per-user Cursor (?:in )?observe (?:mode )?(?:still|also) blocks/i.test(page(stale)), stale);
    }
    assert.match(failModes, /On a per-user install, an explicit saved `guardrail\.hook_fail_mode` selects the outage mode.{0,600}Every other failure blocks in every tier/i);
    const managedRegistration = source('internal/gateway/connector/cursor_enterprise_hooks.go');
    assert.match(managedRegistration, /"failClosed": true,/);
    assert.match(page('connectors/cursor.mdx'), /sets `failClosed: true`, so a hook process that never answers blocks the call. The administrator's resolved fail mode decides/i);
    assert.ok(!/per-user Cursor in observe mode fails open/i.test(failModes));

    const overview = page('connectors/cursor.mdx').split('## What it can block or ask')[1]?.split('## Files it changes')[0] ?? '';
    assert.match(overview, /Observe mode.{0,120}policy findings without blocking/i);
    assert.match(overview, /gateway outage lets the call run with a warning in the default and permissive policies and blocks it in strict/i);
    const mapping = page('connectors/cursor.mdx').split('## Verdict mapping')[1]?.split('## Native ask')[0] ?? '';
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
    const mapping = page('connectors/antigravity.mdx').split('## Verdict mapping')[1]?.split('## Native ask')[0] ?? '';
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
      const text = page(`connectors/${connector}.mdx`).replace(/\s+/g, ' ');
      assert.match(text, /per-user install.{0,120}?(?:default and permissive|default or permissive) polic(?:y|ies).{0,40}?lets?.{0,80}?run with one warning/i, connector);
      assert.match(text, /strict policy.{0,80}?(?:blocks|denies|deny) it/i, connector);
      assert.ok(text.includes('/docs/connectors/capability-matrix#gateway-outage'), connector);
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
    const offenders = ['connectors'].flatMap((folder) => docsPages(join(docs, folder))
      .flatMap((path) => readFileSync(path, 'utf8').replace(/\s+/g, ' ').split(/(?<=[.|])\s+/)
        .filter((sentence) => stale.test(sentence) && !scoped.test(sentence))
        .map((sentence) => `${relative(docs, path)}: ${sentence.slice(0, 160)}`)));
    assert.deepEqual(offenders, []);
  });

  it('describes the live OSS outage decision in the guide and fail-mode reference', () => {
    const guide = page('connectors/opencode.mdx');
    assert.match(guide, /per-user.*default and permissive.*run with one warning.*strict.*blocks/i);
    const failModes = page('reference/fail-modes.mdx');
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
      const setup = page(`connectors/${connector}.mdx`).split('## Setup')[1]?.split('## Check it')[0] ?? '';
      assert.match(setup, /Observe records policy findings without blocking on those findings/i, connector);
      assert.match(setup, /gateway outage still stops proxied requests/i, connector);
      assert.match(page(`connectors/${connector}.mdx`), /While the gateway is down, requests are blocked/i, connector);
    }
  });

  it('scopes general guardrail observe guidance to policy findings', () => {
    assert.match(page('guardrail/index.mdx'), /Observe mode does not enforce policy findings/i);
    assert.match(page('guardrail/index.mdx'), /Hook fail mode and proxy availability still apply/i);
    assert.ok(!/\*\*Observe\*\*[^.]*blocks nothing/i.test(page('guardrail/index.mdx')));
    assert.match(page('policies/thresholds.mdx'), /Observe mode does not enforce policy findings/i);
    const commands = source('docs-site/content/docs/reference/cli.mdx');
    const modeRow = commands.split('\n').find((line) => line.startsWith('| `defenseclaw guardrail mode observe')) ?? '';
    assert.match(modeRow, /observe \(logs policy findings without enforcing them\)/i);
    assert.match(modeRow, /Hook fail mode and proxy availability still apply/i);
  });

  it('names the ACP observe failure exception', () => {
    const proxy = source('internal/acp/proxy.go').split('func observeRefuses(')[1]?.split('\n}')[0] ?? '';
    assert.match(proxy, /state\.profileFailsClosed\(\)/);
    assert.match(proxy, /!opts\.Managed/);
    assert.match(proxy, /!state\.sessionFailsOpen\(promptSessionID\(msg\)\)/);
    const guide = page('acp-guard.mdx');
    assert.match(guide, /observe mode.{0,100}policy findings without blocking/i);
    assert.match(guide, /standalone managed guard.{0,100}refuses an unevaluated frame by default/i);
  });
});

describe('ZeptoClaw removal', () => {
  it('documents the last-connector gate and the forced removal command', () => {
    const removal = source('cli/defenseclaw/commands/cmd_setup.py').split('# WU8 D2=A — last-connector gate.')[1]?.split('elif not yes')[0] ?? '';
    assert.match(removal, /if not remaining:[\s\S]*?if not force and not unshipped:/);
    assert.match(removal, /Pass --force to fully unconfigure enforcement/);
    const turnOff = page('connectors/zeptoclaw.mdx').split('## Disable')[1]?.split('## Details')[0] ?? '';
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
    const body = page('sandboxes/guide.mdx');
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
    const handoff = page('reference/sandbox-cli.mdx').split('Handing the gateway over stops the sandboxes it runs')[1]?.split('</Callout>')[0];
    assert.ok(handoff?.includes('last successful disk sync'), 'gateway handoff advice must qualify copy-mode MicroVM work');
    assert.ok(!handoff?.includes('a copy keeps its work in the sandbox'), 'gateway handoff promises unsynced copy-mode work');
    const managed = page('enterprise/sandboxes.mdx');
    assert.ok(managed.includes('last successful disk sync'), 'managed upgrade advice must qualify failed-VM work');
    assert.ok(!managed.includes('a completed or failed MicroVM on 0.1.5 is started'),
      'managed upgrade advice must not send every failed VM through --end-vm');
    assert.ok(!managed.includes('the user stops and starts a MicroVM that was in the error state'),
      'managed upgrade advice promises a failed VM can always stop and start');
    const upgrade = page('sandboxes/guide.mdx');
    assert.ok(upgrade.includes('On OpenShell 0.1.5 or later, `openshell sandbox stop` requests a guest flush'),
      'raw OpenShell stops must name the release that flushes the guest');
    assert.ok(upgrade.includes('gateway older than OpenShell 0.1.5, save its work'),
      'raw OpenShell stops on older gateways need a save-first warning');
    assert.ok(!upgrade.includes('`openshell sandbox stop` does not sync its guest disk'),
      'raw OpenShell stop must not be described as never syncing');
    for (const [name, claim] of [
      ['sandboxes/guide.mdx', 'last successful disk sync'],
      ['sandboxes/guide.mdx', 'last successful disk sync'],
      ['reference/sandbox-cli.mdx', 'last successful one'],
      ['enterprise/sandboxes.mdx', 'last successful disk sync'],
    ]) {
      assert.ok(page(name).includes(claim), `${name} must qualify what a failed sync preserves`);
    }
  });

  it('keeps legacy guest stop advice aligned with the manager', () => {
    const manager = readFileSync(join(repo, 'internal/openshell/manager/box.go'), 'utf8');
    const autoStops = manager.includes('func (m *Manager) stopOldSupervisor(');
    const userStops = manager.includes('func (m *Manager) reconcileOldSupervisor(');
    assert.notEqual(autoStops, userStops, 'the legacy guest stop mechanism needs an explicit docs check');
    const upgrade = page('sandboxes/guide.mdx');
    assert.equal(upgrade.includes('It does not stop that legacy guest for you'), userStops,
      'manual legacy-guest stop advice requires the no-auto-stop manager');
    assert.equal(upgrade.includes('run `defenseclaw sandbox stop <name>` yourself'), userStops,
      'manual stop instructions require the no-auto-stop manager');
    assert.equal(upgrade.includes('`connect` refuses until you stop it'), userStops,
      'legacy connect advice must follow the manager behavior');
  });

  it('separates raw MicroVM errors by gateway release and phase reason', () => {
    const body = readFileSync(join(docs, 'sandboxes/guide.mdx'), 'utf8');
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
      ['sandboxes/guide.mdx', 'save or sync its work first, then `defenseclaw sandbox stop NAME`'],
      ['macos-app.mdx', 'save or sync each guest’s work first, then stop it with `defenseclaw sandbox stop NAME`'],
      ['reference/sandbox-cli.mdx', 'Save or sync accessible work first. In copy mode, pull work you need on the host; then stop the guest'],
      ['enterprise/sandboxes.mdx', 'Users save or pull accessible work first, then stop a running sandbox with `defenseclaw sandbox stop`'],
      ['sandboxes/guide.mdx', 'Before following a stop step below, save or sync accessible guest work'],
    ] as const) {
      assert.ok(page(name).includes(claim), `${name} must give save-first advice`);
    }
    assert.ok(!page('sandboxes/guide.mdx').includes('or `defenseclaw sandbox delete NAME` deletes it with its work'),
      'do not advise deleting a DefenseClaw guest with a stop recovery path');
    assert.ok(page('sandboxes/guide.mdx').includes('save accessible work outside a MicroVM whose VM still runs before deleting it for the upgrade'),
      'legacy MicroVM upgrade summary must put saving work before deletion');
    assert.ok(!page('enterprise/sandboxes.mdx').includes('and stopped, or deleted'),
      'do not advise deleting a managed guest with a stop recovery path');
    assert.ok(page('tui.mdx').includes('| `U` | Save work you want to keep first, then undo:'),
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
    const wal = page('observability/index.mdx');
    const enterprise = page('enterprise/troubleshooting.mdx');
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
    const enterprise = page('enterprise/troubleshooting.mdx');
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
    const reference = readFileSync(join(site, 'content/docs/enterprise/mdm/intune-windows.mdx'), 'utf8');
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
    const failModes = page('reference/fail-modes.mdx');
    assert.ok(!failModes.includes('The generated hooks stay open even when the effective mode is `closed`'));
    assert.ok(failModes.includes('Copilot and Antigravity still run a call when the hook times out or cannot start'));
    assert.ok(failModes.includes('Under Secure Client they stay open'));
    for (const name of ['connectors/copilot.mdx']) {
      const text = page(name);
      assert.ok(!/no fail-closed hook transport/i.test(text), name);
      // oss-outage-open: a per-user outage follows the policy tier; every other failure denies.
      assert.match(text, /On a per-user install a gateway that is not running follows the policy tier/i, name);
      assert.match(text, /the strict policy denies it/i, name);
      assert.match(text, /Every other failure DefenseClaw sees \(an unusable answer, a missing token\) is denied/i, name);
      // Oversized input is not an outage: default and permissive judge a bounded review (fail-modes.mdx).
      assert.match(text, /Oversized input is denied on a managed host and in the strict policy/i, name);
    }
    for (const name of ['connectors/antigravity.mdx']) {
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
    assert.ok(page('reference/fail-modes.mdx').includes('`closed` outside Secure Client; `open` under it'));
    assert.ok(page('reference/fail-modes.mdx').includes('A per-user 1.0.4 hook reads `config.yaml` next to its own hooks on each call'));
    assert.ok(page('reference/fail-modes.mdx').includes('A per-user (OSS) install honors a saved connector or global'));
  });
});

describe('per-user outage wording on connector pages (rel-1-0-4 GAP-1301, GAP-1317, GAP-1324)', () => {
  it('says the default and permissive policies let an outage call run on Antigravity, Copilot and Devin', () => {
    for (const name of ['connectors/antigravity.mdx', 'connectors/antigravity.mdx', 'connectors/copilot.mdx', 'connectors/devin.mdx']) {
      assert.match(page(name), /default (?:and|or) permissive polic(?:y|ies) lets? (?:the call|`PreToolUse`) run with one warning/i, name);
    }
  });

  it('never opens a Fail mode section with an unqualified closed claim', () => {
    for (const entry of readdirSync(join(docs, 'connectors'))) {
      if (!entry.endsWith('.mdx')) continue;
      const name = `connectors/${entry}`;
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
    const row = page('policies/defaults.mdx').split('| `scanner_overrides.mcp` |')[1]?.split(' | `scanner_overrides.plugin`')[0] ?? '';
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
    const reference = readFileSync(join(site, 'content/docs/reference/cli.mdx'), 'utf8');
    for (const { id, command } of hookConnectors) {
      const row = reference.split('\n').find((line) => line.startsWith(`| \`defenseclaw setup ${command}\` |`));
      assert.ok(row, `${id} CLI reference row is missing`);
      assert.match(row, /first setup.*observe|observe.*first setup/i, `${id} CLI row must qualify the default`);
      assert.match(row, /re-run.*keeps the current mode/i, `${id} CLI row must explain reruns`);

      const setup = page(`connectors/${id}.mdx`).split('## Setup')[1]?.split('## Check it')[0];
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
      const turnOff = page(`connectors/${id}.mdx`).split('## Disable')[1]?.split('## Details')[0];
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
    const claude = page('connectors/claudecode.mdx').split('## Disable')[1]?.split('## Details')[0];
    assert.match(claude ?? '', /removes? DefenseClaw(?:'s)? hooks and OpenTelemetry settings/i);
    const kiro = page('connectors/kiro.mdx').split('## Disable')[1]?.split('## Details')[0];
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
    const setup = page('connectors/claudecode.mdx').split('## Setup')[1]?.split('## Check it')[0];
    assert.match(setup ?? '', /re-run without `--mode` keeps the current mode/i);
    const turnOff = page('connectors/claudecode.mdx').split('## Disable')[1]?.split('## Details')[0];
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
    const guide = page('stories/cursor-secret-exfil.mdx');
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
    const windows = page('get-started/windows/paths-troubleshooting.mdx');
    assert.doesNotMatch(windows, /Hermes.*(?:fail-open setting|always shows failures as open)/i);
    // rel-1-0-4 GAP-0746: a per-user outage follows the policy tier (perUserOutageMode), as for every agent.
    assert.match(source('internal/gateway/connector/hookexec/hookexec.go'), /func perUserOutageMode\(opts \*Options, failMode string\) string \{/);
    assert.doesNotMatch(windows, /Hermes[^.]*closed by default/i);
    // r105 docs refix 1: outage behaviour is stated only in the capability matrix (Go TestOutageBehaviourIsStatedOnlyInTheCapabilityMatrix).
    assert.match(windows, /Hermes follows the same gateway outage rule as the other agents \(\[gateway outage table\]\(\/docs\/connectors\/capability-matrix#gateway-outage\)\)\. A running DefenseClaw hook blocks every other failure; for a timed-out or killed hook see \[Hermes fail mode\]\(\/docs\/connectors\/hermes#fail-mode\)\./);
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
    const limits = readFileSync(join(docs, 'connectors/hermes.mdx'), 'utf8');
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
    'enterprise/threat-model.mdx',
    'enterprise/enrollment.mdx',
    'enterprise/enrollment.mdx',
    'enterprise/machine-policy.mdx',
    'enterprise/windows.mdx',
    'enterprise/lifecycle.mdx',
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
    const windows = page('enterprise/windows.mdx');
    assert.match(windows, /configured Claude Code, Codex and Cursor machine hooks.{0,260}before the first (?:user )?enrollment.{0,260}after the last enrolled (?:user|SID) is removed/i);
    assert.match(windows, /unenrolled (?:account|SID).{0,120}refus/i);
    assert.match(windows, /missing (?:machine )?policy.{0,150}protection failure/i);
    assert.match(windows, /enterprise policy verify.{0,300}enterprise windows (?:reconcile|repair) --profile standalone/i);

    const policy = page('enterprise/machine-policy.mdx');
    assert.match(policy, /configured Claude Code, Codex and Cursor.{0,260}before the first (?:user )?enrollment.{0,260}after the last enrolled (?:user|SID) is removed/i);
    const ownershipOffRow = readFileSync(join(site, 'content/docs/enterprise/machine-policy.mdx'), 'utf8')
      .split('\n').find((line) => line.startsWith('| `off` |'));
    assert.ok(ownershipOffRow);
    assert.match(ownershipOffRow, /Windows.{0,150}Claude Code, Codex and Cursor.{0,180}verified even with zero enrolled users/i);

    const configuration = page('enterprise/configuration.mdx');
    assert.match(configuration, /On Windows.{0,150}ownership.{0,50}off.{0,180}Claude Code, Codex and Cursor.{0,100}machine hooks/i);
    const reference = page('enterprise/enrollment.mdx');
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

    const reference = page('enterprise/machine-policy.mdx');
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
      'enterprise/machine-policy.mdx',
      'enterprise/windows.mdx',
      'enterprise/mdm/intune-windows.mdx',
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
    const tui = source('docs-site/content/docs/tui.mdx');
    const asksRow = tui.split('\n').find((line) => line.startsWith('| Asks |')) ?? '';
    const ui = source('cli/defenseclaw/tui/services/sandbox_state.py');
    const sandboxGuide = page('reference/sandbox-cli.mdx');
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
    assert.match(page('policies/deterministic-detection.mdx'), new RegExp(`\\b${expected} MCP-description YARA signatures\\b`));
  });

  it('states that unknown connectors make profile explain fail with valid names', () => {
    const thresholds = page('policies/thresholds.mdx');
    assert.match(thresholds, /profile explain.*unknown connector.*(?:HTTP 400|400 Bad Request).*valid connectors/i);
    assert.doesNotMatch(thresholds, /unknown connector.*(?:uses|falls back to|resolves to) (?:the )?(?:default|global) (?:profile|threshold)/i);
  });

  it('limits proxy replacement to Linux and macOS', () => {
    const agents = page('guardrail/switching-connectors.mdx');
    assert.match(agents, /setup openclaw --replace.*Linux and macOS.*native Windows.*(?:unsupported|no guardrail proxy)/i);
  });

  it('aligns the TUI footer and status Policy line with the applied config counter', () => {
    const tui = page('tui.mdx');
    const cli = page('reference/cli.mdx').split('### Policy generation and digest')[1]?.split('### ')[0] ?? '';
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
    const enrollment = page('enterprise/enrollment.mdx');
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
    const row = source('docs-site/content/docs/enterprise/troubleshooting.mdx')
      .split('\n').find((line) => line.startsWith('| `enterprise_managed_gateway_peer_unverified` |')) ?? '';
    assert.match(transport, /hook socket directory .* is not owned by root or the gateway service account/);
    assert.match(transport, /hook socket listener uid .* is neither root nor the gateway service uid/);
    assert.match(row, /Linux and macOS:.*socket directory.*root or the gateway account.*listener UID.*kernel/i);
    assert.doesNotMatch(row, /hook socket is not owned by root or the gateway account/);
  });

  it('does not advertise local files as MCP scan targets', () => {
    const api = page('reference/gateway-api.mdx');
    assert.match(api, /`POST`\s*\|\s*`\/v1\/mcp\/scan`[^\n]*Path or JSON-file targets[^\n]*HTTP 400[^\n]*bare identifier without path or file syntax[^\n]*configured server name/i);
    assert.doesNotMatch(api, /MCP scanner against a target URL or local path/i);
  });

  it('keeps managed readers off per-user HITL commands', () => {
    const ask = page('hitl.mdx');
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
    const identity = page('enterprise/identity-sources.mdx');
    const childDomain = identity.split('On a managed Linux host, check an account as root:')[1]?.split('### Windows')[0] ?? '';
    const groupRow = readFileSync(join(site, 'content/docs/enterprise/identity-and-authentication.mdx'), 'utf8')
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
    const hooks = page('reference/cli.mdx').split('### Per-user hooks (`enterprise hooks`)')[1]?.split('### ACP')[0] ?? '';
    const envVars = page('reference/env-vars.mdx');
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
    const guard = page('enterprise/foreign-hook-guard.mdx');
    assert.match(guard, /foreign_hooks: report.*enterprise policy show/i);
    assert.match(guard, /Cursor, Copilot and Devin.*defenseclaw-hook.*warning.*file and digest.*stderr/i);
    assert.match(guard, /Hermes.*stderr warning.*without the file and digest/i);
    assert.match(guard, /OpenCode and Amp.*enterprise policy show.*file and digest/i);
    assert.doesNotMatch(guard, /GAP-0697|(?:OpenCode|Amp).*drops.*warnings/i);
  });

  it('gives managed profile-explain routes in every identity troubleshooting row', () => {
    const rows = readFileSync(join(site, 'content/docs/enterprise/identity-and-authentication.mdx'), 'utf8')
      .split('\n').filter((line) => line.startsWith('| ') && /profile explain/.test(line));
    assert.ok(rows.length >= 4, 'identity troubleshooting rows are missing');
    for (const row of rows) {
      assert.match(row, /managed.*enterprise .*profile-explain/i, row);
    }
  });

  it('gives a working managed restart route without promising it in the refusal', () => {
    const lifecycle = page('enterprise/lifecycle.mdx');
    assert.match(lifecycle, /Windows \| Run the installed release's Setup with `\/repair JSON=1`/);
    assert.doesNotMatch(lifecycle, /the refusal names the commands below/i);
  });

  it('does not promise a Fleet error message that payload inspection cannot reach', () => {
    const fleet = page('edge-connector/install.mdx');
    assert.match(fleet, /payload_invalid/);
    assert.match(fleet, /--payload <dir>/);
    assert.doesNotMatch(fleet, /`fleet\.enabled is set but the managed payload has no policy_compiler\.py`/);
  });

  it('matches the Windows Claude Code version floor', () => {
    const machine = page('enterprise/machine-policy.mdx');
    assert.match(machine, /Windows.*2\.1\.219.*2\.1\.163.*2\.1\.218/);
    assert.doesNotMatch(machine, /floor stops no build/);
  });

  it('treats bare off as a YAML portability issue', () => {
    const machine = page('enterprise/machine-policy.mdx');
    assert.doesNotMatch(machine, /bare `off`.*config refuses/);
    assert.match(machine, /Quote `"off"`.*YAML 1\.1/);
  });

  it('distinguishes config validation from OpenShell install checks', () => {
    for (const name of ['enterprise/sandboxes.mdx', 'enterprise/sandboxes.mdx']) {
      const sandboxes = page(name);
      assert.match(sandboxes, /config validate.*(?:schema|profile).*ensure.*(?:install|pin)/i, name);
      assert.match(sandboxes, /ensure.*install prerequisites.*exact OpenShell.*install: setup/i, name);
      assert.doesNotMatch(sandboxes, /exits 1 where the gateway would refuse/, name);
    }
  });

  it('gives an executable uninstall route after sandbox teardown', () => {
    const uninstall = page('get-started/install.mdx');
    assert.match(uninstall, /If you already ran `defenseclaw sandbox teardown`.*add `--stop-sandboxes`/);
    assert.match(uninstall, /--stop-sandboxes.*running sandboxes/i);
  });

  it('only names Agent360 panels that ship', () => {
    const dashboard = readFileSync(
      join(repo, 'bundles/local_observability_stack/grafana/dashboards/defenseclaw-agent-360.json'),
      'utf8',
    );
    const agent360 = page('observability/grafana-dashboards.mdx');
    assert.equal(agent360.includes('Last seen'), dashboard.includes('Last seen'));
  });

  it('omits the retired Omnigent bridge from current receipt paths', () => {
    const agent360 = page('observability/grafana-dashboards.mdx');
    assert.doesNotMatch(agent360, /Omnigent policy bridge/i);
  });

  it('states the kiro-cli setup floor from the connector (GAP-1402)', () => {
    assert.ok(source('internal/gateway/connector/kiro.go').includes('const KiroCLIHookFloor = "2.27.1"'));
    assert.ok(page('connectors/kiro.mdx').includes('it needs 2.27.1 or later (`KiroCLIHookFloor`)'));
    assert.ok(!page('connectors/kiro.mdx').includes('per-user installs are not version-gated'));
  });

  it('describes the per-user fail-mode setter the CLI accepts (GAP-1411, GAP-1601)', () => {
    const cmd = source('cli/defenseclaw/commands/cmd_guardrail.py');
    assert.ok(cmd.includes('"On a per-user install an explicit saved mode wins. When unset, the gateway-outage mode follows the "'));
    const cli = page('reference/cli.mdx');
    assert.ok(!cli.includes('so a value is refused with exit 1'));
    assert.ok(cli.includes('`open` or `closed` saves your choice, which wins over the policy tier'));
  });

  it('pins the workspace route for older Kiro IDEs', () => {
    const kiro = page('connectors/kiro.mdx');
    assert.match(kiro, /before 1\.0\.182.*setup kiro --workspace/i);
    assert.doesNotMatch(kiro, /Set `claw\.workspace_dir` to the project root before setup/);
  });

  it('states that CEL static cost can reject a regex below the size ceiling', () => {
    const engine = page('policies/cel/engine.mdx');
    assert.match(engine, /512-byte CEL regex limit.*static cost limit can reject/i);
  });

  it('runs gateway examples on the pinned Go version through the shard runner', () => {
    for (const name of ['policies/cel/engine.mdx', 'policies/cel/authoring.mdx']) {
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
    const api = page('reference/gateway-api.mdx');
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

    const api = page('reference/gateway-api.mdx');
    const upn = api.slice(api.indexOf('`upn` is the account'), api.indexOf('`total` counts'));
    assert.ok(upn.includes('current Windows guardian record takes precedence'));
    assert.ok(upn.includes('an expired or failed directory answer omits'));
    assert.ok(upn.includes('profile matching still uses the last good UPN'));
    assert.ok(upn.includes('an earlier value is not carried into the row'));
    assert.ok(upn.includes('A completed background lookup does not update the row by itself; another hook must run'));

    const reference = page('enterprise/identity-and-authentication.mdx');
    assert.ok(reference.includes('another hook runs after the directory cache has a current UPN'));
    assert.ok(reference.includes('profile matching still uses that last good UPN'));
    assert.ok(reference.includes("Each hook replaces the row's UPN"));
  });
});

describe('Windows AD UPN outage wording', () => {
  it('keeps policy continuity separate from current identity rows', () => {
    const sources = page('enterprise/identity-sources.mdx');
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

describe('per-user install window refusal (GAP-2173)', () => {
  it('every per-user hook refusal during an install says what the upgrade page says', () => {
    const upgrade = page('get-started/upgrade.mdx');
    assert.ok(upgrade.includes('DefenseClaw is being installed or upgraded for this account, and its gateway starts again when that is done. Try again in a moment'));
    for (const [file, pattern] of [
      ['internal/gateway/connector/hooks/_hardening.sh', /DefenseClaw is being installed or upgraded for this account[^']*try again in a moment/],
      ['internal/gateway/connector/hooks/copilot-hook.sh', /DefenseClaw is being installed or upgraded for this account; try again in a moment/],
      ['internal/gateway/connector/hooks/copilot-hook.ps1', /DefenseClaw is being installed or upgraded for this account; try again in a moment/],
      ['internal/gateway/connector/hooks/codex-hook.sh', /DefenseClaw is being installed or upgraded for this account/],
      ['internal/gateway/connector/subprocess.go', /DefenseClaw is being installed or upgraded for this account[^"]*try again in a moment/],
    ] as const) {
      assert.match(source(file), pattern, `${file} no longer gives the install-window refusal the upgrade page describes`);
    }
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
    const tui = page('tui.mdx');
    assert.ok(tui.includes(refusal[1]), 'features/tui.mdx does not quote the launcher refusal');
    assert.ok(tui.includes('/docs/tui#on-a-managed-device'));
    assert.ok(page('tui.mdx').includes('#### On a managed device'));
  });
});

describe('Windows event log check (rel-1-0-4 GAP-0598)', () => {
  it('names enterprise windows events and each of its flags', () => {
    const command = source('internal/cli/windows_enterprise_event_check.go');
    assert.ok(command.includes('Use:   "events"'));
    const flags = [...command.matchAll(/Flags\(\)\.\w+Var\(&\w+, "([a-z-]+)"/g)].map((match) => match[1]);
    assert.deepEqual(flags.sort(), ['application', 'json', 'max']);
    const operations = page('enterprise/operations.mdx');
    assert.ok(operations.includes('enterprise windows events'), 'operations.mdx does not name enterprise windows events');
    for (const flag of flags) {
      assert.ok(operations.includes(`--${flag}`), `operations.mdx does not explain --${flag}`);
    }
    assert.ok(command.includes('within two minutes') && operations.includes('within two minutes'));
    assert.ok(page('reference/cli.mdx').includes('| `events` | Standalone |'));
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
    const state = page('policies/cel/tool-call-state.mdx');
    assert.ok(state.includes('Hermes `on_session_end` (which Hermes sends at the end of every turn'));
    assert.ok(/\| \[Hermes\][^\n]*\| `paired-outcomes` \|/.test(readFileSync(join(site, 'content/docs/policies/cel/tool-call-state.mdx'), 'utf8')));
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
    phrases: ['Codex runs the tool when its `PreToolUse` hook is stopped, killed or times out.', 'If the hook stopped before it reached the gateway', 'If it reached the gateway first, the gateway can still record the call', 'It does not prevent a timeout', '`hook_process_fail_open`', '/docs/enterprise/machine-policy#vendor-limits'],
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
    phrases: ["Copilot CLI runs the tool when its `preToolUse` hook times out or cannot start, even when DefenseClaw's fail mode is `closed`.", 'per-user and managed installs on every OS', 'If it reached the gateway first, the gateway can still record the call', '`hook_process_fail_open`', '/docs/enterprise/machine-policy#vendor-limits'],
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
    phrases: ['Without linger, signing out of your last session stops the gateway and its MicroVMs', 'This is how systemd works', '`sudo loginctl enable-linger USER`', '/docs/sandboxes/guide#a-linux-sign-out-ends-a-running-microvm'],
    from: [],
  },
  { gaps: 'GAP-1194', section: 'Claude Code shell', phrases: ['shell mode', 'on every OS, to per-user and managed installs, in observe and action mode', 'It is a Claude Code limit'], from: ['connectors/claudecode.mdx'] },
  { gaps: 'GAP-1163', section: 'Upgrade and policy limits', phrases: ['**Legacy MicroVM guests:**'], from: [] },
  {
    gaps: 'GAP-0716, GAP-0716-MAC, GAP-0716-WIN',
    section: 'Upgrade and policy limits',
    phrases: ['**Managed policy before launch:**', 'on managed Linux, macOS and Windows', 'a process device map on Windows', 'This is an operating system limit', '`unprivileged_user_namespaces`', '`user.max_user_namespaces=0`', '/docs/enterprise/linux#user-namespaces', '/docs/enterprise/macos#machine-policy', '/docs/enterprise/windows#inspect-machine-policy'],
    from: [],
  },
  {
    gaps: 'GAP-0565',
    section: 'Codex',
    phrases: ['the `Sandbox ready` step', '`approval required by policy, but AskForApproval::Granular.sandbox_approval is false`', 'Codex does this with or without DefenseClaw', 'It is a Codex limit.', 'Quit Codex and start it again once'],
    from: ['connectors/codex.mdx', 'connectors/codex.mdx'],
  },
  { gaps: 'GAP-1110', section: 'Local Splunk', phrases: ['works only with an x86_64 Docker engine', 'published for x86_64 (amd64) only', 'This is a Splunk image limit.', '/docs/observability/splunk#before-you-start'], from: [] },
  { gaps: 'GAP-1565', section: 'Upgrade and policy limits', phrases: ['**Restored hook records on managed macOS:**', '`hook_contract_lock.json`', 'the guardian rewrites, within seconds, the records that no longer match the live registration', 'compare the hook commands, not the file bytes'], from: [] },
  { gaps: 'GAP-0999', section: 'Sandboxes', phrases: ['**Raw OpenShell during a gateway restart:**', 'OpenShell has no admission barrier that raw clients honor', 'one started after the last check is ended by the restart', 'This is an OpenShell limit.', '/docs/sandboxes/guide#a-raw-openshell-sandbox-stops-a-restart-or-rollback'], from: [] },
  { gaps: 'GAP-1177', section: 'Sandboxes', phrases: ['**No network cutoff for a contained MicroVM:**', 'the VM stays reported as unprotected and new DefenseClaw runs are refused', 'OpenShell has no VM pause or network-off operation', 'This is an OpenShell and platform limit.', '/docs/sandboxes/guide#a-contained-vm-has-no-confirmed-network-withdrawal'], from: [] },
] as const;

function knownLimitSection(heading: string): string {
  const raw = readFileSync(join(docs, 'support-matrix.mdx'), 'utf8');
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
      const target = `/docs/support-matrix#${anchor(entry.section)}`;
      for (const name of entry.from) {
        const limits = page(name).split('## Limits')[1]?.split(' ## ')[0] ?? '';
        assert.ok(limits.includes(target), `${name} Limits does not link ${target}`);
      }
    });
  }

  it('keeps the page title free of a release number', () => {
    const raw = readFileSync(join(docs, 'support-matrix.mdx'), 'utf8');
    assert.match(raw, /^## Known limits$/m);
    for (const name of ['get-started/upgrade.mdx', 'connectors/codex.mdx', 'connectors/copilot.mdx']) {
      assert.ok(!page(name).includes('Known limits in 1.0'), `${name} names an old release in the known-limits link`);
    }
  });

  it('lists every section in the troubleshooting index summary', () => {
    const index = page('get-started/upgrade.mdx');
    const line = index.split('[Known limits](/docs/support-matrix):')[1]?.split(' - [')[0] ?? '';
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
    // coverage (GAP-1861) routes it through MarkSecurityIncomplete, which sets security_complete false.
    assert.match(status, /r\.MarkSecurityIncomplete\(CodeHookProcessFailOpen\)/);
    assert.match(source('internal/enterprisestatus/result.go'), /func \(r \*Result\) MarkSecurityIncomplete\(reason string\) \{\s*r\.SecurityComplete = false/);
  });

  // A hook that times out may already have reached the gateway, which can then
  // record the call. Every timeout entry must keep the "no audit row" claim to
  // hooks that never reached it, and must not offer signal protection as a cure
  // for timeouts.
  it('scopes every hook-timeout entry on the page', () => {
    const raw = readFileSync(join(docs, 'support-matrix.mdx'), 'utf8');
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
  // GH #1100 Windows Remove items (docs pod, 2026-10-28, live on rc.8): the installed CLI uninstall keeps lifecycle.lock, a disconnected session keeps its registrations.
  { gap: "GH #1100 p0:GAP-0764", page: "enterprise/windows.mdx", section: "Remove", has: ["A plain installed CLI uninstall leaves the lock file and its folder", "`C:\\ProgramData\\Cisco\\DefenseClaw-Lifecycle` from an elevated prompt once no", "not remove a lock an earlier uninstall left."] },
  { gap: "GH #1100 p0:GAP-0675", page: "enterprise/windows.mdx", section: "Remove", has: ["active (connected) session, running as each user.", "session is disconnected (`query user` shows `Disc`), keep theirs and are named in"] },
  { gap: "GH #1100 p0:GAP-0675", page: "enterprise/lifecycle.mdx", section: "Uninstall notes", has: ["out, or whose session is disconnected, keep theirs."], lacks: ["from every signed-in user's agent config"] },
  { gap: "GH #1100 p0:GAP-0675", page: "enterprise/threat-model.mdx", section: "Residual risks", has: ["of signed-out users and users whose session is disconnected"] },
  // GH #1100 p0:GAP-0742 (docs pod, 2026-10-28, live managed RHEL rc.8): chmod 000 ~/.defenseclaw is set back to 0700 with no warning; a link in its place is guardian_target_user_path.
  { gap: "GH #1100 p0:GAP-0742", page: "enterprise/operations.mdx", section: "Per-user connector state", has: ["`~/.defenseclaw` and `~/.defenseclaw/hooks` follow one rule.", "the guardian sets its mode back to `0700` within a minute, also after `chmod 000`, and reports nothing", "A link or a file in place of either folder is not changed: it is reported as `guardian_target_user_path`", "other than `~/.defenseclaw` and its hooks folder, which the guardian sets back to `0700`"] },
  { gap: "GH #1100 p0:GAP-0742", page: "enterprise/troubleshooting.mdx", section: "Lifecycle error codes", has: ["An unreadable `~/.defenseclaw` or `~/.defenseclaw/hooks` is not on this list: the guardian sets it back to `0700`."] },
  // GH #1101 reference items (docs pod, 2026-10-28): config limits, block_message refusal, pack manifest re-pin.
  { gap: "GH #1101 p0:GAP-0677", page: "enterprise/configuration.mdx", section: "Where the config lives", has: ["The file may be at most 4 MiB and 65,536 parsed YAML nodes.", "`configuration source exceeds the 4 MiB limit`", "`parsed YAML exceeds the 65,536-node limit`", "move rules into a [custom rule pack](#custom-rule-packs)"], lacks: ["The file is limited to 4 MiB and 65,536 YAML nodes."] },
  { gap: "GH #1101 p0:GAP-0677", page: "enterprise/windows.mdx", section: "2. Write the config", has: ["The file may be at most 4 MiB and 65,536 YAML nodes", "([limits](/docs/enterprise/configuration#where-the-config-lives))"] },
  { gap: "GH #1101 p0:GAP-0765", page: "enterprise/configuration.mdx", has: ["A longer one is refused with `guardrail.block_message must be a string of at most 4096 characters (it has 4097)`"] },
  { gap: "GH #1101 p0:GAP-0777", page: "policies/rulepack-validation.mdx", has: ["Adding or editing that file changes the digest, so validate the pack again and pin the new digest"] },
  // 1.0.5 docs sync (2026-10-28): fixed 1.0.4 known issues left the page; open ones stay.
  { gap: "1.0.4 known issues fixed in 1.0.5", page: "support-matrix.mdx", section: "Known issues", lacks: ["These are bugs in 1.0.4.", "**Changing the fail mode with Setup `/ensure`:**", "hot-config-undo-closed", "**No skill, MCP or plugin scanner:**"] },
  { gap: "GAP-2329, GAP-0956, GAP-2285", page: "support-matrix.mdx", section: "Known issues", has: ["**Ordinary work blocked:**", "`alias ll=ls`", "`defenseclaw guardrail mode observe --connector NAME`"] },
  { gap: "GAP-2001", page: "enterprise/troubleshooting.mdx", has: ["the run stops with `hook_in_use` and exit `1618` before it replaces anything"] },
  { gap: "GAP-2049", page: "policies/deterministic-detection.mdx", section: "Action-mode rule details", has: ["The permissive pack keeps it at HIGH and reports it."] },
  { gap: "GAP-1519", page: "connectors/index.mdx", section: "Pick yours", has: ["| [GitHub Copilot CLI](/docs/connectors/copilot) | Hook | Tool calls | No: a confirmation blocks |", "Where an agent cannot ask, a confirm verdict becomes an alert with the original action kept; Copilot CLI blocks it instead."], lacks: ["| Tool calls | `preToolUse` |"] },
  { gap: "GAP-1537", page: "enterprise/mdm/intune-linux.mdx", has: ["The wrapper itself makes up to three attempts on exit `75` (busy): the first run and two retries, 10 seconds apart."], lacks: ["retries exit `75` (busy) up to three times"] },
  { gap: "GAP-2242", page: "sandboxes/network.mdx", has: ["for example `pack open (sha256:…), network allowlist (balanced), approvals triage`"], lacks: ["for example `profile balanced, pack open`"] },
  { gap: "GAP-2360", page: "guardrail/index.mdx", has: ["| **Select hook fail mode** *(asked only when this run turns the guardrail on or switches between observe and action;", "`defenseclaw init` already turns the guardrail on, so a later run that keeps the mode does not ask it."], lacks: ["asked on first setup or when the mode changes", "there is no hook fail mode question"] },
  { gap: "GAP-2235", page: "guardrail/unified-llm-key.mdx", has: ["and no `--instance-name` drops the instance", "binding, so the role stops using the custom instance."] },
  { gap: "GAP-2249", page: "stories/observe-claude-code.mdx", has: ["through its [native hooks](/docs/connectors/claudecode).", "Host setup turns Claude Code's native OpenTelemetry export off", "`CLAUDE_CODE_ENABLE_TELEMETRY=0`", "DefenseClaw sees Claude Code through its hooks only. Only an isolated OpenShell sandbox keeps native logs and metrics."], lacks: ["receives its native OpenTelemetry logs and metrics", "native hooks and OpenTelemetry]"] },
  { gap: "GAP-2366", page: "reference/env-vars.mdx", has: ["`DEFENSECLAW_ENTERPRISE_PROFILE` exported in a shell is dropped when the", "command starts. The writers keep writing as usual, and `defenseclaw doctor`", "lists the variable under `Ignored environment overrides`."], lacks: ["process's writers refuse changes (exit code `3`"] },
  { gap: "GAP-2365", page: "guardrail/switching-connectors.mdx", has: ["`Codex is already configured; re-apply its hooks (mode=action)? [Y/n]:`", "A re-run never asks Add, Replace or Cancel.", "`Configure DefenseClaw for Codex enforcement now? [Y/n]:`", "the agent's current mode when it is already set up, observe for a new one"] },
  { gap: "GAP-2221", page: "edge-connector/install.mdx", has: ["when no Fleet API token is saved yet, setup first asks `Generate a new fleet API bearer token? [Y/n]`", "so `sudo` can ask for your password", "Edge setup is incomplete`, and Fleet stays off"] },
  { gap: "GAP-2171", page: "enterprise/operations.mdx", has: ["it prints `unknown flag` and exits `1`, not `1639`"] },
  { gap: "GAP-2171", page: "enterprise/troubleshooting.mdx", has: ["exits `1` with `unknown flag` before the lifecycle runs"] },
  { gap: "GAP-2367", page: "reference/setup-commands.mdx", has: ["writes it to `ai_discovery.trusted_binary_prefixes` in `~/.defenseclaw/config.yaml`"], lacks: ["and persists to `~/.defenseclaw/.env`"] },
  { gap: "GAP-2367", page: "reference/cli.mdx", has: ["writes it to `ai_discovery.trusted_binary_prefixes` in `~/.defenseclaw/config.yaml`"], lacks: ["and persists to `~/.defenseclaw/.env`"] },
  { gap: "GAP-2368", page: "get-started/windows/paths-troubleshooting.mdx", has: ["The watchdog is on by default (`gateway.watchdog.enabled` is `true`)", "set `gateway.watchdog.enabled` to `false` to turn it off"], lacks: ["The watchdog runs only when `gateway.watchdog.enabled` is set"] },
  { gap: "GAP-2363", page: "guardrail/multi-connector.mdx", has: ["Setup first asks the new agent's enforcement mode, prints what it will change, and then", "ask `Proceed? [Y/n]`; Enter applies it, and `--yes` skips the question in scripts."] },
  { gap: "GAP-2354", page: "reference/fail-modes.mdx", has: ["On a per-user install with the `default` or `permissive` rule pack, a call DefenseClaw would allow still runs.", "On a per-user install with the `strict` rule pack, on a managed install and inside an OpenShell sandbox, the call is blocked"], lacks: ["(disk full, database busy), the call is denied."] },
  { gap: "GAP-2356", page: "guardrail/user-and-group-policies.mdx", section: "Before you start", has: ["Steps 1 to 3 are for a per-user install. A managed host (Linux, macOS or Windows) has no `defenseclaw guardrail` commands", "`defenseclaw.exe config validate FILE` and `defenseclaw.exe enterprise windows profile-explain --user CORP\\alice`"] },
  { gap: "GAP-2357", page: "guardrail/user-and-group-policies.mdx", section: "Steps", has: ["With no `--user`, `guardrail profile explain` explains the account that runs the command. The managed `enterprise linux|macos|windows profile-explain` commands need `--user`."], lacks: ["3. Ask which profile a person gets. With no `--user`, it explains the account that runs the command."] },
  { gap: "GAP-2332", page: "scanning/index.mdx", has: ["The defaults quarantine CRITICAL and HIGH skills, warn on MEDIUM and queue it for review, and allow LOW and INFO.", "`defenseclaw config get admission.skill` shows the actions in force"], lacks: ["A skill whose worst finding is MEDIUM, LOW or INFO is installed with the `warning` verdict"] },
  { gap: "GAP-2353", page: "guardrail/unified-llm-key.mdx", has: ["While the guardrail is on, the `DEFENSECLAW_LLM_KEY` row still reads `OPTIONAL`", "A local judge's `JUDGE_API_KEY` row reads `NOT_USED`."], lacks: ["correctly classifies them as `NOT_USED` even when the feature is on"] },
  { gap: "GAP-0515", page: "connectors/hermes.mdx", has: ["On Windows, where Hermes has no guard, an administrator's `open` lets the call run during an outage: the user's `hook-failures.jsonl` gets a line with `fail_mode` `open` and `outcome` `fail_open`.", "through the [foreign-hook guard](/docs/enterprise/foreign-hook-guard) while `foreign_hooks` is `remove`"], lacks: ["(service not running, unusable answer, call too large to inspect)", "The administrator-owned hook is stricter"] },
  { gap: "GAP-2350", page: "enterprise/troubleshooting.mdx", has: ["| `security_incomplete` | Linux, macOS, Windows |", "security_complete is false because of:"], lacks: ["| `security_incomplete` | Windows |"] },
  { gap: "GAP-1696", page: "enterprise/troubleshooting.mdx", section: "`security_complete` is `false` on Windows", has: ["`security_incomplete` lists the reasons and names the actionable causes even next to `hook_process_fail_open`"], lacks: ["on 1.0.3 or a host without Claude Code or Codex"] },
  { gap: "GAP-2351", page: "reference/configuration.mdx", section: "Per-connector files", has: ["warns `a generated script is not the one setup rendered`", "fails the `Hook runtime files` row (`changed since setup`)"], lacks: ["warns `stale generated script` when one no longer matches"] },
  { gap: "GAP-2351", page: "reference/cli.mdx", has: ["warns `a generated script is not the one setup rendered (...)` instead, next to the `Hook runtime files` FAIL"] },
  { gap: "GAP-2347", page: "connectors/hermes.mdx", has: ["on a per-user install it is reported as a `guardrail-degraded` alert when the gateway starts again. A managed gateway raises no such alert"], lacks: ["`~/.defenseclaw/logs/hook-failures.jsonl` and reported as a `guardrail-degraded` alert"] },
  { gap: "GAP-0515", page: "enterprise/foreign-hook-guard.mdx", section: "Which connectors it covers", has: ["| Hermes | On Linux and macOS, unless `foreign_hooks: allow` |", "The Windows Hermes registration does not run the guard."] },
  { gap: "GAP-0515", page: "reference/fail-modes.mdx", has: ["the guard checks the session of Copilot calls on every OS and of Hermes calls on Linux and macOS with the gateway", "and to Hermes on Linux and macOS"], lacks: ["Amp and Hermes need the gateway's session record"] },
  { gap: "GAP-2330", page: "reference/index.mdx", has: ["Map each `fail` and `warn` check by its label or message. The table below has the common ones; for any other row, run the `Next step:` line doctor prints under it"], lacks: ["to an entry on [Troubleshooting](/docs/get-started/upgrade) by its label"] },
  { gap: "GAP-2359", page: "guardrail/index.mdx", has: ["guardrail.detection_strategy: regex_only", "so the setup summary and `guardrail status` show the strategy that runs: `regex_only`."], lacks: ["guardrail.detection_strategy: regex_judge"] },
  { gap: "GAP-2337", page: "enterprise/rollout.mdx", section: "Step 1: Choose the agents", has: ["A key that names no DefenseClaw connector (a", "stop with `config_invalid` and name the key; Windows Setup refuses it the same way."] },
  { gap: "GAP-2338", page: "enterprise/identity-sources.mdx", has: ["and `subject.principal` are empty, and the text output shows the account name", "The `subject` object has no domain field"], lacks: ["`subject.domain`"] },
  { gap: "GAP-2333", page: "connectors/capability-matrix.mdx", has: ["| Family | `proxyConnectors` and `IsProxyConnector()` in `internal/gateway/connector/platform_support.go`"], lacks: ["RoutingConnector"] },
  { gap: "GAP-2240", page: "policies/defaults.mdx", has: ["Available policies: * default [built-in] [active] Balanced security policy", "Activate a policy: defenseclaw policy activate <name> Show details: defenseclaw policy show <name>", "`*` and `[active]` mark the active preset."], lacks: ["Available policies: default [built-in]"] },
  { gap: "GAP-2247", page: "scanning/mcp-scanner.mdx", has: ["| `analyzers` | unset, read back as `auto` | The analyzers to run. Unset (`config get` prints `auto`) and `[]` both mean YARA, plus the LLM judge when it is ready. |"], lacks: ["| `analyzers` | `[]` (auto) |"] },
  { gap: "GAP-2293", page: "reference/cli.mdx", section: "Managed devices and exit code 3", has: ["`config set` prints `This device is managed: change config.yaml in the admin config (MDM or management plane); config set did not change it`", "no `version` command (run `defenseclaw.exe --version`) and no `policy activate`", "`connector list-backups`, exit `1` with `this computer's DefenseClaw is managed by your organization`", "(the Windows package has no `policy activate`; see below)"], lacks: ["`rollback` with a note that the computer is managed, refuses `config set`,"] },
  { gap: "GAP-2293", page: "reference/cli.mdx", section: "Gateway daemon", has: ["On a managed Windows computer `status`, `audit findings` and `connector list-backups` have no per-user gateway to read and exit `1`"] },
  { gap: "GAP-2287", page: "enterprise/troubleshooting.mdx", has: ["`installed_version` is the recorded version when an administrator gave an unknown `--profile`; it is omitted for a standard account, which cannot read the deployment record."], lacks: ["because they were not checked, and `installed_version` is omitted."] },
  { gap: "GAP-2300", page: "enterprise/configuration.mdx", section: "Files next to the config", has: ["on Windows an `ensure` that repairs a missing record keeps the proven count and says `(recovered config generation)` in `reason` instead"] },
  { gap: "GAP-2301", page: "enterprise/configuration.mdx", section: "Where the config lives", has: ["(Administrators and SYSTEM full control; the gateway service, `NT SERVICE\\DefenseClawGateway`, can only read it)"], lacks: ["config.yaml` (Administrators only)"] },
  { gap: "GAP-1461", page: "policies/defaults.mdx", has: ["Writes to the active user's `authorized_keys` are blocked in action mode when a direct command, a file tool or a supported literal interpreter form proves the target; in observe mode the same write raises a CRITICAL would-block alert and runs."], lacks: ["Writes to the active user's `authorized_keys` are blocked when"] },
  { gap: "GAP-0044", page: "sandboxes/guide.mdx", has: ["A stop DefenseClaw makes for your organization's policy (a hook alarm, a revoked registration) does not end a MicroVM whose disk could not sync either"], lacks: ["still goes ahead and the activity feed says what may be lost"] },
  { gap: "GAP-0044", page: "reference/sandbox-cli.mdx", has: ["A stop DefenseClaw makes for your organization's policy (a hook alarm, a revoked registration) does not end a MicroVM whose disk could not sync either"], lacks: ["still goes ahead and the activity feed says what may be lost"] },
  { gap: "GAP-2192", page: "enterprise/identity-entra-id.mdx", has: ['<Callout type="warn" title="Not part of the release certification">', "Active Directory is the certified identity stack. The Entra setups below were last verified live in October 2026"], lacks: ["1.0.4 certification", "certified identity stack in 1.0.4"] },
  { gap: "GAP-2192", page: "enterprise/identity-okta.mdx", has: ['<Callout type="warn" title="Not part of the release certification">', "Active Directory is the certified identity stack. The Okta lab is retired"], lacks: ["1.0.4 certification", "certified identity stack in 1.0.4"] },
  { gap: "GAP-2192", page: "enterprise/identity-sources.mdx", has: ["Active Directory is the certified identity stack; the Okta and Entra parts were last verified live in October 2026."], lacks: ["certified in 1.0.4"] },
  { gap: "GAP-2158", page: "guardrail/unified-llm-key.mdx", has: ["## The `keys` subcommands"], lacks: ["All four `keys` subcommands"] },
  { gap: "GAP-2309", page: "connectors/opencode.mdx", has: ["a managed standalone OpenCode plugin stays closed and blocks the outage even when the administrator selects open", "Under Secure Client an administrator can choose outage-only open; on a managed standalone host OpenCode blocks the outage under either mode."], lacks: ["On managed hosts, an administrator may select open for a classified outage only", "A managed administrator can choose outage-only open."] },
  { gap: "GAP-2314", page: "connectors/devin.mdx", has: ["in a project `.devin/hooks.v1.json` setup and teardown edit only DefenseClaw's entries, so your comments, formatting and a UTF-8 BOM stay.", "If setup cannot edit the project file in place, for example when it has a duplicate top-level key, it writes it back as JSON too, so its comments, formatting and BOM are removed."], lacks: ["Modified hook files are written as JSON, so comments and formatting are removed", "but writes a changed file back as JSON, so comments and formatting are removed"] },
  { gap: "GAP-0826", page: "reference/fail-modes.mdx", section: "Refusals that ignore the fail mode", has: ["so they block in every fail mode on a managed standalone computer:", "Secure Client hooks are different for a refused credential: an HTTP 401 or 403 follows the effective fail mode"], lacks: ["so they block in every fail mode on a managed computer:"] },
  { gap: "GAP-0826", page: "connectors/capability-matrix.mdx", has: ["a refused credential (outside Secure Client, where an HTTP 401 or 403 follows the effective fail mode)"], lacks: ["an invalid managed runtime, a refused credential, and,"] },
  { gap: "GAP-2315", page: "ai-discovery.mdx", section: "Before you start", has: ["On a managed (standalone enterprise) Linux or macOS computer every command in it refuses, for enrolled users and for root alike", "`sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux discovery`", "run `defenseclaw.exe enterprise windows discovery` from an elevated prompt"] },
  { gap: "GAP-2215", page: "ai-discovery.mdx", section: "AIBOM (AI Bill of Materials)", has: ["With `--json` one connector prints one JSON object; several print a JSON array with one object per connector, each naming its `connector`.", "with several connectors each array element has this shape"], lacks: ["and merges them into a single document"] },
  { gap: "GAP-2317", page: "support-matrix.mdx", section: "Known issues", lacks: ["**A saved fail mode is not used in 1.0.4:**", "on a per-user install the outage behavior follows the policy tier, as [Fail modes](/docs/reference/fail-modes) says"] },
  { gap: "GAP-1821", page: "support-matrix.mdx", section: "Known issues", lacks: ["**Claude Code settings can keep a variable from 1.0.2 or 1.0.3**", "keep a variable from 1.0.2**. After an upgrade from 1.0.2, the"] },
  { gap: "GAP-0012", page: "support-matrix.mdx", section: "Upgrade and policy limits", has: ["If that sync fails (a frozen guest, for one), the stop is held and the guest keeps running", "`defenseclaw sandbox stop NAME --discard-unsynced` stops it anyway and loses what it wrote since its last sync; the activity feed then shows `stop_unflushed`"], lacks: ["The stop requests a disk sync, but changes made after the last successful sync may be lost."] },
  { gap: "GAP-0012", page: "sandboxes/guide.mdx", section: "A MicroVM stop is held because its disk could not sync", has: ["To stop it anyway, run `defenseclaw sandbox stop NAME --discard-unsynced`", "the activity feed shows `stop_unflushed`"] },
  { gap: "GAP-0516", page: "reference/env-vars.mdx", section: "Managed hosts and the environment", has: ["`DEFENSECLAW_FAIL_MODE` is not one of them: a managed hook uses only the fail mode the administrator installed", "security opt-outs (`DEFENSECLAW_FAIL_MODE` among them;"], lacks: ["`DEFENSECLAW_FAIL_MODE` is passed through for older installed hooks", "opt-outs except `DEFENSECLAW_FAIL_MODE` and"] },
  { gap: "GAP-0516", page: "enterprise/threat-model.mdx", has: ["`DEFENSECLAW_FAIL_MODE` is ignored in both directions: the installed fail mode applies"], lacks: ["`DEFENSECLAW_FAIL_MODE`, `DEFENSECLAW_STRICT_AVAILABILITY`, `DEFENSECLAW_HOOK_MAX_BODY` and `DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS` count only when stricter"] },
  { gap: "GAP-0669", page: "stories/cursor-secret-exfil.mdx", has: ["cursor gateway outage=open (failClosed=true)", "`failClosed=true` in `hooks.json` only covers a hook process that cannot answer."], lacks: ["cursor hook failures=closed"] },
  { gap: "GAP-2132", page: "guardrail/index.mdx", has: ["`defenseclaw doctor` shows `Config file` (`canonical schema valid`) and `Rule pack` as `[PASS]`"], lacks: ["shows `Config validation` and `Rule pack` as `[PASS]`"] },
  { gap: "GAP-2132", page: "reference/keys.mdx", has: ["`defenseclaw doctor` shows `Config file` (`canonical schema valid`) as `[PASS]` on every OS"], lacks: ["shows `Config validation` as `[PASS]`", "on Windows the row is `Config file`"] },
  { gap: "GAP-2145", page: "get-started/first-run.mdx", has: ["`init` does not ask for an outage mode and saves none", "Omitted, nothing is saved: the default and permissive policies let a call run with a warning, strict blocks it."], lacks: ["closed on a new install", "On a new install the fail mode prompt offers `closed`"] },
  { gap: "GAP-2238", page: "get-started/first-guardrail.mdx", has: ["Claude Code claudecode enabled observe open default"], lacks: ["observe closed default"] },
  { gap: "GAP-2238", page: "stories/switch-connectors.mdx", has: ["Claude Code claudecode enabled observe open default", "Codex codex enabled observe open default"], lacks: ["observe closed default"] },
  { gap: "GAP-2210", page: "get-started/upgrade.mdx", has: ["1.0.5 upgrades any 1.0 release and is tested from 1.0.4, 1.0.3 and 1.0.2.", "This is a legacy path that is no longer tested."], lacks: ["1.0.4 supports upgrades from", "the supported bridge"] },
  { gap: "GAP-2173", page: "get-started/upgrade.mdx", section: "Upgrade", has: ["DefenseClaw refuses every agent call that gets no answer from the gateway.", "with a saved `open` too: an install or upgrade is not a gateway outage", "DefenseClaw is being installed or upgraded for this account, and its gateway starts again when that is done. Try again in a moment", "The installer waits up to 3 minutes for a slow gateway start, and the window ends when the installer exits, also if it fails."], lacks: ["12 to 16 seconds"] },
  { gap: "GAP-2173", page: "reference/fail-modes.mdx", section: "Per-user installs", has: ["while the installer has the gateway stopped: every call blocks in every tier, a saved `open` included"], lacks: ["Per-user default and permissive calls that receive a usable gateway allow may proceed"] },
  { gap: "GAP-2175", page: "enterprise/operations.mdx", has: ["The lifecycle `status --json` and `verify --json` results carry the same digest as `policy.effective_digest` on every OS", "`policy verify` does not print it."], lacks: ["It is the only way to"] },
  { gap: "GAP-2182", page: "reference/migrate-v9.mdx", has: ["[Moving from the 0.8.x Setup package](/docs/get-started/upgrade#windows-moving-from-the-setup-package)"], lacks: ["[Moving from the 0.8.x Setup package](/docs/get-started/windows)"] },
  { gap: "GAP-2182", page: "get-started/upgrade.mdx", has: ["### Windows: moving from the Setup package"] },
  { gap: "GAP-2198", page: "enterprise/mdm/intune-tenant.mdx", has: ["[The helper](#the-helper)", "[Troubleshooting](#troubleshooting)", "[Guardrail profiles and Entra groups](#guardrail-profiles-and-entra-groups)", "## The helper", "## Troubleshooting"], lacks: ["](/docs/enterprise/mdm/intune-tenant)", "[tenant reference]"] },
  { gap: "GAP-1681", page: "connectors/claudecode.mdx", has: ["setup writes the hooks through a link to a file you own, also when that file is outside your home folder", "A link or target that another account owns is refused, and setup changes nothing.", "On a managed install a link that leads out of your home folder is refused too."], lacks: ["A link anywhere else is refused before any hook is written."] },
  { gap: "GAP-1683", page: "connectors/claudecode.mdx", has: ["host setup removes only exporters DefenseClaw wrote; your own exporters stay", "An exporter you set yourself, such as your own collector in `OTEL_EXPORTER_OTLP_ENDPOINT`, stays with the settings that turn it on", "An exporter you added yourself is yours and stays, and so does an earlier install's exporter whose credential is gone"], lacks: ["host upgrades remove old exporters", "setup sets Claude Code telemetry and all OTLP exporters off", "host setup disables them"] },
  { gap: "GAP-1683", page: "get-started/windows/paths-troubleshooting.mdx", has: ["remove the native OTLP settings and tokens they can prove DefenseClaw wrote", "An exporter you set yourself stays.", "An earlier install's exporter whose token is gone also stays"], lacks: ["Host Codex and Claude Code setups remove native OTLP settings and tokens because"] },
  { gap: "GAP-1683", page: "get-started/windows/telemetry-security.mdx", has: ["An exporter you set yourself stays."], lacks: ["Host setup disables Codex and Claude Code native OTLP"] },
  { gap: "GAP-1683", page: "connectors/claudecode.mdx", section: "How Claude Code reaches the gateway", has: ["the scoped credential setup gave Claude Code (the current one or one it recorded as retired)", "Setup writes the content settings (`OTEL_LOG_USER_PROMPTS` and the other `OTEL_LOG_*` keys) as `0`; a value you set yourself stays.", "without its own `_HEADERS` key sends the generic `OTEL_EXPORTER_OTLP_HEADERS` an earlier DefenseClaw release wrote, so setup removes it with them.", "An exporter left by an earlier install whose credential is gone also stays, even when it sends `x-defenseclaw-*` headers"], lacks: ["`OTEL_LOG_*` keys) stay `0`", "a value that carries a DefenseClaw credential"] },
  { gap: "GAP-1683", page: "get-started/windows/telemetry-security.mdx", has: ["value with the scoped credential setup gave that connector (current, or recorded as retired)", "An exporter left by an earlier install whose credential is gone also stays, even with `x-defenseclaw-*` headers"], lacks: ["a value with a DefenseClaw credential", "also one that points at an old local port."] },
  { gap: "GAP-2222", page: "reference/configuration.mdx", has: ["```text (source: config:guardrail.block_at) HIGH ```", "The source line comes first and goes to standard error"], lacks: ["```text HIGH (source: config:guardrail.block_at) ```"] },
  { gap: "GAP-2189", page: "enterprise/index.mdx", has: ["Exit `3`: `This device is managed: the asset_policy block and allow lists are set in the admin config (MDM or management plane)`"], lacks: ["add it to asset_policy"] },
  { gap: "GAP-2189", page: "reference/source-of-truth.mdx", has: ["This device is managed: the asset_policy block and allow lists are set in the admin config (MDM or management plane)"], lacks: ["add it to asset_policy"] },
  { gap: "GAP-2189", page: "policies/admission.mdx", has: ["This device is managed: the asset_policy block and allow lists are set in the admin config (MDM or management plane)"], lacks: ["add it to asset_policy"] },
  { gap: "GAP-2189", page: "tui.mdx", has: ["`This device is managed: the asset_policy block and allow lists are set in the admin config (MDM or management plane)`"], lacks: ["add it to asset_policy"] },
  { gap: "GAP-2266", page: "enterprise/get-started.mdx", has: ["\"message\": \"claudecode: a killed PreToolUse hook or PreToolUse timeout is non-blocking; ...\"", "{ \"code\": \"security_incomplete\"", "once per enabled connector"], lacks: ["Codex can run a tool after its PreToolUse hook is killed or times out"] },
  { gap: "GAP-2266", page: "enterprise/linux.mdx", has: ["\"message\": \"codex: a killed PreToolUse hook or PreToolUse timeout is non-blocking; ...\"", "{ \"code\": \"unprivileged_ptrace\"", "appears once per enabled connector"], lacks: ["Codex can run a tool after its PreToolUse hook is killed or times out"] },
  { gap: "GAP-2211", page: "reference/cli.mdx", has: ["the bare `alice` exits `1` with `user lookup failed: no account named \"alice\" on this host`", "(`profile-explain` excepted: it resolves one account, so it needs the name `getent passwd` prints or the uid)"], lacks: ["`--user U` (account name, uid, SID or principal)"] },
  { gap: "GAP-2211", page: "enterprise/identity-and-authentication.mdx", has: ["or the managed `profile-explain --user alice` exits `1` with `user lookup failed"] },
  { gap: "GAP-2292", page: "reference/cli.mdx", has: ["(on Windows `No policy_dir is set, so the gateway loads no Rego: the admission policy is compiled from config.yaml alone.`)", "and `test` says there is nothing to run; both exit `0`."] },
  { gap: "GAP-2294", page: "reference/configuration.mdx", has: ["An unknown `auth_mode` makes the file invalid: `defenseclaw config validate` exits `1`", "the gateway does not load the file", "A sub-block from another family is accepted and ignored"], lacks: ["`defenseclaw doctor` warns about family mismatches and unknown `auth_mode` values."] },
  { gap: "GAP-2297", page: "reference/fail-modes.mdx", has: ["and `defenseclaw status --json` (`fail_mode.drift`) report the drift until a refresh succeeds", "or a running gateway's own registration repair, which usually follows within seconds", "On Windows `status --json` also lists `policy-unverified` for Codex"], lacks: ["`--no-restart` saves without refreshing; `guardrail status` reports drift until a refresh succeeds."] },
  { gap: "GAP-1633", page: "connectors/cursor.mdx", has: ["An explicit `--fail-mode` is saved as Cursor's outage choice", "A per-user Cursor hook uses an explicit saved outage mode"], lacks: ["is ignored with a warning"] },
  { gap: "GAP-2244", page: "reference/fail-modes.mdx", has: ["`closed --no-restart` is refused and saves nothing while the connector still has a hook that is not verified closed; run the same command without `--no-restart`."] },
  { gap: "GAP-1698", page: "enterprise/operations.mdx", has: ["and `last-package-result.log` beside it with the standard error of the same run (often empty, `0` bytes). Every rpm or deb install and upgrade writes both."], lacks: ["so no `.log` stays beside it after an upgrade"] },
  { gap: "GAP-2201", page: "reference/gateway-api.mdx", section: "The policy object", has: ["On a managed standalone computer `/health` gives the object only to an administrator", "`curl http://127.0.0.1:18970/health`, even under `sudo`, has no `policy` key"] },
  { gap: "GAP-2241", page: "reference/sandbox-cli.mdx", section: "`sandbox list`", has: ["`NAME HARNESS PHASE MODE NETWORK UPTIME HOOKS PROJECT`", "NETWORK is the network profile the sandbox runs"], lacks: ["PROFILE is the profile the sandbox runs"] },
  { gap: "GAP-1662", page: "policies/deterministic-detection.mdx", section: "Download piped into a shell", has: ["(`CMD-WIN-IWR-IEX`) when PowerShell runs it", "so there is no finding for them."], lacks: ["(`CMD-WIN-IWR-IEX`) are still reported in every profile."] },
  { gap: "GAP-0033", page: "policies/deterministic-detection.mdx", section: "Download piped into a shell", has: ["`pwsh -Command \"...\"`", "`powershell -Command \"...\"`", "with or without `-NoProfile`"], lacks: ["or `pwsh -NoProfile -Command \"...\"` on"] },
  { gap: "GAP-1795", page: "support-matrix.mdx", section: "Upgrade and policy limits", has: ["fails with Conflict and leaves it starting", "keep the VM while you need what it holds"], lacks: ["can use `defenseclaw sandbox start NAME --end-vm`, then stop it"] },
  { gap: "GAP-1795", page: "sandboxes/guide.mdx", has: ["fails with Conflict and leaves it starting"], lacks: ["`start NAME --end-vm` starts it", "or on 0.1.5 start it with `--end-vm`", "can refuse the recovery above", "ends the lingering VM without a flush", "(which ends its VM without a flush)"] },
  { gap: "GAP-1795", page: "sandboxes/guide.mdx", section: "A sandbox is in OpenShell's error state", has: ["fails with Conflict and leaves it starting"], lacks: ["run `defenseclaw sandbox stop NAME` once it is ready"] },
  { gap: "GAP-1795", page: "enterprise/sandboxes.mdx", has: ["its `--end-vm` start fails with Conflict"], lacks: ["is started with `defenseclaw sandbox start <name> --end-vm`"] },
  { gap: "GAP-1762", page: "support-matrix.mdx", section: "Claude Code shell", has: ["no hook decision and no hook audit row", "the Tetragon runtime layer can still record it (`hook_seen=false`)"], lacks: ["the audit log has no row for it"] },
  { gap: "GAP-1763", page: "support-matrix.mdx", section: "Upgrade and policy limits", has: ["a process tracer such as PRoot on Linux", "`unprivileged_ptrace`", "`kernel.yama.ptrace_scope=2`"] },
  { gap: "GAP-1764", page: "get-started/windows/paths-troubleshooting.mdx", section: "Codex refuses every command in its first session", has: ["Granular.sandbox_approval is false", "Quit Codex and start it again once", "/docs/support-matrix#codex"] },
  { gap: "GAP-0552", page: "support-matrix.mdx", section: "Scanners on macOS", has: ["run as you, with a timeout", "can escape that tracking and keep running after the scan and after `defenseclaw-gateway stop`", "This is a macOS limit."] },
  { gap: "GAP-1158", page: "support-matrix.mdx", section: "Codex", has: ["**Shared daemon keeps its model key:**", "fail with `401` until the daemon restarts", "Run `codex app-server daemon restart` from a shell that has the new key."] },
  { gap: "GAP-1203", page: "support-matrix.mdx", section: "Identity", has: ["utmp keeps only the first 32 characters of a user name", "omit `defenseclaw.session.kind` and `client.address`", "Keep systemd-logind running"] },
  { gap: "r103:GAP-0214", page: "support-matrix.mdx", section: "Upgrade and policy limits", has: ["**Hermes config changed and put back quickly:**", "within about 3 seconds", "one Hermes session can start without the DefenseClaw hook", "records the change in the audit log"] },
  { gap: "GAP-1209", page: "support-matrix.mdx", section: "Sandboxes", has: ["**Rejected model key in a sandbox:**", "retries a rejected request for up to about three minutes", "cannot warn before the retries end"] },
  { gap: "GAP-1641", page: "scanning/registries.mdx", has: ["`openclaw package metadata is missing the plugins map`", "without one the fetch fails with `401 Client Error: Unauthorized`", "Both are upstream changes"] },
  { gap: "GAP-1191, GAP-1198, GAP-1199, GAP-1220, GAP-1223, GAP-1224, GAP-1242, GAP-1247, GAP-1248, GAP-1249, GAP-1250, GAP-1251, GAP-1252, GAP-1262, GAP-1265, GAP-1275, GAP-1276, GAP-1285, GAP-1290", page: "support-matrix.mdx", section: "Agent messages that are not from DefenseClaw", has: ["`Model metadata for <model> not found. Defaulting to fallback metadata`", "`api_key_model_discovery`", "`Workspace (granular)`", "`Auto-update failed: no write permission to npm prefix`", "`Unknown command: /NAME`", "`Contains brace with quote character (expansion obfuscation)`", "automatic update fails with `EACCES`", "lists command words such as `exit`, `test` or `run` as paths", "is not in the built-in catalog", "`Security scan — [HIGH] Pipe to interpreter`", "Hermes can then say DefenseClaw blocked the step", "`This foreground command appears to start a long-lived server/watch process`", "`node not available (Hermes-managed Node not installed)`", "`pygount: command not found`", "`pm-runtime: invalid package install stamp`", "`.install.lock`", "`npm warn install-scripts: postinstall ... is not covered by allowScripts`", "`codex exec --full-auto`", "its audit log has no block for it"] },
  { gap: "GAP-1543", page: "connectors/claudecode.mdx", has: ["strict and managed installs block it", "a killed or timed-out hook lets the call run"], lacks: ["every other hook failure blocks", "During an outage the default and permissive policies let the call run with a warning, strict blocks it."] },
  { gap: "GAP-1544", page: "connectors/claudecode.mdx", section: "Disable", has: ["It asks `Proceed? [Y/n]`; add `--yes` in scripts or when stdin is not a terminal."] },
  { gap: "GAP-1566", page: "connectors/copilot.mdx", section: "On a managed computer", has: ["are per-user commands", "/docs/enterprise/lifecycle#change-the-config", "refuses `setup copilot`"] },
  { gap: "GAP-1571", page: "connectors/copilot.mdx", section: "Files DefenseClaw will modify", has: ["The registration runs `%USERPROFILE%\\.defenseclaw\\hooks\\copilot-hook.ps1`, which calls"] },
  { gap: "GAP-1675", page: "connectors/opencode.mdx", section: "On a managed computer", has: ["`C:\\ProgramData\\opencode\\opencode.json`", "`C:\\Program Files\\Cisco\\DefenseClaw\\share\\opencode\\defenseclaw.js`", "on Windows too", "`guardrail.connectors.opencode.enabled: false`"] },
  { gap: "GAP-1701", page: "connectors/hermes.mdx", has: ["| Hook program, managed Windows | `C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw-hook.exe`", "the administrator sets `guardrail.connectors.hermes.enabled: false` in the managed `config.yaml` and runs `ensure`"] },
  { gap: "GAP-1598", page: "connectors/antigravity.mdx", has: ["`antigravity-hook.sh PreToolUse`", "a per-user install in the default or permissive policy lets `PreToolUse` run with one warning"], lacks: ["With the default fail mode closed", "binds each registration to a trusted `--event` argument"] },
  { gap: "GAP-1637", page: "connectors/kiro.mdx", section: "Fail mode", has: ["the default and permissive policies let the call run with one warning, and the strict policy blocks it"] },
  { gap: "GAP-1590", page: "connectors/amp.mdx", section: "Fail mode", has: ["the default and permissive policies let the call run with one warning"], lacks: ["closed by default"] },
  { gap: "GAP-1670", page: "connectors/cursor.mdx", has: ["a gateway outage lets the call run with a warning in the default and permissive policies and blocks it in strict"], lacks: ["a gateway outage blocks supported events by default"] },
  { gap: "GAP-1670", page: "connectors/cursor.mdx", section: "Fail mode", has: ["the default and permissive policies let the call run with a warning, strict blocks it"], lacks: ["still blocks supported events during a gateway outage by default"] },
  { gap: "GAP-1683", page: "connectors/codex.mdx", has: ["host setup removes only exporters that carry a DefenseClaw credential", "your own exporters stay"], lacks: ["host upgrades remove old exporters"] },
  { gap: "GAP-1702", page: "connectors/codex.mdx", section: "Files DefenseClaw will modify", has: ["`/etc/codex/requirements.toml` with `/opt/defenseclaw/bin/defenseclaw-hook` on Linux"] },
  { gap: "GAP-1315", page: "connectors/codex.mdx", section: "On a managed computer", has: ["when it reconciles an enrolled account", "for an account that is not enrolled the preference stays"], lacks: ["removes that conflicting user preference during reconciliation"] },
  { gap: "GAP-1582", page: "connectors/zeptoclaw.mdx", has: ["`ncat`", "those seven commands"] },
  { gap: "GAP-1582", page: "connectors/zeptoclaw.mdx", has: ["seven PATH shims", "`ncat` (a link to the `nc` shim)"] },
  { gap: "GAP-1644", page: "connectors/zeptoclaw.mdx", has: ["`4000`, or the free port `init` chose when another account holds 4000"] },
  { gap: "GAP-1645", page: "connectors/zeptoclaw.mdx", has: ["unless you pass `--replace`", "`no usable providers found`"] },
  { gap: "GAP-0108, GAP-1524", page: "get-started/quickstart.mdx", has: ["its hook lets a call run with one warning while the gateway is not running", "a running hook blocks every other failure it detects"], lacks: ["With the default fail mode closed", "The hook fail mode is closed on a new install", "every other hook failure blocks"] },
  { gap: "GAP-1620", page: "get-started/quickstart.mdx", has: ["On an install that already guards other agents, `init --connector claudecode` keeps only Claude Code.", "use `defenseclaw setup <agent>` instead"] },
  { gap: "GAP-1660", page: "reference/cli.mdx", has: ["Fields that are not set (`connector`, `command`, `url` and the others) are left out."], lacks: ["\"source_path_contains\": [],"] },
  { gap: "GAP-1626", page: "reference/cli.mdx", has: ["`5` when run from a standard account", "`elevation_required`"] },
  { gap: "GAP-1604", page: "index.mdx", has: ["the shipped default blocks CRITICAL and alerts on MEDIUM and above."], lacks: ["alerts on HIGH."] },
  { gap: "GAP-1606", page: "policies/rules.mdx", has: ["regex rules and suppressions of the bundled strict pack"] },
  { gap: "GAP-1607", page: "enterprise/enrollment.mdx", has: ["sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise hooks status # macOS"] },
  { gap: "GAP-0885", page: "enterprise/enrollment.mdx", has: ["under `unenrolled_users: inspect` (the default) an extension-only user of it gets no target row", "with `deny` the user becomes a target"] },
  { gap: "GAP-1609", page: "tui.mdx", has: ["The **Blocks** filter chip (move between chips with `h` and `l`; `3` still opens Skills)"], lacks: ["`3` (Blocks) lists"] },
  { gap: "GAP-1610", page: "stories/prompt-injection-codex.mdx", has: ["Host setup does not wire Codex's native OpenTelemetry; only an isolated OpenShell sandbox uses it."], lacks: ["Setup also wires Codex's native OpenTelemetry."] },
  { gap: "GAP-1610", page: "connectors/codex.mdx", has: ["when they carry a credential this install recorded", "puts it back when it removes its own", "delete those tables by hand"], lacks: ["Host setup removes native OpenTelemetry exporters installed by earlier releases: Codex"] },
  { gap: "GAP-1618", page: "enterprise/macos.mdx", has: ["`enterprise macos status --json` and `enterprise macos verify` report `tetragon_not_applicable`"] },
  { gap: "GAP-1618", page: "enterprise/configuration.mdx", has: ["on macOS `status --json` and `verify` report `tetragon_not_applicable`"] },
  { gap: "GAP-1591", page: "policies/cel/engine.mdx", has: ["`exists` and `all` comprehensions; nesting is limited to two levels", "so `validate-pack` refuses `map`, `filter` and `exists_one` (`semantic_surface`)"], lacks: ["`exists`, `all`, `map` and `filter` comprehensions"] },
  { gap: "GAP-2250", page: "support-matrix.mdx", section: "Hook floods on Windows", has: ["every hook decision adds about 40 KiB to the account's audit database (`audit.db`)", "can also pass its 256 MiB alarm and hook answers can take seconds", "A call the gateway took but did not answer in time is blocked in every policy tier, never let through", "This is a Windows disk-write limit."] },
  { gap: "GAP-2250", page: "get-started/windows/paths-troubleshooting.mdx", has: ["audit.db grows fast or hook answers are slow during a tool-call flood", "/docs/support-matrix#hook-floods-on-windows"] },
  { gap: "GAP-2216", page: "get-started/install.mdx", has: ["| Python | 3.11-3.13 |", "`uv` and Python 3.11-3.13 from python.org"], lacks: ["3.10-3.13"] },
  { gap: "GAP-2216", page: "scanning/skill-scanner.mdx", has: ["DefenseClaw needs Python 3.11 to 3.13 (the package refuses Python 3.10)"], lacks: ["DefenseClaw itself still runs on Python 3.10"] },
  { gap: "GAP-2216", page: "scanning/mcp-scanner.mdx", has: ["itself needs Python 3.11 to 3.13 (the package refuses Python 3.10)"], lacks: ["DefenseClaw itself also supports Python 3.10"] },
  { gap: "GAP-2216", page: "scanning/registries.mdx", has: ["DefenseClaw needs Python 3.11 to 3.13, so every"], lacks: ["any Python 3.10 runtime"] },
  { gap: "GAP-1587", page: "guardrail/index.mdx", has: ["fails the **Config validation** and **Rule pack** rows and skips **Policy**"], lacks: ["fails the Policy row until you pin the new digest"] },
  { gap: "GAP-1656", page: "policies/rules.mdx", has: ["`live state was not checked while config.yaml is invalid`"], lacks: ["fails the **Policy** row: `generation 2"] },
  { gap: "GAP-1652", page: "guardrail/index.mdx", has: ["pin the `files digest` value it prints (the guardrail.custom_packs pin, not the `digest` line)", "set both its `path` and `digest`"] },
  { gap: "GAP-1649", page: "reference/keys.mdx", has: ["`DefenseClaw blocked this because its gateway is stopped`", "`defenseclaw: gateway unreachable, blocking <agent> tool (fail mode closed)`"] },
  { gap: "GAP-1667", page: "reference/keys.mdx", has: ["Under the default and permissive policies a per-user call runs with one warning instead"], lacks: ["the hook is fail-closed. This holds in observe mode too."] },
  { gap: "GAP-1666", page: "reference/keys.mdx", has: ["`Config file` (`canonical schema valid`) as `[PASS]` on every OS", "`Gateway token env`, `Gateway token drift` and `Gateway PID identity`"] },
  { gap: "GAP-1691", page: "reference/fail-modes.mdx", has: ["accept only `open` or `closed`, in lower case"], lacks: ["Any value other than `open` (in any case) is `closed`."] },
  { gap: "GAP-1517", page: "guardrail/benchmarks.mdx", has: ["title=\"Eleven YARA signatures\""], lacks: ["Ten YARA signatures"] },
  { gap: "GAP-1404", page: "reference/configuration.mdx", has: ["`%LOCALAPPDATA%\\hermes\\config.yaml` on native Windows"] },
  { gap: "GAP-1307", page: "observability/redaction.mdx", has: ["move needs at least two routes on the destination;"] },
  { gap: "GAP-1382", page: "acp-guard.mdx", has: ["On a per-user install `defenseclaw acp catalog` prints the list. On a managed computer it is refused (exit 2)"] },
  { gap: "GAP-1631", page: "guardrail/multi-connector.mdx", has: ["`Fail` is `open` under the default policy"], lacks: ["enabled observe closed default"] },
  { gap: "GAP-1673", page: "enterprise/troubleshooting.mdx", section: "Lifecycle error codes", has: ["| `hook_process_fail_open` | Linux, macOS, Windows |", "| `status_detail_unavailable` |", "| `claude_state_unreadable` |"] },
  { gap: "GAP-1696", page: "enterprise/troubleshooting.mdx", section: "`security_complete` is `false` on Windows", has: ["`status_detail_unavailable`", "`claude_state_unreadable`", "ATTESTCLAUDEEFFECTIVEPOLICY=1", "`security_incomplete` lists the reasons"] },
  { gap: "GAP-1700", page: "enterprise/troubleshooting.mdx", section: "`security_complete` is `false` on Linux or macOS", has: ["`unprivileged_user_namespaces`", "with only `hook_process_fail_open`, `unprivileged_user_namespaces` and `unprivileged_ptrace` warnings"] },
  { gap: "GAP-1697", page: "enterprise/troubleshooting.mdx", has: ["On managed Windows `defenseclaw.exe` exits `3` and writes no audit row"] },
  { gap: "GAP-1707", page: "enterprise/rollout.mdx", has: ["On Linux and macOS a healthy install keeps it at `false` with only `hook_process_fail_open`", "`unprivileged_ptrace` while the kernel allows them"] },
  { gap: "GAP-1630", page: "policies/rulepack-validation.mdx", has: ["defenseclaw policy activate default", "with `strict` a call is blocked while the gateway is not running, and `default` lets it run with a warning again"] },
  { gap: "GAP-1653", page: "guardrail/unified-llm-key.mdx", has: ["'remove <ENV_NAME>': {"] },
  { gap: "GAP-1623", page: "stories/observe-claude-code.mdx", has: ["Select-String -Path", "ConvertFrom-Json"], lacks: ["`closed` (the default) blocks"] },
  { gap: "GAP-1624", page: "get-started/windows/telemetry-security.mdx", has: ["`audit.db` and `.env` grant access only to the user (`OWNER RIGHTS` or the account) and SYSTEM", "only after taking ownership"], lacks: ["readable only by that user, Administrators, and SYSTEM"] },
  { gap: "GAP-1712", page: "get-started/windows/telemetry-security.mdx", has: ["`C:\\ProgramData\\Cisco\\DefenseClaw\\runtime\\audit.db`", "`enterprise windows verify --profile standalone`"] },
  { gap: "GAP-1665", page: "reference/configuration.mdx", has: ["on Windows `installer\\` holds only `install.ps1`"] },
  { gap: "GAP-1665", page: "get-started/windows/paths-troubleshooting.mdx", has: ["`skill-scanner.cmd`, `mcp-scanner.cmd`", "`defenseclaw-hook-state.json`"] },
  { gap: "GAP-1713", page: "get-started/windows/paths-troubleshooting.mdx", has: ["On a managed Windows computer none of these per-user paths are used", "`C:\\ProgramData\\Cisco\\DefenseClaw\\etc\\config.yaml`"] },
  { gap: "GAP-1671", page: "enterprise/index.mdx", has: ["| Attempt on managed Windows | Result |", "config set did not change it", "not a command of the administrator's `defenseclaw.exe`"] },
  { gap: "GAP-1678", page: "reference/cli.mdx", section: "Observability rows", has: ["| Codex OTel environment |", "| Connector OTLP: CONNECTOR |", "| Native OTLP credentials |"] },
  { gap: "GAP-1689", page: "enterprise/ai-defense-key.mdx", has: ["`! secret set: done with N warnings`", "The warnings are the host's normal status, not a failed store."] },
  { gap: "GAP-1568", page: "enterprise/ai-defense-key.mdx", has: ["`! secret remove: done with N warnings`", "`! secret remove: nothing to do (up_to_date), N warnings`"] },
  { gap: "GAP-1573", page: "get-started/install.mdx", section: "Check it worked", has: ["`✓ All components in sync.`", "piped to another command, as above, they use text"] },
  { gap: "GAP-1581", page: "get-started/upgrade.mdx", section: "Rollback", has: ["A previous install that never ran `defenseclaw init` has no configuration, and what rollback does then depends on the gateway:", "If the gateway is running, rollback must start the previous gateway, which refuses with `no config.yaml exists yet`. Rollback then undoes itself and exits 1", "There is nothing to fix there:", "If the gateway is stopped, rollback completes and exits 0, and the previous install runs with no `config.yaml`", "run `defenseclaw rollback` again to roll forward to your current install and its configuration"], lacks: ["Rollback needs a previous install that was initialized. If that install never ran `defenseclaw init`, rollback says `no config.yaml exists yet`, undoes itself and exits 1; the current install stays."] },
  { gap: "GAP-1567", page: "policies/recipes.mdx", has: ["In every mode, observe included, DefenseClaw blocks an agent that copies into `~/.defenseclaw` (`tamper.detector_state_write`"] },
  { gap: "GAP-2419", page: "policies/recipes.mdx", has: ["In every mode, observe included, DefenseClaw blocks an agent that copies into `~/.defenseclaw`", "with the permissive pack it only reports it)."], lacks: ["In action mode DefenseClaw blocks an agent that copies into"] },
  { gap: "GAP-2419", page: "guardrail/index.mdx", has: ["is blocked in every mode (rule `tamper.detector_state_write`; the permissive pack only reports it)."] },
  { gap: "GAP-2419", page: "enterprise/concepts.mdx", has: ["DefenseClaw's own files: that is blocked in every mode."], lacks: ["policy verdicts never block and DefenseClaw\nrecords what it would have blocked. In `action`"] },
  { gap: "GAP-2424", page: "guardrail/index.mdx", has: ["The picker's \"never block\" covers policy findings. Observe still blocks an agent that changes DefenseClaw's own files"] },
  { gap: "GAP-2424", page: "guardrail/multi-connector.mdx", has: ["The picker's \"never block\" covers policy findings. Observe still blocks an agent that changes DefenseClaw's own files"] },
  { gap: "GAP-2424", page: "guardrail/switching-connectors.mdx", has: ["The picker's \"never block\" covers policy findings. Observe still blocks an agent that changes DefenseClaw's own files"] },
  { gap: "GAP-2466", page: "enterprise/linux.mdx", section: "2. Stage the config", has: ["Write the config as `config_version: 9`. `ensure` also takes a `config_version: 8` file: it migrates it to 9, keeps `config.yaml.v8.bak` and `migration-v9.json`, and warns `config_version_8`. It refuses any other version with `config_invalid`."], lacks: ["The lifecycle requires `config_version: 9`"] },
  { gap: "GAP-2466", page: "enterprise/macos.mdx", section: "2. Stage the config", has: ["Write the config as `config_version: 9`. `ensure` also takes a `config_version: 8` file: it migrates it to 9, keeps `config.yaml.v8.bak` and `migration-v9.json`, and warns `config_version_8`. It refuses any other version with `config_invalid`."], lacks: ["The lifecycle requires `config_version: 9`"] },
  { gap: "GAP-2440", page: "get-started/upgrade.mdx", section: "Upgrade", has: ["For a few seconds while the installer swaps the hooks, a hook from the release you upgrade from (1.0.4 or earlier) can show its own generic text instead", "that a gateway cold start failed, or that you should run `defenseclaw-gateway restart`", "That text comes from the older release and cannot change; you do not need to restart anything, wait for the installer to finish and retry."], lacks: ["A hook from the release you upgrade from can instead say that the gateway is stopped or unreachable."] },
  { gap: "GAP-2458", page: "get-started/upgrade.mdx", has: ["Going from 1.0.4 straight to 1.0.2 on macOS or Linux, with either command or with the 1.0.2 installer, leaves a hook helper that 1.0.2 cannot use", "From 1.0.5 on, going back to 1.0.2 is clean."] },
  { gap: "GAP-2458", page: "get-started/upgrade.mdx", section: "`defenseclaw_api_listener_foreign: command not found` after going back to 1.0.2 (macOS and Linux)", has: ["defenseclaw_api_listener_foreign: command not found", "rm ~/.defenseclaw/hooks/_hardening.sh defenseclaw-gateway restart", "Or go from 1.0.4 to 1.0.5 first, then back to 1.0.2"] },
  { gap: "GAP-2451", page: "enterprise/troubleshooting.mdx", section: "Warnings", has: ["| `agent_settings_not_restored` (exporter removed) | Windows |", "`.claude\\settings.json.defenseclaw-otlp-removed.bak` or `.codex\\config.toml.defenseclaw-otlp-removed.bak`", "Delete the copy to clear the warning.", "On Windows this code also reports an earlier per-user install's native OTLP exporter"], lacks: ["| `native_otlp_marked_removed` | Windows |"] },
  { gap: "GAP-2451", page: "enterprise/troubleshooting.mdx", section: "Warnings", has: ["| `agent_settings_not_restored` (exporter not removed) | Windows |", "still holds the native OTLP exporter of an earlier per-user DefenseClaw install", "| `native_otlp_config_unchecked` | Linux, macOS, Windows |"], lacks: ["| `native_otlp_take_back_pending` | Windows |"] },
  { gap: "GAP-1613", page: "enterprise/sandboxes.mdx", has: ["`sandboxes are unavailable: OpenShell 0.1.3 runs no DefenseClaw sandbox:"], lacks: ["OpenShell 0.1.3 is installed, but that release is unsupported"] },
  { gap: "GAP-1619", page: "guardrail/user-and-group-policies.mdx", has: ["`defenseclaw-gateway config validate FILE`", "`enterprise macos ensure --config FILE`", "`enterprise macos profile-explain`"] },
  { gap: "GAP-1635", page: "policies/admission.mdx", has: ["`tool list` prints one table per connector", "`UPDATED` shows `-` for an entry until it is changed"] },
  { gap: "GAP-1659", page: "guardrail/user-and-group-policies.mdx", section: "A complete example", has: ["hilt: {enabled: true, min_severity: LOW}"], lacks: ["hilt: {enabled: true, min_severity: HIGH}"] },
  { gap: "GAP-0595", page: "ai-discovery.mdx", has: ["asks `Proceed? [Y/n]`; press Enter to continue. In a script or scheduled task, use `defenseclaw agent", "It asks `Proceed? [Y/n]`; `--yes` skips the question."] },
  { gap: "GAP-0633", page: "reference/env-vars.mdx", has: ["exported in a shell is dropped when the", "The writers keep writing as usual"], lacks: ["where the profile is standalone, the Linux default"] },
  { gap: "GAP-0669", page: "stories/cursor-secret-exfil.mdx", has: ["defenseclaw setup cursor --yes --mode action --rule-pack default --no-human-approval --restart", "`--yes` re-applies hooks when Cursor is already configured and skips the optional LLM judge prompt", "✓ cursor mode=action"] },
  { gap: "GAP-0520", page: "guardrail/index.mdx", has: ["**Select action connector(s) for LLM judge.**"] },
  { gap: "GAP-0388", page: "observability/local-observability.mdx", has: ["18 DefenseClaw dashboards (19 with the Fleet assets)"] },
  { gap: "GAP-0388", page: "observability/grafana-dashboards.mdx", has: ["DefenseClaw provisions 18 Grafana dashboards", "it is not in the installed package and is added with the separate Fleet assets"] },
  { gap: "GAP-1716", page: "get-started/windows/install-lifecycle.mdx", section: "Upgrade", has: ["exit code 0 means the installer started, not that it finished", "-Rollback -Yes`, which waits and sets the exit code"] },
  { gap: "GAP-1716", page: "support-matrix.mdx", section: "Upgrade and policy limits", has: ["**Windows upgrade and rollback return before the installer finishes:**"] },
  { gap: "GAP-0922, GAP-0923", page: "support-matrix.mdx", section: "Upgrade and policy limits", has: ["macOS has no setting that stops a user's sandbox profile", "DefenseClaw does not see or audit its tool calls"], lacks: ["unshare -Urm"] },
  { gap: "GAP-0725", page: "enterprise/identity-sources.mdx", has: ["the same entry selects the account of that name in each of those domains", "The strict policy tier refuses a request when that ambiguity could change its profile."] },
  { gap: "GAP-0725", page: "guardrail/user-and-group-policies.mdx", has: ["the entry selects the account of that name in each domain"] },
  { gap: "GAP-0755", page: "enterprise/enrollment.mdx", has: ["Excluding an enrolled account also removes its guardian identity record at the next guardian pass"] },
  { gap: "GAP-1163", page: "reference/sandbox-cli.mdx", has: ["If that sync fails, DefenseClaw does not stop the VM"] },
  { gap: "GAP-1550", page: "sandboxes/guide.mdx", section: "A MicroVM stop is held because its disk could not sync", has: ["Signing out without linger, `sandbox teardown` and an administrator"] },
  { gap: "GAP-1595", page: "tui.mdx", has: ["asks in this terminal whether to stop it anyway"], lacks: ["defenseclaw sandbox stop NAME --yes`)"] },
  { gap: "GAP-0868", page: "enterprise/sandboxes.mdx", has: ["the package pauses each account's old sandbox daemon before it replaces any file"] },
  { gap: "GAP-0546", page: "enterprise/sandboxes.mdx", has: ["`ensure` fails with `config_invalid` and keeps the previous config and the running gateway"] },
  { gap: "GAP-0691", page: "enterprise/sandboxes.mdx", has: ["can be written in any letter case: `VM` is `vm`"] },
  { gap: "GAP-0714", page: "enterprise/sandboxes.mdx", has: ["read and write access to `/dev/kvm` (the `kvm` group, a user ACL entry or an open mode)"] },
  { gap: "GAP-1693", page: "reference/sandbox-cli.mdx", has: ["can reach your account's request limit"] },
  { gap: "GAP-1552", page: "enterprise/sandboxes.mdx", has: ["a run first waits up to 10 seconds for your sandbox policy"] },
  { gap: "GAP-0701", page: "sandboxes/guide.mdx", has: ["offers the next free port and writes it as `openshell.ingress_port` or `openshell.egress_port`"] },
  { gap: "GAP-0831", page: "support-matrix.mdx", section: "Upgrade and policy limits", has: ["adds none back (approvals included)", "withdrawing those rules does not contain the guest's old OpenShell network broker, which passes a connection it cannot inspect straight to the host (NVIDIA/OpenShell#4494), so treat the guest's network as open until it restarts", "Restart it once DefenseClaw has withdrawn its rules: save the work you need, then run `defenseclaw sandbox stop NAME` and `defenseclaw sandbox start NAME`"], lacks: ["it cannot cut that guest off below OpenShell's own network broker"] },
  { gap: "GAP-0831", page: "sandboxes/guide.mdx", section: "A guest from OpenShell 0.1.3 or older keeps its network after its rules are withdrawn", has: ["passes a connection it cannot inspect straight to the host", "This is an OpenShell 0.1.3 limit (NVIDIA/OpenShell#4494)", "**Fix:** restart the sandbox after DefenseClaw has withdrawn its rules"] },
  { gap: "GAP-0454", page: "support-matrix.mdx", section: "Sandboxes", has: ["DefenseClaw's lock covers only DefenseClaw commands, and OpenShell has no admission barrier that raw clients honor", "Do not start raw `openshell` sandboxes until the DefenseClaw command finishes."] },
  { gap: "GAP-0454", page: "sandboxes/guide.mdx", section: "A raw `openshell` sandbox stops a restart or rollback", has: ["Starting a sandbox with raw `openshell` while DefenseClaw changes, restarts or rolls back the gateway is unsupported", "A sandbox started after the last check cannot be seen, and the restart ends it."] },
  { gap: "GAP-1173, GAP-1188", page: "enterprise/mdm/intune-linux.mdx", has: ["the script first writes what it replaces to a root-only journal"] },
  { gap: "GAP-1584, GAP-1616", page: "enterprise/mdm/index.mdx", has: ["including the rotation journal and the staging folders of wrapper runs that were killed", "`--purge` also removes the wrapper's empty state folder `/var/db/defenseclaw-mdm`", "every ensure exits `mdm_secret_failed`"] },
  { gap: "GAP-0727", page: "enterprise/lifecycle.mdx", has: ["`--purge` leaves that folder and the install's binaries exactly as they are"], lacks: ["to a new `~/.defenseclaw-backup-<UTC time>` folder"] },
  { gap: "GAP-0727", page: "reference/cli.mdx", lacks: ["is moved to `~/.defenseclaw-backup-<UTC time>` first"] },
  { gap: "GAP-1654", page: "enterprise/linux.mdx", has: ["Accounts the deployment never enrolled keep their DefenseClaw files"] },
  { gap: "GAP-1542", page: "enterprise/lifecycle.mdx", has: ["`--purge` removes everything DefenseClaw installed", "`eDSPermissionError`"] },
  { gap: "GAP-0286", page: "support-matrix.mdx", section: "Upgrade and policy limits", has: ["the old gateway's audit row can still say allow", "the gateway records such a call as unconfirmed"] },
  { gap: "GAP-1563", page: "support-matrix.mdx", section: "Codex", has: ["shows `Config check: not run` because the sandbox hides who owns your folders"] },
  { gap: "GAP-1600, GAP-1748", page: "observability/splunk.mdx", has: ["setup stops with exit 1 and saves nothing", "run `defenseclaw observability destination test <name>`"] },
  { gap: "GAP-1398, GAP-1750", page: "observability/splunk.mdx", has: ["In Splunk Free mode Splunk Web opens as admin with no login"] },
  { gap: "GAP-1663", page: "ai-discovery.mdx", has: ["The selected planes are kept for the next `enable`."] },
  { gap: "GAP-1589", page: "acp-guard.mdx", has: ["the last line then ends with `new profile NAME`", "takes out the profiles setup wrote for that pair"] },
  { gap: "GAP-1677", page: "reference/cli.mdx", has: ["says there is nothing to acknowledge and exits 0"] },
  { gap: "GAP-1366", page: "reference/cli.mdx", has: ["one warning says the change was saved"] },
  { gap: "GAP-1274", page: "tui.mdx", has: ["WATCHING means every selected plane is running"] },
  { gap: "GAP-1539", page: "support-matrix.mdx", section: "Upgrade and policy limits", has: ["`user_registrations_failed`"] },
  { gap: "GAP-1703", page: "connectors/hermes.mdx", section: "Managed verification", has: ["`connector hermes cannot be verified: session-only HERMES_HOME cannot be observed by the managed service`"] },
  { gap: "GAP-1603, GAP-1627", page: "enterprise/operations.mdx", has: ["the bounded scan of this account's private agent installs was incomplete", "`audit_write_failed` stays for 16 minutes"] },
  { gap: "GAP-1753", page: "support-matrix.mdx", section: "Managed macOS private agent scan", has: ["On macOS 15.8 the managed scan also skips these folders"] },
  { gap: "GAP-1714", page: "enterprise/troubleshooting.mdx", section: "An account on a stalled network or FUSE mount", has: ["`fusermount -uz`"] },
  { gap: "GAP-1503", page: "policies/deterministic-detection.mdx", has: ["instruction-file writes are HIGH, so they are reported, not blocked"] },
  { gap: "GAP-1254", page: "connectors/copilot.mdx", has: ["removes the `enabledPlugins` entry `defenseclaw@defenseclaw`"] },
  { gap: "GAP-1795", page: "reference/sandbox-cli.mdx", has: ["OpenShell 0.1.5 refuses `--end-vm` for a MicroVM whose workload completed or failed while its VM still runs"] },
  { gap: "GAP-0013", page: "get-started/quickstart.mdx", has: ["A mode you saved with `defenseclaw guardrail fail-mode` wins over the policy: with a saved `open` the call still runs under strict, and `defenseclaw guardrail fail-mode closed`"] },
  { gap: "GAP-0013", page: "connectors/claudecode.mdx", has: ["On a per-user install with no saved mode, a gateway that is not running follows the policy tier"], lacks: ["On a per-user install a gateway that is not running follows the policy tier"] },
  { gap: "GAP-0013", page: "connectors/codex.mdx", has: ["On a per-user install with no saved mode, a gateway that is not running follows the policy tier: the default and permissive policies let the call run with one warning, and the strict policy blocks it"] },
  { gap: "GAP-0040", page: "connectors/codex.mdx", has: ["A saved mode decides instead: with `guardrail fail-mode open` saved, the call runs with one warning under every policy, strict included."], lacks: ["yes, except on a per-user install with no saved mode"] },
  { gap: "GAP-0013", page: "policies/defaults.mdx", has: ["A per-user install with no saved mode follows its rule pack when the gateway is down"] },
  { gap: "GAP-0464", page: "enterprise/troubleshooting.mdx", has: ["The foreign-hook guard is the exception: with `foreign_hooks: remove` (the default) the connectors it checks need the gateway's session record, so `open` does not apply to them", "It is never an allow, also with the administrator's `hook_fail_mode: open`: `open` covers only a gateway service the hook proves stopped."], lacks: ["It is never an allow unless the administrator set `hook_fail_mode: open`."] },
  { gap: "GAP-0827", page: "enterprise/machine-policy.mdx", section: "Managed OpenCode plugin", has: ["a stopped gateway service depends on `foreign_hooks`: with `remove` (the default) the foreign-plugin guard needs the gateway's session record, so `open` does not apply; with `report` or `allow` it does.", "/docs/connectors/capability-matrix#gateway-outage"], lacks: ["It fails closed: a tool call is blocked when the hook binary cannot run, answers with an error, or the gateway is unreachable."] },
  { gap: "GAP-1997", page: "reference/fail-modes.mdx", has: ["Their PATH shims for `curl`, `wget`, `ssh`, `nc`, `pip` and `npm` are not requests", "Open runs the real tool with one warning and a `hook-failures.jsonl` record. Closed refuses it."] },
  { gap: "GAP-1997", page: "support-matrix.mdx", lacks: ["refuse to run the real tool in every policy, so `npm` and `pip` builds stop", "running <tool> without inspection"] },
  { gap: "GAP-1997", page: "connectors/zeptoclaw.mdx", section: "Subprocess policy", has: ["While the gateway is not running, the shims follow the policy", "running <tool> without inspection", "refusing to exec <tool>`, exit 1"] },
  { gap: "GAP-1997", page: "connectors/openclaw.mdx", section: "Subprocess policy", has: ["While the gateway is not running, the shims follow the policy", "running <tool> without inspection", "refusing to exec <tool>`, exit 1"] },
  { gap: "GAP-0506", page: "segmentation.mdx", section: "Fail-open and fail-closed, per layer", has: ["| A hook cannot reach the gateway | The [gateway outage table](/docs/connectors/capability-matrix#gateway-outage) gives the result per connector and install.", "covers a gateway outage only, and not for a connector whose foreign-hook guard checks the session with the gateway ([gateway outage table](/docs/connectors/capability-matrix#gateway-outage))"] },
  { gap: "GAP-0465", page: "connectors/capability-matrix.mdx", has: ["report as `effective_hook_fail_mode` the mode a managed connector's hook works in", "(on Windows the Amp and OpenCode plugins) read `closed`"], lacks: ["also for a hook that blocks the outage anyway"] },
  { gap: "GAP-0034", page: "connectors/claudecode.mdx", has: ["Works on Linux and macOS. On a per-user install setup writes the hooks through a link", "On Windows setup refuses a `settings.json` that is a symbolic link or junction, wherever it points, and changes nothing", "On Windows replace the link with the file it points to, then run setup again."], lacks: ["| `settings.json` is a symlink | Works. On a per-user install"] },
  { gap: "GAP-0034", page: "get-started/windows/paths-troubleshooting.mdx", has: ["Setup changes the Claude Code `settings.json` only as a regular file. If it is a symbolic link or junction, setup refuses, names the link and its target, and changes nothing."] },
  { gap: "GAP-2255", page: "enterprise/enrollment.mdx", has: ["`enterprise <os> profile-explain --user <account>` prints", "enterprise macos profile-explain --user <account>", "The gateway has no top-level `profile-explain`."], lacks: ["runs. `profile-explain --user <account>` prints"] },
  { gap: "GAP-2255", page: "enterprise/sandboxes.mdx", has: ["| `enterprise <os> profile-explain --user NAME`; check the identity source |", "Run `enterprise <os> profile-explain --user` and `sandbox explain`"], lacks: ["| `profile-explain --user NAME`;", "Run `profile-explain --user` and"] },
  { gap: "GAP-2212", page: "enterprise/ai-defense-key.mdx", has: ["On a host whose status has warnings the output starts with `! secret set: done with N warnings` and the warning lines (for example `openshell_prerequisite_missing`,", "`secret remove` prints the same header."], lacks: ["restarts the gateway so it reads the key. The output starts with `✓ secret set: done` and `- stored credential ai-defense-api-key`. </Tab>"] },
  { gap: "GAP-2204", page: "enterprise/lifecycle.mdx", section: "Restart the managed gateway", has: ["| macOS | `sudo launchctl bootout system/com.cisco.defenseclaw.gateway` | `sudo launchctl bootstrap system /Library/LaunchDaemons/com.cisco.defenseclaw.gateway.plist` |", "| Linux | `sudo systemctl stop defenseclaw-gateway-hook.socket defenseclaw-gateway-api.socket defenseclaw-gateway.service` |", "a socket that still listens starts the gateway again at the next hook", "`enterprise_managed_gateway_not_running`"] },
  // r105-rows-end
  { gap: "GAP-2391", page: "guardrail/unified-llm-key.mdx", has: ["`audit export` shows it as `action=config.change.applied` with `actor=cli:<your user name>`", "`defenseclaw.admin.target_ref=config:dotenv:<ENV>`"], lacks: ["action=config-update target=config:dotenv:<ENV>"] },
  { gap: "GAP-2391", page: "reference/keys.mdx", has: ["(`audit export` action `config.change.applied`, `structured` `defenseclaw.admin.operation=config-update` and `defenseclaw.admin.target_ref=config:dotenv:<ENV>`)"], lacks: ["record a `config-update` audit event with target `dotenv:<ENV>`"] },
  { gap: "GAP-2391", page: "reference/cli.mdx", has: ["Configuration changes are audit rows with action `config.change.applied`;"], lacks: ["Configuration changes are audit rows (action `config-update`)."] },
  { gap: "GAP-0730", page: "observability/sandbox-telemetry.mdx", has: ["A changed root-owned `gateway.toml` render on its own (field `gateway_configuration`) is reported the same way but does not pause"], lacks: ["(field `gateway configuration`)"] },
  { gap: "GAP-0730", page: "enterprise/sandboxes.mdx", has: ["A hand edit of the rendered `gateway.toml` itself (only root can make it) is reported with the same record, and status and doctor show the drift, but it does not pause", "| Settings drift (not for a changed rendered `gateway.toml` alone, which is reported without a pause) |"] },
  { gap: "GAP-1883", page: "get-started/upgrade.mdx", section: "Upgrade", has: ["To go back to an earlier release, use `defenseclaw rollback` or `defenseclaw upgrade --version X.Y.Z`.", "Running an older release's installer (`install.sh` or `install.ps1` of that release) directly over a newer install is not a supported downgrade", "`defenseclaw doctor` reports two DefenseClaw PreToolUse handlers", "Claude Code tool calls fail in the older release's hook (`unknown flag: --connector`)"] },
  { gap: "GAP-1883", page: "get-started/windows/install-lifecycle.mdx", section: "Upgrade", has: ["running an older release's `install.ps1` over a newer install is not a supported downgrade", "use `defenseclaw rollback` or `defenseclaw upgrade --version X.Y.Z`"] },
  { gap: "GAP-2391", page: "reference/cli.mdx", has: ["they are audit rows with action `config.change.applied` and others."], lacks: ["they are audit rows with action `config-update` and others."] },
  { gap: "GAP-2262", page: "guardrail/unified-llm-key.mdx", section: "Undo", has: ["defenseclaw setup guardrail --non-interactive --detection-strategy regex_only", "Without `--non-interactive` the command starts the full setup wizard"], lacks: ["and run `defenseclaw setup guardrail --detection-strategy regex_only` to turn the judge off."] },
  { gap: "GAP-1921", page: "reference/fail-modes.mdx", has: ["`config validate`, `config set` and `guardrail fail-mode` accept only `open` or `closed`, in lower case; any other value (`OPEN`, `banana`) is refused.", "The `--fail-mode` flag of `defenseclaw init`, `quickstart` and `setup <connector>` takes either case and saves it in lower case."], lacks: ["`config validate` and the writers accept only `open` or `closed`"] },
  { gap: "GAP-2392", page: "tui.mdx", section: "Panels", has: ["The quick-action row at the end of Overview lists both as `[G] Gateway` and `[z] AI Discovery`", "The hint line above the status line is not a key list on Overview"], lacks: ["The key row shows both actions at 80 columns."] },
  { gap: "GAP-2239", page: "policies/defaults.mdx", section: "What `setup guardrail` actually writes", has: ["If `config.yaml` already has an entry for the connector under `guardrail.connectors` (`defenseclaw setup claude-code` or an `init` that picked several agents writes one), the command saves `mode` and `rule_pack` in that entry instead of at the top level. The setup summary and `defenseclaw guardrail status` show the values the connector runs with; `defenseclaw config show --section guardrail` shows where they are saved."] },
  { gap: "GAP-2224", page: "stories/cursor-secret-exfil.mdx", has: ["✓ cursor gateway outage=open (failClosed=true)", "This is the output in a terminal. Piped to another command or saved to a file, the same lines start with `OK` and `i` instead of the check mark and the info sign."] },
  { gap: "GAP-2349", page: "tui.mdx", section: "Panels", has: ["The one exception is Sandboxes: there `P`, `R` and `A` are the", "On Sandboxes, press `p` for"] },
  { gap: "GAP-2228", page: "tui.mdx", has: ["generation and policy digest as its own segment, right after the gateway:", "The active policy and mode are a separate segment further along the line"], lacks: ["example `policy strict · action · gen 10 · 8b19ede82344`", "ends with the policy the running"] },
  { gap: "GAP-2345", page: "get-started/first-run.mdx", section: "Path A: interactive (`defenseclaw init`)", has: ["1. **Select active connector(s)**: every installed hook connector is pre-selected", "2. **Scanner mode** (`local`, `remote` or `both`, default `local`).", "3. **Select connector(s) for action enforcement**", "**Select action connector(s) for LLM judge**", "5. **Start gateway after setup?** (default yes), then **Run targeted readiness checks?** (default yes)."], lacks: ["pre-selects every installed hook connector and configures them all in `observe` mode. It then shows one checklist"] },
  { gap: "GAP-2223", page: "connectors/codex.mdx", has: ["A per-user install writes no `.env` block", "On a managed Linux or macOS computer, setup keeps a marked block in `$CODEX_HOME/.env`"], lacks: ["On Linux and macOS, setup keeps a marked block in `$CODEX_HOME/.env`"] },
  { gap: "GAP-2361", page: "enterprise/operations.mdx", has: ["On a managed standalone computer `/health` carries the `policy`", "`curl http://127.0.0.1:18970/health`, even under `sudo`, has no `policy` key", "sudo curl -s --unix-socket /opt/cisco/defenseclaw/run/hook.sock http://localhost/health"], lacks: ["The gateway stamps it on `/health` and `/status`"] },
  { gap: "GAP-2342", page: "get-started/first-run.mdx", has: ["You do not need `init` before `quickstart`.", "If `init` chose no agent and started the gateway, `quickstart --connector <name>` restarts the gateway so it loads the agent and writes its hooks."] },
  { gap: "GAP-0010", page: "connectors/kiro.mdx", section: "ACP guard", has: ["In enterprise managed mode an administrator enrolls each user, editor and agent with `defenseclaw-gateway enterprise acp enroll`, and the user runs the setup command it reports.", "Managed ACP is preview"], lacks: ["ACP editors are not supported in enterprise managed mode"] },
  { gap: "GAP-2190", page: "connectors/codex.mdx", section: "Files DefenseClaw will modify", has: ["| Connector credentials | `~/.defenseclaw/hooks` | `%USERPROFILE%\\.defenseclaw\\hooks` | | Proxy bypass for cloud credentials (managed Linux and macOS only) | `$CODEX_HOME/.env` (marked block; a per-user install writes none) | not written |"] },
  { gap: "GAP-1536", page: "enterprise/mdm/intune-macos.mdx", has: ["| Upload script | Your edited copy of `defenseclaw-enterprise.sh`, with the config added |"], lacks: ["the wrapper is about"] },
  // pod docs i1 (2026-10-28)
  { gap: "GAP-2051", page: "get-started/windows/telemetry-security.mdx", has: ["OpenCode's managed plugin also grant access only to the user (or `OWNER RIGHTS`) and SYSTEM", "`judge_bodies.db`", "also grant Administrators"], lacks: ["readable by the user, Administrators, and SYSTEM, and so is OpenCode's managed"] },
  { gap: "GAP-1766", page: "enterprise/troubleshooting.mdx", has: ["and `verify` reports it as an error and exits `1`. On Windows `status` warns `policy_not_applied` with the Setup `/repair` next step, `security_complete` is `false`, and `verify` fails (exit `1603`)."], lacks: ["computes to. The message gives both and says the gateway applies the config on its next reload. `status` and `verify` show the same condition"] },
  { gap: "GAP-1766", page: "enterprise/troubleshooting.mdx", has: ["`policy.last_reload_error` and `policy.applied: false` say the same. `verify` fails with this code (exit `1603`)."] },
  { gap: "GAP-2099", page: "support-matrix.mdx", has: ["the guardian rewrites, within seconds, the records that no longer match the live registration", "Records that still match stay byte for byte as restored."], lacks: ["the guardian and gateway rewrite them at the next check", "the running guardian rewrites them within minutes"] },
  // pod docs it2 (2026-10-28)
  { gap: "GAP-2257", page: "connectors/codex.mdx", section: "Setup", has: ["On a terminal it still asks: `Select mode (1, 2) [2]:` with the current mode as the default (Enter keeps it)", "`Codex is already configured; re-apply its hooks (mode=action)? [Y/n]:`", "`Add LLM judge on top of rule scanning? [y/N]:`", "`--yes` skips the questions and keeps the current mode"] },
  // pod docs it3 (2026-10-28)
  { gap: "GAP-2264", page: "hitl.mdx", has: ["Outside Manual mode Claude Code cannot ask, so the call is blocked and its row shows `decision=blocked` in the list and `blocked` on the `Decision` line of `--show`."], lacks: ["Outside Manual mode, the decision is `block`."] },
  { gap: "GAP-2264", page: "stories/hitl-approvals.mdx", has: ["Outside Manual mode Claude Code cannot ask, so the call is blocked and its row shows `decision=blocked` in the list and `blocked` on the `Decision` line of `--show`."], lacks: ["Outside Manual mode, the decision is `block`."] },
  { gap: "GAP-2260", page: "guardrail/semantic-routing.mdx", has: ["Native Windows is not supported: there `defenseclaw setup routing` says so and refuses `--enable`, and `--disable` still turns off a routing block copied from another machine."] },
  { gap: "GAP-2334", page: "enterprise/mdm/linux-config-management.mdx", section: "Check health", has: ["| Kit detection script | `packaging/mdm/linux/detect.sh --require-healthy` (exit `1`, or `unhealthy` with `--format value`, when `verify` reports a problem or `security_complete` is `false`: a host whose `verify` passes with incomplete security still fails it, and the message says which) |"], lacks: ["| Kit detection script | `packaging/mdm/linux/detect.sh --require-healthy` |"] },
  // pod docs r105 loop i1 (2026-10-28)
  { gap: "GAP-2411", page: "enterprise/troubleshooting.mdx", has: ["On Linux and macOS `status` warns `policy_not_applied` with `policy.applied: false` and `security_complete: false`, and `verify` reports it as an error and exits `1`."], lacks: ["`policy.applied: false` and do not warn"] },
  { gap: "GAP-2411", page: "enterprise/operations.mdx", has: ["`verify` reports `policy_not_applied` or `policy_reload_rejected` as an error"] },
  { gap: "GAP-2412", page: "enterprise/ai-defense-key.mdx", has: ["that applies signed policy bundles, contact your administrator: `secret set`"], lacks: ["bundle apply --bundle", "bundle sign --secret-file"] },
  { gap: "GAP-2412", page: "enterprise/troubleshooting.mdx", has: ["| `disk_full` | Linux, macOS; Windows policy bundles |"], lacks: ["Windows bundle apply"] },
];

function pageSection(name: string, heading?: string): string {
  const text = page(name);
  if (!heading) return text;
  const body = text.split(`## ${heading} `)[1];
  assert.ok(body !== undefined, `${name} has no "## ${heading}" section`);
  return body.split(' ## ')[0];
}

// GAP-0506 class: a Markdown table row about a gateway outage states no outcome of its own;
// it points at the gateway outage table (or the fail modes reference) and never keys the
// outage result by the guardrail mode. The table page and the fail modes reference are the sources.
describe('outage rows in Markdown tables point at the outage table (GAP-0506)', () => {
  const outageCell = /^(?:an? )?(?:hook|agent hook|hooks) (?:cannot|can't|could not) reach the gateway|^(?:the )?gateway (?:outage|is down|is unreachable|is not running|is stopped|stops|cannot answer)\b|^gateway (?:down|unreachable|not running|stopped)\b/i;
  const outcome = /\b(?:block|blocks|blocked|run|runs|allow|allows|allowed|deny|denies|denied|refuse|refuses|fails? (?:open|closed))\b/i;
  const pointer = /\/docs\/connectors\/capability-matrix#gateway-outage|\/docs\/reference\/fail-modes/;
  const byGuardrailMode = /\b(?:in|under) (?:observe|action) mode\b[^|.;:]{0,40}\b(?:fails? (?:open|closed)|runs?|blocks?|allows?|denies)\b|\b(?:observe|action)(?: mode)?\s*(?::|=|->)\s*(?:fails? )?(?:open|closed)\b/i;
  it('every outage row links the table and does not key the result by guardrail mode', () => {
    const sources = new Set(['connectors/capability-matrix.mdx', 'reference/fail-modes.mdx']);
    const bad: string[] = [];
    let rows = 0;
    for (const file of mdxPages(docs)) {
      const rel = relative(docs, file).replace(/\\/g, '/');
      if (sources.has(rel)) continue;
      for (const line of readFileSync(file, 'utf8').split('\n')) {
        if (!line.startsWith('|')) continue;
        const cells = line.split('|').slice(1, -1).map((cell) => cell.trim());
        if (cells.length < 2 || !outageCell.test(cells[0].replace(/[*`]/g, ''))) continue;
        const body = cells.slice(1).join(' | ');
        if (!outcome.test(body)) continue;
        rows++;
        if (!pointer.test(body)) bad.push(`${rel}: no outage table link: ${line.slice(0, 160)}`);
        if (byGuardrailMode.test(body)) bad.push(`${rel}: outage result keyed by guardrail mode: ${line.slice(0, 160)}`);
      }
    }
    assert.ok(rows >= 1, `expected at least the segmentation outage row, found ${rows}`);
    assert.deepEqual(bad, []);
  });
});

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
    assert.ok(page('scanning/skill-scanner.mdx').includes('[WARN] Scanner settings — the skill-scanner LLM judge is off;'));
  });
});

describe('edge API examples carry every response field (GAP-1632)', () => {
  it('names each Device JSON field and the list paging keys', () => {
    const fields = [...source('internal/fleet/manager/manager.go').split('type Device struct')[1].split('\n}')[0].matchAll(/json:"([a-z_]+)"/g)].map((m) => m[1]);
    assert.ok(fields.length >= 25, `Device has ${fields.length} JSON fields`);
    const api = page('edge-connector/api-reference.mdx');
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
    const text = page('edge-connector/install.mdx');
    assert.ok(text.includes('are read only by the adapters and are listed only on this page'));
  });
});

// GAP-1461: the observe/action split of the authorized_keys sentence is the
// shipped rule severity (CRITICAL in every pack) under the mode mapping.
describe('authorized_keys writes block in action mode and alert in observe (GAP-1461)', () => {
  it('rates persistence.ssh_authorized_keys_command CRITICAL in every pack', () => {
    for (const pack of ['default', 'permissive', 'strict']) {
      const yaml = source(`policies/guardrail/${pack}/rules/commands.yaml`);
      const rule = yaml.split('- id: persistence.ssh_authorized_keys_command\n')[1]?.split(/\n {2}- id: /)[0] ?? '';
      assert.ok(rule, `${pack}: no persistence.ssh_authorized_keys_command rule`);
      assert.match(rule, /^ {4}severity: CRITICAL$/m, `${pack}: not CRITICAL (GAP-1461 sentence)`);
    }
  });
});

// GAP-0044: a policy (emergency) stop of a MicroVM whose disk sync failed
// contains it and leaves it running; the pages say so.
describe('policy stop of an unsynced MicroVM contains it (GAP-0044)', () => {
  it('matches lifecycle.go: an emergency stop with a failed flush returns containedStopRefusal', () => {
    const go = source('internal/openshell/manager/lifecycle.go');
    assert.match(go, /if why, ok := emergencyStop\(ctx\); ok \{\n\t+return containedStopRefusal\(name, flushErr, m\.containUnsynced\(ctx, b, why\)\)/, 'GAP-0044: emergency stop branch changed; re-check the pages');
  });
});

// GAP-2193: each Entra page callout appears once.
describe('identity-entra-id callouts appear once (GAP-2193)', () => {
  it('has one "A per-user config belongs to the user" callout', () => {
    const text = page('enterprise/identity-entra-id.mdx');
    assert.equal(text.split('<Callout type="warn" title="A per-user config belongs to the user">').length - 1, 1);
  });
  it('has each callout title once', () => {
    const titles = [...page('enterprise/identity-entra-id.mdx').matchAll(/<Callout[^>]*title="([^"]+)"/g)].map((m) => m[1]);
    assert.deepEqual(titles.filter((t, i) => titles.indexOf(t) !== i), []);
  });
});

// GAP-2347 class: only a per-user gateway turns hook-failures.jsonl lines
// into a guardrail-degraded alert (reportHookFailOpenCalls returns on a
// managed host), so every sentence that promises that alert from the file
// says per-user.
describe('fail-open alert promises are scoped to per-user installs (GAP-2347)', () => {
  it('scopes every hook-failures.jsonl guardrail-degraded sentence and matches the gateway', () => {
    const report = source('internal/gateway/hook_failopen_report.go');
    assert.match(report, /func \(s \*Sidecar\) reportHookFailOpenCalls\(\) \{\s*if s == nil \|\| s\.logger == nil \|\| ManagedEnterpriseActive\(\) \{\s*return/, 'the managed early return moved: re-check the docs scope');
    const walk = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : e.name.endsWith('.mdx') ? [join(dir, e.name)] : []));
    const root = join(site, 'content/docs');
    const unscoped: string[] = [];
    for (const file of walk(root)) {
      const paragraphs = readFileSync(file, 'utf8').split(/\n\s*\n/).map((p) => p.split(/\s+/).join(' '));
      for (const sentence of paragraphs.flatMap((p) => p.split(/(?<=[.;])\s+(?=[A-Z`*\[-])/))) {
        if (!sentence.includes('hook-failures.jsonl') || !/guardrail-degraded/.test(sentence)) continue;
        if (!/per-user/i.test(sentence)) unscoped.push(`${relative(root, file)}: ${sentence.slice(0, 160)}`);
      }
    }
    assert.deepEqual(unscoped, []);
    for (const name of ['connectors/hermes.mdx', 'connectors/copilot.mdx']) assert.ok(page(name).includes('A managed gateway raises no such alert'), `${name} lost the managed sentence`);
  });
});

// GAP-2330 class: doctor rows and checks are explained under the CLI
// reference's Read the rows; the upgrade page's Troubleshooting lists only
// installer and upgrade failures, so no sentence about a doctor row or check
// sends the reader there.
describe('doctor rows are not sent to the upgrade troubleshooting (GAP-2330)', () => {
  it('has no sentence that maps a doctor row or check to get-started/upgrade', () => {
    const offenders: string[] = [];
    const walk = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : e.name.endsWith('.mdx') ? [join(dir, e.name)] : []));
    const root = join(site, 'content/docs');
    for (const file of walk(root)) {
      const paragraphs = readFileSync(file, 'utf8').split(/\n\s*\n/).map((p) => p.split(/\s+/).join(' '));
      for (const sentence of paragraphs.flatMap((p) => p.split(/(?<=[.:;])\s+(?=[A-Z0-9`*\[-])/))) {
        if (!sentence.includes('](/docs/get-started/upgrade')) continue;
        if (/\b(doctor|fail|warn)\b[^.]*\b(rows?|checks?)\b/i.test(sentence)) offenders.push(`${relative(root, file)}: ${sentence.slice(0, 160)}`);
      }
    }
    assert.deepEqual(offenders, []);
    assert.ok(page('reference/index.mdx').includes('([Read the rows](/docs/reference/cli#read-the-rows))'), 'runbook step 4 lost its doctor rows link');
    assert.ok(page('reference/cli.mdx').includes('### Read the rows'), 'the Read the rows anchor is gone');
  });
});

// GAP-2333 class: every code name in the capability matrix's contributor
// table exists in the source files that row names, so a renamed or removed
// interface or function cannot stay on the page.
describe('capability matrix contributor sources exist (GAP-2333)', () => {
  it('names only symbols found in the files of its row', () => {
    const raw = readFileSync(join(site, 'content/docs/connectors/capability-matrix.mdx'), 'utf8');
    const table = raw.split('<Accordion title="Where the data comes from (for contributors)">')[1]?.split('</Accordion>')[0] ?? '';
    const rows = table.split('\n').filter((l) => l.startsWith('| ') && !l.startsWith('| Field') && !l.startsWith('| ---'));
    assert.ok(rows.length >= 6, 'contributor table not found');
    const defaultDirs = ['internal/gateway/connector', 'cli/defenseclaw/commands'];
    const missing: string[] = [];
    let symbols = 0;
    for (const row of rows) {
      const tokens = [...row.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
      const isPath = (t: string) => t.includes('/') || /\.(go|py|json|ts|js)$/.test(t);
      const files: string[] = [];
      for (const tok of tokens.filter(isPath)) {
        if (tok.endsWith('/')) { readdirSync(join(repo, tok)); continue; }
        const dirs = tok.includes('/') ? [dirname(tok)] : defaultDirs;
        const base = tok.includes('/') ? tok.slice(tok.lastIndexOf('/') + 1) : tok;
        const pattern = new RegExp('^' + base.replace(/[.]/g, '\\.').replace(/\*/g, '.*').replace(/<[^>]+>/g, '.+') + '$');
        const hits = dirs.flatMap((d) => readdirSync(join(repo, d)).filter((f) => pattern.test(f)).map((f) => join(d, f)));
        assert.ok(hits.length > 0, `contributor table names a file that does not exist: ${tok}`);
        files.push(...hits);
      }
      if (files.length === 0) files.push(...defaultDirs.flatMap((d) => readdirSync(join(repo, d)).filter((f) => /\.(go|py)$/.test(f)).map((f) => join(d, f))));
      const corpus = files.map((f) => readFileSync(join(repo, f), 'utf8')).join('\n');
      for (const tok of tokens.filter((t) => !isPath(t))) {
        const name = tok.match(/^[A-Za-z_][A-Za-z0-9_]*/)?.[0];
        if (!name) continue;
        symbols += 1;
        if (!new RegExp(`\\b${name}\\b`).test(corpus)) missing.push(`${name} (row: ${row.split('|')[1].trim()})`);
      }
    }
    assert.ok(symbols >= 6, `only ${symbols} code names checked`);
    assert.deepEqual(missing, []);
  });
});

// GAP-2350 / GAP-1696 class: the security_incomplete scope on every page
// follows enterprisestatus Finish (named on Linux and macOS) and the Windows
// reasons (named next to the agent residuals, GAP-1900).
describe('security_incomplete scope matches the status code (GAP-2350, GAP-1696)', () => {
  it('lists every OS and scopes no sentence to 1.0.3 or hosts without Claude Code or Codex', () => {
    const result = source('internal/enterprisestatus/result.go');
    assert.match(result, /if goos != "windows" \{\s*r\.nameIncompleteFields\(\)/, 'Finish no longer names incomplete fields on Linux and macOS: re-check the OS column');
    assert.ok(result.includes('"security_complete is false because of: "'), 'the Linux/macOS message changed: re-check the sample');
    const walk = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : e.name.endsWith('.mdx') ? [join(dir, e.name)] : []));
    const root = join(site, 'content/docs');
    const stale: string[] = [];
    for (const file of walk(root)) {
      for (const line of readFileSync(file, 'utf8').split('\n')) {
        if (!line.includes('security_incomplete')) continue;
        if (/1\.0\.3 or a host without/.test(line) || /^\| `security_incomplete` \| Windows \|/.test(line)) stale.push(`${relative(root, file)}: ${line.slice(0, 160)}`);
      }
    }
    assert.deepEqual(stale, []);
  });
});

// GAP-2351 class: the doctor freshness wording on the pages is the wording
// cmd_doctor.py prints, for both the older-build case and the hand edit.
describe('doctor hook freshness wording matches cmd_doctor.py (GAP-2351)', () => {
  it('names both doctor messages and the doctor still prints them', () => {
    const doctor = source('cli/defenseclaw/commands/cmd_doctor.py');
    for (const s of ['stale generated script (', 'a generated script is not the one setup rendered', "run 'defenseclaw doctor --fix' to render the scripts again"]) assert.ok(doctor.includes(s), `cmd_doctor.py no longer prints: ${s}`);
    for (const name of ['reference/configuration.mdx', 'reference/cli.mdx', 'guardrail/index.mdx']) assert.ok(page(name).includes('a generated script is not the one setup rendered'), `${name} lacks the hand-edit wording`);
  });
});

// GAP-2354 / GAP-2332 / GAP-2353: the three sentences follow the code that
// decides them; a change there re-opens the page.
describe('audit-failure tiers, admission defaults and local-provider keys match the code (GAP-2354, GAP-2332, GAP-2353)', () => {
  it('keeps the per-user degraded allow, the skill scanner gate (warn MEDIUM, allow LOW/INFO) and OPTIONAL for an enabled guardrail', () => {
    const hook = source('internal/gateway/agent_hook.go');
    assert.ok(hook.includes('DefenseClaw audit is degraded: this call was allowed, but its audit record could not be written.'), 'agent_hook.go no longer prints the degraded-audit message');
    assert.match(hook, /!managed\.IsManagedEnterprise\(cfg\.DeploymentMode\) &&\s*cfg\.HookPolicyTierForConnector\(connectorName\) != config\.HookPolicyTierStrict &&\s*!sandboxHookForConnector/, 'the audit-failure allow is no longer per-user non-strict outside sandboxes: re-check support-matrix.mdx');
    // Skills: the scanner gate (fail_on_severity HIGH, review_queue_min
    // MEDIUM) decides before the built-in map, so LOW and INFO allow.
    const adm = source('internal/policy/admission.go');
    assert.match(adm, /derived = derivedScannerGate\(skill\.EffectiveFailOnSeverity\(\), skill\.EffectiveReviewQueueMin\(\)\)/, 'skills no longer take the scanner gate: re-check scanning/index.mdx');
    assert.match(adm, /case rank >= review:\s*out\[sev\] = actionWarn\s*default:\s*out\[sev\] = actionAllow/, 'the scanner gate no longer allows below review_queue_min: re-check scanning/index.mdx');
    const settings = source('internal/config/scanner_settings.go');
    assert.match(settings, /DefaultSkillScannerFailOnSeverity\s*=\s*"HIGH"/, 'skill scanner fail_on_severity default changed: re-check scanning/index.mdx');
    assert.match(settings, /DefaultSkillScannerReviewQueueMin\s*=\s*"MEDIUM"/, 'skill scanner review_queue_min default changed: re-check scanning/index.mdx');
    const py = source('cli/defenseclaw/enforce/admission.py');
    assert.ok(py.includes('_DEFAULT_FAIL_ON_SEVERITY = "HIGH"') && py.includes('_DEFAULT_REVIEW_QUEUE_MIN = "MEDIUM"'), 'Python scanner gate defaults changed: re-check scanning/index.mdx');
    assert.ok(py.includes('out[sev] = _SHORTHANDS["warn"] if rank >= review else _SHORTHANDS["allow"]'), 'Python scanner gate no longer allows below review_queue_min: re-check scanning/index.mdx');
    const cred = source('cli/defenseclaw/credentials.py');
    assert.match(cred, /def _defenseclaw_llm_key[\s\S]*?getattr\(gc, "enabled", False\):\s*return Requirement\.OPTIONAL/, 'DEFENSECLAW_LLM_KEY is no longer OPTIONAL with the guardrail on: re-check unified-llm-key.mdx');
  });
});

// GAP-2359: the setup summary prints the strategy that runs (judge off ->
// regex_only, GAP-1647), not the saved default; the page's summary matches.
describe('setup summary shows the effective detection strategy (GAP-2359)', () => {
  it('prints _effective_detection_strategy, which reads the guardrail status value', () => {
    const setup = source('cli/defenseclaw/commands/cmd_setup.py');
    assert.ok(setup.includes('("guardrail.detection_strategy", _effective_detection_strategy(gc, gc.connector)),'), 'summary no longer prints the effective strategy: re-check guardrail/index.mdx');
    assert.ok(setup.includes('return _scan_value(gc, connector)'), 'effective strategy no longer comes from the status value');
  });
});

// GAP-2338 class: every `subject.<field>` a page names is a key the
// profile-explain subject object has (guardrail_profile.go).
describe('profile-explain subject fields exist (GAP-2338)', () => {
  it('names only keys of the subject map', () => {
    const go = source('internal/gateway/guardrail_profile.go');
    const block = go.split('out["subject"] = map[string]any{')[1]?.split('\n\t\t}')[0] ?? '';
    const keys = new Set([...block.matchAll(/"([a-z_]+)":/g)].map((m) => m[1]));
    assert.ok(keys.has('principal') && keys.has('directory'), 'subject map not found in guardrail_profile.go');
    for (const name of ['enterprise/identity-sources.mdx', 'enterprise/identity-and-authentication.mdx']) {
      for (const m of page(name).matchAll(/`subject\.([a-z_]+)/g)) {
        assert.ok(keys.has(m[1]), `${name} names subject.${m[1]}, which profile-explain does not print`);
      }
    }
  });
});

// GAP-2356 / GAP-2357: managed hosts run the Go CLI, which has no guardrail
// group and whose profile-explain needs --user; the page says so.
describe('managed profile commands match the Go CLI (GAP-2356, GAP-2357)', () => {
  it('keeps --user required and no guardrail command in the Go CLI', () => {
    assert.ok(source('internal/cli/enterprise_identity_views.go').includes('if view.use == "profile-explain" && query.Get("user") == "" {'), 'enterprise profile-explain no longer requires --user: re-check user-and-group-policies.mdx step 3');
    // git grep exits 1 when nothing matches: no Go command named guardrail.
    let withGuardrail = '';
    try {
      withGuardrail = execFileSync('git', ['grep', '-l', '-E', 'Use:[[:space:]]+"guardrail', '--', 'internal/cli/*.go', ':!*_test.go'], { cwd: repo, encoding: 'utf8' }).trim();
    } catch (err) {
      if ((err as { status?: number }).status !== 1) throw err;
    }
    assert.equal(withGuardrail, '', 'the Go CLI gained a guardrail command: re-check user-and-group-policies.mdx Before you start');
  });
});

// GAP-2360 / GAP-2363: the wizard asks the hook fail mode only on a run that
// turns the guardrail on or changes the mode, and the per-connector writers
// the multi-connector page lists confirm unless --yes.
describe('wizard fail-mode question and per-connector confirmations match the CLI (GAP-2360, GAP-2363)', () => {
  it('asks the fail mode only when the guardrail was off or the mode changed', () => {
    const setup = source('cli/defenseclaw/commands/cmd_setup.py');
    assert.ok(setup.includes('was_initial_setup = not bool(gc.enabled)'), 'initial-setup test changed: re-check guardrail/index.mdx fail-mode row');
    assert.ok(setup.includes('if was_initial_setup or mode_changed:\n        _prompt_hook_fail_mode(gc)'), 'fail-mode question condition changed: re-check guardrail/index.mdx');
  });
  it('gives hilt, fail-mode, block-message, enable and disable a --yes confirmation', () => {
    const cli = source('cli/defenseclaw/commands/cmd_guardrail.py');
    for (const name of ['hilt', 'fail-mode', 'block-message', 'enable', 'disable']) {
      const head = cli.split(`@guardrail.command("${name}"`)[1]?.split('\ndef ')[0] ?? '';
      assert.ok(head.includes('@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")'), `guardrail ${name} lost its --yes confirmation: re-check guardrail/multi-connector.mdx`);
    }
  });
});

// GAP-2257: a re-run of a hook connector setup keeps the mode but still asks
// on a terminal (mode, re-apply, judge in action mode). Every page that says a
// re-run keeps the current mode must also say it asks and that --yes skips it.
describe('setup re-run pages say the re-run asks on a terminal (GAP-2257)', () => {
  it('keeps the asking code the pages describe', () => {
    const setup = source('cli/defenseclaw/commands/cmd_setup.py');
    assert.ok(setup.includes('if interactive and not mode_from_flag:\n        normalized_mode = _prompt_connector_mode(connector, default_mode=normalized_mode)'), 're-run mode question changed: re-check the connector pages (GAP-2257)');
    assert.ok(setup.includes('if interactive and normalized_mode == "action" and enable_judge is None and _prompt_enable_judge(connector, gc):'), 'judge question condition changed: re-check connectors/codex.mdx (GAP-2257)');
    assert.ok(setup.includes('"  Add LLM judge on top of rule scanning?",\n        default=already,'), 'judge question text changed: re-check connectors/codex.mdx (GAP-2257)');
  });
  it('every keeps-the-current-mode sentence names the questions and --yes', () => {
    const pages = ['amp', 'antigravity', 'claudecode', 'codex', 'copilot', 'cursor', 'devin', 'hermes', 'kiro', 'opencode'].map((c) => `connectors/${c}.mdx`);
    for (const page of [...pages, 'reference/cli.mdx', 'reference/setup-commands.mdx']) {
      const text = pageSection(page);
      for (const m of text.matchAll(/re-run without `--mode` keeps the current mode[^\n]*/g)) {
        assert.ok(/asks/.test(m[0]) && m[0].includes('`--yes` skips the questions'), `${page}: a re-run sentence does not say it asks on a terminal and that --yes skips it: ${m[0].slice(0, 120)}`);
      }
    }
  });
});

// GAP-2365 / GAP-2367 / GAP-2368: the setup re-run question, where
// trusted-paths writes and the watchdog default follow the code.
describe('setup re-run question, trusted-paths store and watchdog default match the code (GAP-2365, GAP-2367, GAP-2368)', () => {
  it('asks re-apply on a re-run and configure-now with no peer', () => {
    const setup = source('cli/defenseclaw/commands/cmd_setup.py');
    assert.ok(setup.includes('f"  {label} is already configured; re-apply its hooks (mode={normalized_mode})?"'), 're-run question changed: re-check guardrail/switching-connectors.mdx');
    assert.ok(setup.includes('f"  Configure DefenseClaw for {label} {verb} now?"'), 'configure-now question changed: re-check guardrail/switching-connectors.mdx');
    assert.ok(setup.includes('mode = gc.effective_mode(connector) if connector in _configured_connector_set(gc) else "observe"'), 'mode default changed: re-check guardrail/switching-connectors.mdx');
  });
  it('writes trusted-paths additions to config.yaml', () => {
    const setup = source('cli/defenseclaw/commands/cmd_setup.py');
    assert.ok(setup.includes('Add a directory to ai_discovery.trusted_binary_prefixes in config.yaml.'), 'trusted-paths store changed: re-check reference/setup-commands.mdx and reference/cli.mdx');
    for (const page of ['reference/setup-commands.mdx', 'reference/cli.mdx']) {
      assert.ok(!pageSection(page).includes('and persists to `~/.defenseclaw/.env`'), `${page} sends trusted-paths add to .env`);
    }
  });
  it('turns the watchdog on by default and starts it with the gateway', () => {
    assert.ok(source('internal/config/config.go').includes('viper.SetDefault("gateway.watchdog.enabled", true)'), 'watchdog default changed: re-check get-started/windows/paths-troubleshooting.mdx');
    assert.ok(source('internal/cli/daemon.go').includes('func startConfiguredWatchdog('), 'gateway start no longer starts the watchdog: re-check get-started/windows/paths-troubleshooting.mdx');
  });
});

// GAP-2179: every NAME=value property standalone Setup /? prints is in both
// Setup property tables. GAP-2171: an unknown defenseclaw.exe flag under
// `enterprise` keeps cobra's error (exit 1); only lifecycle refusals are 1639.
describe('Setup properties and the Windows unknown-flag exit match the code (GAP-2179, GAP-2171)', () => {
  it('lists every property standalone Setup /? prints', () => {
    const main = source('cmd/defenseclaw-enterprise-setup/main.go');
    const usage = main.slice(main.indexOf('func writeStandaloneSetupUsage('), main.indexOf('Exit codes: 0 success, 1603 failure'));
    const props = [...usage.matchAll(/"  ([A-Z]+)=/g)].map((m) => m[1]);
    assert.ok(props.length >= 12, `Setup usage parse found ${props.length} properties`);
    for (const page of ['enterprise/windows.mdx', 'reference/cli.mdx']) {
      const text = pageSection(page);
      for (const p of props) assert.ok(text.includes('`' + p + '='), `${page} Setup property table lacks ${p}=`);
    }
  });
  it('keeps the enterprise tree out of the root usage-error mapping', () => {
    const exit = source('internal/cli/exit_code.go');
    assert.ok(exit.includes('var usageFlagErrorExempt = []string{"enterprise", "hook", "notify", "watchdog"}') && exit.includes('\treturn 1\n}'), 'unknown-flag exit for enterprise windows changed: re-check enterprise/operations.mdx and enterprise/troubleshooting.mdx (GAP-2171)');
  });
});

// GAP-2221: the Fleet setup questions, the sudo write and the refusal the page quotes.
describe('edge-connector setup prompts and sudo refusal match the CLI (GAP-2221)', () => {
  it('asks for the token, writes the service env through sudo and stops when it cannot', () => {
    const py = source('cli/defenseclaw/commands/cmd_setup_edge_connector.py');
    assert.ok(py.includes('"Generate a new fleet API bearer token?", default=True'), 'token question changed: re-check edge-connector/install.mdx');
    assert.ok(py.includes('subprocess.run(["sudo", "install", "-d", "-m", "700", str(svc_env_path.parent)], check=True)'), 'service env is no longer written through sudo: re-check edge-connector/install.mdx');
    assert.ok(py.includes('f"Could not provision {name} in {svc_env_path}; Edge setup is incomplete"'), 'sudo refusal text changed: re-check edge-connector/install.mdx');
    assert.ok(py.indexOf('Edge setup is incomplete') < py.indexOf('_enable_fleet_config(ctx.obj.cfg.data_dir)'), 'Fleet is enabled before the service env is written: re-check "Fleet stays off" in edge-connector/install.mdx');
  });
});

// GAP-1519: the "Can ask you first" column of the connectors table follows
// capability-matrix.json (canAskNative and askEvents) for every connector.
describe('connectors table ask column matches the capability data (GAP-1519)', () => {
  it('says No exactly where canAskNative is false and names every ask event otherwise', () => {
    const matrix = JSON.parse(readFileSync(join(site, 'data/capability-matrix.json'), 'utf8')) as { connectors: { id: string; hooks?: { canAskNative?: boolean; askEvents?: string[] } }[] };
    const byId = new Map(matrix.connectors.map((c) => [c.id, c.hooks ?? {}]));
    const table = readFileSync(join(site, 'content/docs/connectors/index.mdx'), 'utf8').split('## Pick yours')[1]?.split('\n## ')[0] ?? '';
    const rows = table.split('\n').filter((line) => /^\| \[[^\]]+\]\(\/docs\/connectors\/[a-z]+\)/.test(line));
    assert.ok(rows.length >= 10, 'connectors/index.mdx Pick yours table not found');
    for (const row of rows) {
      const id = /\/docs\/connectors\/([a-z]+)\)/.exec(row)![1];
      const hooks = byId.get(id);
      assert.ok(hooks, `${id}: not in capability-matrix.json`);
      const ask = row.split('|')[4].trim();
      if (hooks.canAskNative) {
        assert.ok(!ask.startsWith('No'), `${id}: canAskNative true but the table says ${ask}`);
        for (const event of hooks.askEvents ?? []) assert.ok(ask.includes('`' + event + '`'), `${id}: ask event ${event} missing from the table`);
      } else {
        assert.ok(ask.startsWith('No'), `${id}: canAskNative false but the table says ${ask} (GAP-1519)`);
      }
    }
  });
});

// GAP-1537: the Linux MDM wrapper makes at most three attempts (two retries,
// 10 s apart) on busy; intune-linux.mdx says so.
describe('Linux MDM wrapper busy retries match intune-linux.mdx (GAP-1537)', () => {
  it('retries busy twice, 10 seconds apart', () => {
    const sh = source('packaging/mdm/linux/defenseclaw-enterprise.sh');
    const fn = sh.split('dc_run_lifecycle_retry() {')[1]?.split('\n}')[0] ?? '';
    assert.ok(fn.includes('attempt=1') && fn.includes('[ "$attempt" -ge 3 ]') && fn.includes('retry $attempt of 2') && fn.includes('sleep 10'), 'dc_run_lifecycle_retry changed: re-check intune-linux.mdx Execution retries');
    assert.equal((sh.match(/dc_busy_output "\$output" && \[ "\$attempt" -lt 3 \]/g) ?? []).length, 2, 'package busy retry loops changed: re-check intune-linux.mdx Execution retries');
  });
});

// GAP-2334: detect.sh --require-healthy fails on security_complete false as
// well as on a verify problem; the Linux config-management page says so.
describe('kit detect.sh health gate matches the Linux Check health row (GAP-2334)', () => {
  it('fails on a verify problem and on incomplete security', () => {
    const detect = source('packaging/mdm/linux/detect.sh');
    assert.ok(detect.includes('dc_json_true "$verify" ok || dc_report 0 unhealthy') && detect.includes('dc_json_true "$verify" security_complete || dc_report 0 unhealthy "verify reported incomplete security'), 'detect.sh --require-healthy gate changed: re-check enterprise/mdm/linux-config-management.mdx Check health');
  });
});

// GAP-2264: a hook block shows as "blocked" in defenseclaw alerts; the HITL pages quote that word.
describe('alerts decision label for a hook block matches the HITL pages (GAP-2264)', () => {
  it('labels a hook block "blocked"', () => {
    const py = source('cli/defenseclaw/commands/cmd_alerts.py');
    assert.ok(py.includes('if action == "block":') && py.includes('else "blocked"'), 'alerts no longer labels a hook block "blocked": re-check hitl.mdx and stories/hitl-approvals.mdx Check it worked');
  });
});

// GAP-2260: setup routing refuses --enable on native Windows; semantic-routing.mdx says so.
describe('setup routing on native Windows matches semantic-routing.mdx (GAP-2260)', () => {
  it('refuses --enable and names the reason on native Windows', () => {
    const py = source('cli/defenseclaw/commands/cmd_setup.py');
    assert.ok(py.includes('if enable and _routing_unsupported_on_host():') && py.includes('"Semantic routing is not supported on native Windows: it routes OpenClaw and "'), 'setup routing no longer refuses --enable on native Windows: re-check semantic-routing.mdx Prerequisites');
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

// GH #1101 (p0 GAP-0677, GAP-0765): the limit messages the configuration pages quote.
describe('config limit refusals match the configuration pages (GH #1101)', () => {
  it('the parser and schema still word the 4 MiB, 65,536-node and block_message limits as quoted', () => {
    const yaml = source('internal/config/yaml_v8.go');
    assert.ok(yaml.includes('"configuration source exceeds the 4 MiB limit"') && yaml.includes('"parsed YAML exceeds the 65,536-node limit"'), 'config size/node refusal changed: re-check enterprise/configuration.mdx Where the config lives');
    const schema = source('internal/config/schema_v8.go');
    assert.ok(schema.includes('"a string of %s %d characters"') && schema.includes('" (it has %d)"'), 'schema length refusal changed: re-check the block_message sentence in enterprise/configuration.mdx');
    const configSchema = JSON.parse(source('schemas/config/v8/defenseclaw-config.schema.json'));
    const limits: unknown[] = [];
    const walk = (node: unknown): void => {
      if (!node || typeof node !== 'object') return;
      const record = node as Record<string, unknown> & { block_message?: { $ref?: string; maxLength?: number } };
      if (record.block_message && typeof record.block_message === 'object') {
        const ref = String(record.block_message.$ref ?? '').replace('#/$defs/', '');
        limits.push(ref ? configSchema.$defs[ref]?.maxLength : record.block_message.maxLength);
      }
      for (const value of Object.values(record)) walk(value);
    };
    walk(configSchema);
    assert.ok(limits.length > 0 && limits.every((limit) => limit === 4096), `block_message maxLength is not 4096 everywhere: ${limits.join(',')}`);
  });
});

// GAP-2391: keys set stores config-update with target config:dotenv:<ENV>, and
// audit export writes a v8 config.change.applied row with that target in structured.
describe('keys set audit row matches the pages (GAP-2391)', () => {
  it('export maps config-update to config.change.applied and keys set names config:dotenv', () => {
    assert.ok(source('internal/cli/audit_export.go').includes('} else if eventName == "config.change.applied" && actionOut == string(audit.ActionConfigUpdate) {'), 'audit export no longer writes config.change.applied for config-update: re-check unified-llm-key.mdx, keys.mdx, cli.mdx');
    const keys = source('cli/defenseclaw/commands/cmd_keys.py');
    assert.ok(keys.includes('action=ACTION_CONFIG_UPDATE,') && keys.includes('target_type="config",') && keys.includes('target_id=f"dotenv:{env_name}",'), 'keys set audit target changed: re-check the GAP-2391 pages');
    assert.ok(source('cli/defenseclaw/commands/cmd_audit.py').includes('config changes included (action config.change.applied):'), 'audit --help names the old export action');
    // Class residual (checker it12): the Go audit export help and its --include-activity note.
    const exp = source('internal/cli/audit_export.go');
    assert.ok(!exp.includes('(action config-update and others)'), 'audit export help or the --include-activity note names the stored action, not the exported one');
    assert.equal((exp.match(/\(action config\.change\.applied and others\)/g) ?? []).length, 2, 'audit export help and the --include-activity note must name config.change.applied');
  });
});

// GAP-2239, GAP-2224, GAP-2342: the code behind the three page sentences.
describe('setup summary, ASCII markers and the no-connector gateway match the pages (GAP-2239, GAP-2224, GAP-2342)', () => {
  it('summary uses the connector values, piped output uses OK and i, quickstart restarts a no-connector gateway', () => {
    const py = source('cli/defenseclaw/commands/cmd_setup.py');
    assert.ok(py.includes('("guardrail.mode", gc.effective_mode(gc.connector)),') && py.includes('("guardrail.rule_pack", gc.effective_rule_pack(gc.connector) or "default"),'), 'single-connector setup summary no longer prints the connector values: re-check policies/defaults.mdx');
    const ux = source('cli/defenseclaw/ux.py');
    assert.ok(ux.includes('"✓": "OK",') && ux.includes('"ℹ": "i",'), 'ASCII markers changed: re-check stories/cursor-secret-exfil.mdx and get-started/install.mdx');
    const boot = source('cli/defenseclaw/bootstrap.py');
    assert.ok(boot.includes('if roster is None and cfg.active_connectors() and _running_gateway_has_no_connector(cfg):') && boot.includes('guardrail.get("last_error") == "no connector configured"'), 'first run no longer restarts a gateway that booted with no connector: re-check get-started/first-run.mdx');
    assert.ok(source('internal/gateway/sidecar.go').includes('s.health.SetGuardrail(StateDisabled, "no connector configured", details)'), 'the gateway no longer reports a no-connector boot on /health: re-check bootstrap._running_gateway_has_no_connector');
  });
});

// GAP-2262: --non-interactive --detection-strategy regex_only turns the judge off.
describe('Undo turns the judge off without the wizard (GAP-2262)', () => {
  it('regex_only disables the judge in setup guardrail', () => {
    const py = source('cli/defenseclaw/commands/cmd_setup.py');
    assert.ok(py.includes('elif detection_strategy == "regex_only":\n                gc.judge.enabled = False'), 'setup guardrail --detection-strategy regex_only no longer turns the judge off: re-check unified-llm-key.mdx Undo');
    assert.ok(py.includes('@click.option("--non-interactive", is_flag=True, help="Use flags instead of prompts")'), 'setup guardrail lost --non-interactive: re-check unified-llm-key.mdx Undo');
  });
});

// GAP-1921: the CLI flags take OPEN (click Choice, case_sensitive=False) and
// save the lower-case choice; guardrail fail-mode, config set and validate refuse it.
describe('fail-mode case rules match fail-modes.mdx (GAP-1921)', () => {
  it('init, quickstart and setup flags ignore case; guardrail fail-mode does not', () => {
    for (const f of ['cli/defenseclaw/commands/cmd_init.py', 'cli/defenseclaw/commands/cmd_quickstart.py', 'cli/defenseclaw/commands/cmd_setup.py']) {
      assert.ok(/"--fail-mode",\s*type=click\.Choice\(\["open", "closed"\], case_sensitive=False\)/.test(source(f)), `${f} --fail-mode case rule changed: re-check reference/fail-modes.mdx`);
    }
    assert.ok(source('cli/defenseclaw/commands/cmd_guardrail.py').includes('@click.argument("mode", required=False, type=click.Choice(["open", "closed"]))'), 'guardrail fail-mode now ignores case: re-check reference/fail-modes.mdx');
  });
});

// GAP-2392: Overview's hint line shows notices or tips, never a KEYS row; the
// G and z keys are in the quick-action row of the Overview body.
describe('Overview G and z keys are where tui.mdx says (GAP-2392)', () => {
  it('quick actions list G and z; the Overview hint is a notice or a tip', () => {
    const app = source('cli/defenseclaw/tui/app.py');
    assert.ok(app.includes('("G", "Gateway"),') && app.includes('("z", "AI Discovery"),'), 'Overview quick actions changed: re-check tui.mdx Panels');
    const hint = source('cli/defenseclaw/tui/widgets/hint_bar.py');
    const ov = hint.slice(hint.indexOf('def _overview_hint'), hint.indexOf('def _alerts_hint'));
    assert.ok(ov.length > 0 && !ov.includes('KEYS'), 'Overview hint line now has a KEYS row: re-check tui.mdx Panels');
    assert.ok(ov.includes('"Press 2 for Alerts."') && ov.includes('return self.next_tip()'), 'Overview hint notices changed: re-check tui.mdx Panels');
  });
});

// GAP-2349, GAP-2228: the Sandboxes panel keeps P, R and A for its own actions
// (p still opens Policies), and the status strip renders gen/digest and the
// policy posture as separate segments.
describe('Sandboxes panel keys and status strip segments match tui.mdx (GAP-2349, GAP-2228)', () => {
  it('Sandboxes binds P, R and A; p falls back to Policies; gen/digest is its own segment', () => {
    const sb = source('cli/defenseclaw/tui/sandbox_panel.py');
    assert.ok(sb.includes('"sandboxes-pull": "P",') && sb.includes('"sandboxes-review": "R",') && sb.includes('"sandboxes-always": "A",'), 'Sandboxes P/R/A changed: re-check tui.mdx Panels');
    const app = source('cli/defenseclaw/tui/app.py');
    assert.ok(/LOWERCASE_PANEL_FALLBACK[^\n]*"sandboxes": frozenset\(\{"p"/.test(app), 'Sandboxes p no longer opens Policies: re-check tui.mdx Panels');
    const strip = source('cli/defenseclaw/tui/widgets/status_strip.py');
    assert.ok(strip.includes('segments.append(StatusSegment(model.applied_policy, "active"))') && strip.includes('segments.append(StatusSegment(model.policy_posture, "active"))'), 'status strip segments changed: re-check tui.mdx Config generation and policy digest');
  });
});

// GAP-0730: the drift the pages call report-only is the one the daemon exempts
// from the pause (blockingOpenShellDrift): a changed render, nothing else.
describe('rendered gateway.toml drift is reported without a pause (GAP-0730)', () => {
  it('only a changed rendered gateway configuration is non-blocking', () => {
    const go = source('internal/gateway/sandbox_daemon_openshell.go');
    assert.ok(go.includes('renderedGatewayDriftField     = "gateway configuration"'), 'rendered drift field renamed: re-check observability/sandbox-telemetry.mdx and enterprise/sandboxes.mdx');
    assert.ok(go.includes('if item.Field != renderedGatewayDriftField || item.Have != "changed" {'), 'blockingOpenShellDrift changed: a changed render may pause again, re-check the GAP-0730 pages');
    assert.ok(go.includes('drift = blockingOpenShellDrift(drift)'), 'readyOpenShell no longer filters drift: re-check the GAP-0730 pages');
    assert.ok(go.includes('return "gateway_configuration"') && go.includes('driftFieldInvalid.ReplaceAllString(strings.ToLower(field), "_")'), 'driftEventField changed: re-check the field value sandbox-telemetry.mdx names');
  });
});

// GAP-1922: the saved-installer protection the detection page promises is the
// rule every shipped pack carries, and the every-mode claim is the observe test.
describe('saved installer protection matches the rule packs (GAP-1922)', () => {
  it('names installer/ and previous/installer/ in tamper.detector_state_write of every pack, for writes and deletes', () => {
    const text = page('policies/deterministic-detection.mdx');
    assert.ok(text.includes('DefenseClaw also protects its saved installer (`~/.defenseclaw/installer/` and `~/.defenseclaw/previous/installer/`): with the default and strict rule packs, an agent that writes, truncates or deletes it is blocked in every mode, like `config.yaml`. The permissive pack rates this rule HIGH and blocks only CRITICAL, so with it such a write to the saved installer or `config.yaml` is reported, not blocked, in both modes. Reading or running the saved installer stays allowed.'));
    assert.ok(!text.includes('`~/.defenseclaw/previous/installer/`): an agent that writes, truncates or deletes it is blocked in every mode'), 'GAP-0046: unqualified every-mode claim is back');
    assert.ok(page('policies/recipes.mdx').includes('DefenseClaw protects its own files; with the permissive pack it only reports it).'), 'GAP-0046: recipes step 2 lost the pack qualifier');
    // GAP-0046: the page's per-pack split is the shipped severity against the
    // posture thresholds (default and strict block it, permissive reports it).
    const thresholds = source('internal/gateway/decision.go');
    assert.match(thresholds, /case "strict":\n\t\treturn severityMedium, severityLow\n\tcase "permissive":\n\t\treturn severityCritical, severityHigh\n\tdefault:\n\t\treturn severityCritical, severityMedium/, 'GAP-0046: posture thresholds changed; re-check the per-pack sentence');
    const packSeverity: Record<string, string> = { default: 'CRITICAL', strict: 'HIGH', permissive: 'HIGH' };
    for (const pack of ['default', 'permissive', 'strict']) {
      const yaml = source(`policies/guardrail/${pack}/rules/cognitive.yaml`);
      const rule = yaml.split('- id: tamper.detector_state_write\n')[1]?.split(/\n {2}- id: /)[0] ?? '';
      assert.ok(rule, `${pack}: no tamper.detector_state_write rule`);
      const pattern = rule.match(/^ {4}pattern: '(.*)'$/m)?.[1] ?? '';
      assert.ok(pattern.includes('|installer|'), `${pack}: pattern does not name installer/`);
      assert.ok(pattern.includes('previous[/\\\\]installer'), `${pack}: pattern does not name previous/installer/`);
      assert.match(rule, new RegExp(`^ {4}severity: ${packSeverity[pack]}$`, "m"), `${pack}: not ${packSeverity[pack]} (GAP-0046 per-pack sentence)`);
      for (const access of ['PATH_ACCESS_WRITE', 'PATH_ACCESS_APPEND', 'PATH_ACCESS_DELETE']) {
        assert.ok(rule.includes(access), `${pack}: ${access} missing`);
      }
    }
    const goTest = source('internal/gateway/action_saved_installer_state_test.go');
    assert.ok(goTest.includes('instructionProtectionTestAPI(t, agent, "observe", "HIGH")'), 'the every-mode proof no longer runs in observe');
    for (const row of ['{"append installer", ', '{"delete previous installer", ', '{"read installer", ', '{"run saved installer help", ']) {
      assert.ok(goTest.includes(row), `Go test lost row ${row}`);
    }
  });
});

// GAP-2289: the setup guardrail connector list matches the CLI's choices per
// OS: the proxy connectors are refused on native Windows (platform_support.py).
describe('setup guardrail --connector choices match the CLI (GAP-2289)', () => {
  it('lists the hook connectors everywhere and openclaw/zeptoclaw only on Linux and macOS', () => {
    const setup = source('cli/defenseclaw/commands/cmd_setup.py');
    const fallback = setup.split('_CONNECTOR_NAMES_FALLBACK = [')[1]?.split(']')[0] ?? '';
    const names = [...fallback.matchAll(/"([a-z]+)"/g)].map((m) => m[1]).sort();
    assert.match(setup, /type=_PlatformConnectorChoice\(_CONNECTOR_NAMES, case_sensitive=False\)/);
    const support = source('cli/defenseclaw/platform_support.py');
    const windows = support.split('WINDOWS_CONNECTOR_SUPPORT')[1] ?? '';
    const refused = [...windows.matchAll(/"([a-z]+)": ConnectorPlatformSupport\(\s*UNSUPPORTED,/g)].map((m) => m[1]).sort();
    assert.deepEqual(refused, ['openclaw', 'zeptoclaw']);
    const hooks = names.filter((n) => !refused.includes(n));
    const text = page('guardrail/index.mdx');
    const row = text.split('**Which agent framework are you using?**')[1]?.split('| **Enable guardrail?**')[0] ?? '';
    const listed = row.split('; on Linux and macOS also')[0];
    assert.deepEqual([...listed.matchAll(/`([a-z]+)`/g)].map((m) => m[1]).filter((n) => n !== 'connector' && n !== 'agent').sort(), hooks.sort());
    assert.ok(row.includes('on Linux and macOS also `openclaw` and `zeptoclaw`. Native Windows refuses those two'), 'connector row lost the per-OS split');
    assert.ok(text.includes('amp or kiro; on Linux and macOS also openclaw or zeptoclaw (native Windows refuses those two: they need the guardrail proxy)'), 'flag table lost the per-OS split');
    assert.ok(!text.includes('`kiro`, `openclaw`, `zeptoclaw`.'), 'old unqualified list is back');
  });
});

// GAP-2291: an in-page link on a connector page points at a heading of that page.
describe('connector pages have no dead in-page anchors (GAP-2291)', () => {
  it('resolves every [text](#anchor) link to a heading on the same page', () => {
    const dir = join(site, 'content/docs/connectors');
    const dead: string[] = [];
    for (const file of docsPages(dir)) {
      const raw = readFileSync(file, 'utf8');
      const ids = new Set<string>();
      for (const m of raw.matchAll(/^#{1,6} (.+?)\s*$/gm)) {
        const custom = m[1].match(/\[#([a-z0-9-]+)\]$/);
        ids.add(custom ? custom[1] : anchor(m[1].replace(/`/g, '')));
      }
      for (const m of raw.matchAll(/\]\(#([a-z0-9-]+)\)/g)) {
        if (!ids.has(m[1])) dead.push(`${file.split('/content/docs/')[1]}#${m[1]}`);
      }
    }
    assert.deepEqual(dead, []);
  });
});

// GAP-0045: the managed env-var rules name every tighten_only variable of the
// registry, on the env-vars catalog and in the threat model's B17 row, and
// neither calls DEFENSECLAW_FAIL_MODE tighten_only (it is ignore, GAP-0516).
describe('managed env-var rules match the registry (GAP-0045)', () => {
  it('lists every tighten_only variable and keeps DEFENSECLAW_FAIL_MODE ignore', () => {
    const reg = JSON.parse(readFileSync(join(repo, 'internal/envvars/registry.json'), 'utf8'));
    const entries: { name: string; managed?: string }[] = [];
    const walk = (v: unknown): void => {
      if (Array.isArray(v)) v.forEach(walk);
      else if (v && typeof v === 'object') {
        const o = v as Record<string, unknown>;
        if (typeof o.name === 'string' && typeof o.managed === 'string') entries.push({ name: o.name, managed: o.managed });
        else Object.values(o).forEach(walk);
      }
    };
    walk(reg);
    const tighten = entries.filter((e) => e.managed === 'tighten_only').map((e) => e.name).sort();
    assert.ok(tighten.length >= 3, `parsed ${tighten}`);
    assert.equal(entries.find((e) => e.name === 'DEFENSECLAW_FAIL_MODE')?.managed, 'ignore');
    const catalog = page('reference/env-vars.mdx');
    const tightenRow = catalog.split('| `tighten_only` |')[1].split('\n')[0];
    const ignoreRow = catalog.split('| `ignore` |')[1].split('\n')[0];
    const b17 = readFileSync(join(repo, 'docs/ENTERPRISE-THREAT-MODEL.md'), 'utf8').split('| B17 |')[1].split('\n')[0];
    for (const name of tighten) {
      assert.ok(tightenRow.includes('`' + name + '`'), `env-vars tighten_only row omits ${name}`);
      assert.ok(b17.includes('`' + name + '`'), `threat model B17 omits ${name}`);
    }
    // The ignore row's except-list names the tighten_only security opt-outs.
    for (const name of tighten.filter((n) => n !== 'DEFENSECLAW_HOOK_MAX_BODY')) {
      assert.ok(ignoreRow.includes('`' + name + '`'), `env-vars ignore row except-list omits ${name}`);
    }
    assert.ok(!/`DEFENSECLAW_FAIL_MODE` remains `tighten_only`/.test(b17), 'B17 still calls DEFENSECLAW_FAIL_MODE tighten_only');
    // The ignore row names DEFENSECLAW_FAIL_MODE as ignored, before the
    // tighten_only exception, so it never reads as one of the tighten_only pair.
    const failAt = ignoreRow.indexOf('`DEFENSECLAW_FAIL_MODE`');
    const tightAt = ignoreRow.indexOf('`tighten_only`');
    assert.ok(failAt >= 0, 'env-vars ignore row does not name DEFENSECLAW_FAIL_MODE');
    assert.ok(tightAt < 0 || failAt < tightAt, 'env-vars ignore row names DEFENSECLAW_FAIL_MODE after tighten_only');
  });
});

// GAP-2300: the config.generation.json row names every field the writer can
// put in the file (cfgtxn GenerationState JSON tags).
describe('config.generation.json fields match the writer (GAP-2300)', () => {
  it('lists every GenerationState JSON field on enterprise/configuration.mdx', () => {
    const src = readFileSync(join(repo, 'internal/config/internal/cfgtxn/cfgtxn.go'), 'utf8');
    const body = src.split('type GenerationState struct {')[1].split('\n}')[0];
    const fields = [...body.matchAll(/json:"([a-z0-9_]+)/g)].map((m) => m[1]);
    assert.ok(fields.includes('generation_reset') && fields.length >= 10, `parsed ${fields}`);
    const row = page('enterprise/configuration.mdx').split('| `config.generation.json` |')[1].split('| `config.yaml.lock` |')[0];
    const missing = fields.filter((f) => !f.startsWith('transaction_') && !row.includes('`' + f + '`'));
    assert.deepEqual(missing, []);
    if (fields.some((f) => f.startsWith('transaction_'))) assert.ok(row.includes('`transaction_*`'), 'transaction_* fields not named');
  });
});

// GAP-2345 / GAP-2223 / GAP-2361: the code behind the first-run prompt list,
// the per-user Codex .env sentence and the managed /health socket paths.
describe('first-run prompts, Codex .env block scope and managed hook sockets match the code (GAP-2345, GAP-2223, GAP-2361)', () => {
  it('asks the five first-run prompts the page lists, in that order', () => {
    const init = source('cli/defenseclaw/commands/cmd_init.py');
    const wizard = init.split('ux.section("DefenseClaw First-Run Setup")')[1]?.split('\ndef ')[0] ?? '';
    const order = ['_prompt_connector_selection(', '"  " + ux.bold("Scanner mode")', '_prompt_action_connectors(', 'if action_set:\n        shared_fail, shared_human, shared_sev = _prompt_action_policy(', 'judge_hook_connectors = _prompt_first_run_judge_connectors(', '"  " + ux.bold("Start gateway after setup?")', '"  " + ux.bold("Run targeted readiness checks?")'];
    let at = -1;
    for (const needle of order) {
      const next = wizard.indexOf(needle, at + 1);
      assert.ok(next > at, `first-run prompt moved or renamed: ${needle}: re-check get-started/first-run.mdx Path A`);
      at = next;
    }
    for (const title of ['title = "Select active connector(s). Detected connectors are pre-selected."', 'title="Select connector(s) for action enforcement."', '"  " + ux.bold("Require human approval for risky actions?")', 'title="Select action connector(s) for LLM judge."']) {
      assert.ok(init.includes(title), `first-run prompt renamed: ${title}: re-check get-started/first-run.mdx Path A`);
    }
  });
  it('writes the Codex .env block only on a managed install', () => {
    const codex = source('internal/gateway/connector/codex.go');
    assert.match(codex, /if opts\.ManagedEnterprise \{\n(?:\t+\/\/[^\n]*\n)*\t+if err := ensureCodexDotEnvProxyBypass\(opts\)/, 'Codex .env block no longer managed-only: re-check connectors/codex.mdx');
  });
  it('names the managed hook socket paths', () => {
    const layout = source('internal/managed/standalone_layout.go');
    assert.ok(layout.includes('HookSocketPath:  "/run/defenseclaw-hook/hook.sock"') && layout.includes('HookSocketPath:  root + "/run/hook.sock"'), 'hook socket path changed: re-check enterprise/operations.mdx');
  });
});

// GAP-0010 / GAP-1536: managed ACP is enrolled, never called unsupported, and
// no page pins a byte or line count of an MDM kit script (it goes stale).
describe('managed ACP wording and MDM kit size claims (GAP-0010, GAP-1536)', () => {
  it('ships the managed ACP enroll and setup commands the pages name', () => {
    const acp = source('internal/cli/enterprise_acp.go');
    assert.ok(acp.includes('Use:   "enroll",') && acp.includes('enterpriseCmd.AddCommand(enterpriseACPCmd)'), 'enterprise acp enroll is gone: re-check connectors/kiro.mdx and support-matrix.mdx');
  });
  it('no page says ACP editors are unsupported in managed mode or gives an MDM script size', () => {
    const files = execFileSync('git', ['ls-files', 'docs-site/content/docs'], { cwd: repo, encoding: 'utf8' }).split('\n').filter((f) => f.endsWith('.mdx'));
    const bad: string[] = [];
    for (const f of files) {
      const text = readFileSync(join(repo, f), 'utf8').split(/\s+/).join(' ');
      if (/ACP editors are not supported in (enterprise )?managed mode/.test(text)) bad.push(`${f}: managed ACP unsupported`);
      if (/(wrapper|script) is about [0-9,.]+ ?KB/.test(text)) bad.push(`${f}: fixed script size`);
    }
    assert.deepEqual(bad, []);
  });
});

// GAP-2331: the edge-connector allowlist takes IPv6 literals without brackets;
// policy_compiler.py refuses a bracketed entry, so no page or README may ask for one.
describe('edge-connector IPv6 allowlist entries are written without brackets (GAP-2331)', () => {
  it('compiler refuses brackets and no page or README asks for them', () => {
    assert.ok(source('edge-connector/tools/policy_compiler.py').includes("write the IPv6 literal without brackets"), 'policy compiler no longer refuses a bracketed IPv6 entry: re-check edge-connector pages');
    const bad = ['docs-site/content/docs/edge-connector/architecture.mdx', 'docs-site/content/docs/edge-connector/policies.mdx', 'edge-connector/README.md', 'edge-connector/INSTALL.md']
      .filter((f) => /bracketed globally scoped IPv6/.test(source(f).split(/\s+/).join(' ')));
    assert.deepEqual(bad, []);
  });
});

// GAP-2190: a table row placed after a paragraph renders as stray text, not a
// row of the table above it. No page may start a table line right after prose.
describe('no table row is detached from its table (GAP-2190)', () => {
  it('every table line follows a blank line, another table line or an MDX comment', () => {
    const files = execFileSync('git', ['ls-files', 'docs-site/content/docs'], { cwd: repo, encoding: 'utf8' }).split('\n').filter((f) => f.endsWith('.mdx'));
    const bad: string[] = [];
    for (const f of files) {
      const lines = readFileSync(join(repo, f), 'utf8').split('\n');
      let fence = false;
      lines.forEach((line, i) => {
        if (line.trimStart().startsWith('```')) fence = !fence;
        if (fence || i === 0 || !line.trimStart().startsWith('|')) return;
        const prev = lines[i - 1].trim();
        if (prev && !prev.startsWith('|') && !/^\{\/\*.*\*\/\}$/.test(prev)) bad.push(`${f}:${i + 1}`);
      });
    }
    assert.deepEqual(bad, []);
  });
});

// GH #1100 (p0 GAP-0675): the pages say a disconnected session keeps its registrations because the uninstall warning says so.
describe('Windows uninstall session wording matches the pages (GH #1100)', () => {
  it('the no-active-session reason still names a disconnected session', () => {
    const messages = source('internal/cli/windows_enterprise_messages.go');
    assert.ok(messages.includes('"had no active (connected) session (signed out, or signed in with a disconnected session)"'), 'windowsEnterpriseNoActiveSession changed: re-check enterprise/windows.mdx Remove, lifecycle.mdx Uninstall notes and threat-model.mdx');
  });
});
