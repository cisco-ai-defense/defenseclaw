import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

// Docs claims that must match what the product does. Each check reads the
// page as one line of words, so a reflowed paragraph still matches.

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(site, '..');

function page(name: string): string {
  return readFileSync(join(site, 'content/docs', name), 'utf8').split(/\s+/).join(' ');
}

function repoText(name: string): string {
  return readFileSync(join(repo, name), 'utf8').split(/\s+/).join(' ');
}

function docsText(): string {
  const walk = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return walk(path);
    return /\.(?:md|mdx)$/.test(entry.name) ? [readFileSync(path, 'utf8')] : [];
  });
  return [...walk(join(repo, 'docs')), ...walk(join(site, 'content/docs')), repoText('CHANGELOG.md')]
    .join(' ').split(/\s+/).join(' ');
}

const blanketOutageClaims = [
  /(?:gateway )?outages? always block (?:all|every) (?:managed )?(?:hook|connector|call)/i,
  /Every call checked while the gateway is down is blocked/i,
];

describe('1.0.4 managed outage and upgrade claims', () => {
  it('documents the protected-record exception that the guarded outage path still uses', () => {
    const guard = repoText('internal/cli/hook_foreign_guard.go');
    assert.match(guard, /func protectedForeignHookSession\(/);
    assert.match(guard, /if protected, ok := protectedForeignHookSession\(/);
    const outage = page('enterprise/configure/foreign-hook-guard.mdx').split('## Gateway outages')[1]?.split('## Approve a hook')[0] ?? '';
    assert.match(outage, /administrator.*open.*fresh.*trusted.*process and session records.*block/i);
    assert.match(outage, /Missing.*blocked.*stale.*untrusted.*block/i);
    assert.doesNotMatch(outage, /guarded tool calls are blocked whatever the fail mode/i);
  });

  it('documents automatic legacy-supervisor stops and retry after a failed stop', () => {
    const manager = repoText('internal/openshell/manager/box.go');
    assert.match(manager, /scheduleOldSupervisorStop\(b\)/);
    assert.match(repoText('internal/openshell/manager/reconcile.go'), /retryOldSupervisorStop\(b\)/);
    const guide = page('troubleshooting/sandboxes/setup-and-gateway.mdx');
    assert.match(guide, /automatic stop.*old.*supervisor.*Reconciliation retries a failed stop/i);
    assert.doesNotMatch(guide, /DefenseClaw never stops these guests itself/i);
    assert.match(repoText('CHANGELOG.md'), /old supervisor.*automatically stops.*failed stop.*retries/i);
  });

  it('describes the stop after a failed MicroVM sync without an unavailable flag', () => {
    const flush = repoText('internal/openshell/manager/graceful.go');
    const lifecycle = repoText('internal/openshell/manager/lifecycle.go');
    const command = repoText('internal/cli/sandbox.go');
    assert.match(flush, /func \(m \*Manager\) flushSandbox\([^)]*\) \{/);
    assert.match(lifecycle, /m\.endHarness\(ctx, gw, b\).*StopSandbox\(ctx, name\)/);
    assert.match(command, /newSandboxStopCmd.*BoolVarP\(&o\.Yes, "yes"/);
    assert.doesNotMatch(command, /discard-unsynced/);
    for (const name of ['reference/sandboxes/cli.mdx', 'troubleshooting/sandboxes/setup-and-gateway.mdx']) {
      const text = page(name);
      assert.match(text, /sync fails.*stop_unflushed.*stop.*(?:may|can).*(?:empty|lost)/i, name);
      assert.match(text, /no separate failed-sync confirmation or loss-acceptance flag/i, name);
      assert.doesNotMatch(text, /--discard-unsynced/i, name);
      assert.doesNotMatch(text, /sync fails.{0,100}keeps running/i, name);
      assert.doesNotMatch(text, /stop still proceeds with the stop/i, name);
    }
  });

  it('gives package-upgrade precautions without promising a sandbox preflight', () => {
    const linux = repoText('packaging/linux/preinstall.sh');
    const macos = repoText('scripts/build-macos-enterprise-pkg.sh');
    const macosPreinstall = macos.split('cat >"$SCRIPTS/preinstall" <<\'EOF\'')[1]?.split(' EOF ')[0] ?? '';
    assert.ok(macosPreinstall, 'macOS pkg preinstall heredoc is present');
    assert.doesNotMatch(linux, /sandbox/i);
    assert.doesNotMatch(macosPreinstall, /sandbox/i);
    const sections = [
      page('troubleshooting/sandboxes/setup-and-gateway.mdx').split('### Before a 1.0.4 package upgrade')[1]?.split('### ')[0] ?? '',
      page('enterprise/runtime/sandboxes.mdx').split('### Upgrade from an earlier sandbox daemon')[1]?.split('### ')[0] ?? '',
      repoText('CHANGELOG.md').split('### Known limits')[1]?.split('### Changed')[0] ?? '',
    ];
    for (const [index, section] of sections.entries()) {
      assert.match(section, /rpm and deb packages and macOS pkg do not check sandbox state before replacing files/i, `package section ${index}`);
      assert.match(section, /save or pull.*work.*stop.*sandbox/i, `package section ${index}`);
      assert.doesNotMatch(section, /sandboxes_running|package.*refuses before replacing files.*sandbox/i, `package section ${index}`);
      if (index < 2) {
        assert.match(section, /completed MicroVM or an error-state MicroVM whose VM is still running/i, `package section ${index}`);
        assert.match(section, /error-state MicroVM whose VM has exited does not need a stop for a later gateway restart/i, `package section ${index}`);
      }
    }
  });

  it('keeps the gateway restart boundary for a MicroVM whose VM has exited', () => {
    const restartGate = repoText('internal/openshell/restartgate.go');
    assert.match(restartGate, /case PhaseError: return !stopFlushes && !VMGone\(said\)/);
    const manager = repoText('internal/openshell/manager/box.go');
    assert.match(manager, /case audit\.SandboxPhaseError: return openshell\.HoldsGateway\(openshell\.PhaseError, reason, !stopLosesWrites\(driver\)\)/);
    const troubleshooting = page('troubleshooting/sandboxes/setup-and-gateway.mdx')
      .split('The upgrade restarts the gateway')[1]?.split('### Before a 1.0.4 package upgrade')[0] ?? '';
    assert.match(troubleshooting, /completed MicroVM.*error-state MicroVM whose VM is still running/i);
    assert.match(troubleshooting, /error-state MicroVM whose VM has exited.*(?:exempt|does not block)/i);
    for (const name of ['enterprise/runtime/sandboxes.mdx', 'enterprise/runtime/sandbox-reference.mdx']) {
      const modeSwitch = page(name).split('In both modes `ensure`')[1]?.split('### ')[0] ?? '';
      assert.match(modeSwitch, /completed MicroVM or an error-state MicroVM whose VM is still running/i, name);
      assert.match(modeSwitch, /error-state MicroVM whose VM has exited.*(?:exempt|does not block)/i, name);
    }
    const changelog = repoText('CHANGELOG.md').split('**Sandboxes run only on OpenShell 0.1.5 or later.**')[1]?.split(' - **')[0] ?? '';
    assert.match(changelog, /gone \(its VM process exited\).*completed MicroVM.*other error state.*VM keeps running/i);
  });
  it('names the exact gateway-backed guarded outage and Windows Amp routes', () => {
    const outage = page('enterprise/configure/foreign-hook-guard.mdx').split('## Gateway outages')[1]?.split('## Approve a hook')[0] ?? '';
    assert.match(outage, /foreign_hooks: remove.*default.*classified gateway outage.*administrator.*open.*fresh, trusted process and session records.*Missing, blocked, stale or untrusted records block/i);
    assert.match(outage, /at most 15 minutes old.*still revocable/i);
    assert.match(outage, /Windows Amp.*local.*plugin.*report.*allow/i);
  });

  it('states the guarded outage record boundary without a blanket block', () => {
    const text = page('enterprise/configure/foreign-hook-guard.mdx');
    assert.match(text, /earlier online allow alone does not guarantee.*next call runs/i);
    assert.match(text, /fresh, trusted process and session records.*show no block/i);
    assert.doesNotMatch(text, /guarded tool calls are blocked whatever the fail mode/i);
  });

  it('keeps the managed guarded outage limit across operator and threat-model pages', () => {
    const names = [
      'appendix/coverage-by-layer.mdx', 'reference/configuration/fail-modes.mdx',
      'reference/connectors/devin.mdx', 'enterprise/configure/foreign-hook-guard.mdx',
      'enterprise/configure/reference.mdx', 'enterprise/operate/reference.mdx',
      'enterprise/operate/lifecycle.mdx', 'enterprise/plan/threat-model.mdx',
      'troubleshooting/enterprise/index.mdx',
    ];
    for (const name of names) {
      assert.match(page(name), /foreign_hooks: remove.*fresh, trusted process and session records/i, name);
    }
    assert.match(repoText('docs/ENTERPRISE-THREAT-MODEL.md'), /R31.*foreign_hooks: remove.*fresh, trusted process and session records/i);
    assert.match(repoText('CHANGELOG.md'), /foreign_hooks: remove.*fresh, trusted process and session records/i);
    assert.match(page('appendix/coverage-by-layer.mdx'), /On a per-user install or under Secure Client.*Connector limits and failure reporting vary.*Managed standalone behavior is in the next row/i);
    const all = docsText();
    for (const pattern of blanketOutageClaims) assert.doesNotMatch(all, pattern);
    assert.ok(blanketOutageClaims.some((pattern) => pattern.test('Every call checked while the gateway is down is blocked')));
  });

  it('documents the Hermes guard limit in each outage explanation', () => {
    const hermes = page('reference/connectors/hermes.mdx');
    const enterprise = hermes.split('### Enterprise standalone profile')[1]?.split('### OpenShell sandbox')[0] ?? '';
    const failMode = hermes.split('## Fail mode')[1]?.split('## Limits')[0] ?? '';
    const row = hermes.match(/\| Hook fail mode \|[^|]*\|/)?.[0] ?? '';
    const managedRow = hermes.match(/\| Managed standalone \|[^|]*\|/)?.[0] ?? '';
    for (const [name, section] of [['enterprise', enterprise], ['verdict row', row], ['managed row', managedRow], ['fail mode', failMode]] as const) {
      assert.match(section, /foreign_hooks: remove.*fresh, trusted process and session records.*otherwise it blocks/i, name);
    }
    assert.match(enterprise, /foreign_hooks: report.*allow.*no session exchange.*classified outage.*open/i);
    assert.match(enterprise, /Windows Hermes.*does not run.*foreign-hook guard/i);
  });

  for (const name of ['copilot', 'cursor', 'devin', 'opencode', 'amp', 'claudecode', 'codex']) {
    it(`keeps the managed ${name} fail-mode boundary in its connector page`, () => {
      const failMode = page(`reference/connectors/${name}.mdx`).split('## Fail mode')[1]?.split('## ')[0] ?? '';
      assert.match(failMode, /managed standalone.*classified gateway outage.*foreign_hooks: remove.*fresh, trusted process and session records.*otherwise it blocks/i);
      assert.doesNotMatch(failMode, /guarded tool calls block during a gateway outage under administrator `open`/i);
      if (name === 'amp') {
        assert.match(failMode, /Windows Amp.*plugin.*blocks.*outage.*every fail mode/i);
      }
      if (name === 'claudecode' || name === 'codex') {
        assert.match(failMode, /managed_hooks_only: preserve.*foreign_hooks: remove/i);
      }
    });
  }

  for (const name of ['antigravity', 'kiro']) {
    it(`limits managed ${name} open to classified outages`, () => {
      const failMode = page(`reference/connectors/${name}.mdx`).split('## Fail mode')[1]?.split('## ')[0] ?? '';
      assert.match(failMode, /managed standalone.*administrator.*open.*classified gateway outage/i);
      assert.match(failMode, /(?:authentication|unusable answer).*block.*every fail mode/i);
      assert.doesNotMatch(failMode, /When the gateway cannot give a usable answer, the hook blocks the events that support a block response unless/i);
    });
  }

  it('distinguishes the Windows Amp local guard record from gateway-backed sessions', () => {
    const guard = page('enterprise/configure/foreign-hook-guard.mdx');
    assert.match(guard, /Windows Amp keeps its guard record locally.*managed plugin blocks gateway outages in every fail mode.*report.*allow/i);
    assert.match(page('enterprise/configure/reference.mdx'), /Amp \(`amp`\).*gateway-backed foreign-hook guard.*local foreign-hook session record.*plugin itself blocks gateway outages/i);
    assert.match(repoText('CHANGELOG.md'), /Windows Amp keeps its guard record locally.*managed plugin blocks outages independently/i);
    const risk = repoText('docs/ENTERPRISE-THREAT-MODEL.md').split('| R13 |')[1]?.split('| R14 |')[0] ?? '';
    assert.match(risk, /Windows Amp keeps its guard record locally.*managed plugin blocks gateway outages/i);
    assert.doesNotMatch(docsText(), /guard checks each covered connector's session with the gateway/i);
    assert.doesNotMatch(guard, /Calls of other unguarded connectors follow their effective fail mode/i);
  });

  it('describes bounded Windows WAL catch-up and the remaining hook delay', () => {
    const enterprise = page('troubleshooting/enterprise/index.mdx');
    assert.match(enterprise, /Windows.*audit\.db-wal.*bounded catch-up/i);
    assert.match(enterprise, /bounded catch-up.*256 MiB/i);
    assert.match(enterprise, /0\.9.to.1\.2 GB.*10 calls a second/i);
    assert.match(enterprise, /hook answers.*(?:slow|wait|delay).*default.*closed/i);
    assert.doesNotMatch(enterprise, /audit\.db-wal.*20 GB|fix needs a change to how the audit store indexes hook records and is deferred/i);
  });

  it('keeps one supervisor upgrade entry with automatic stop and failed-stop retry', () => {
    const changelog = repoText('CHANGELOG.md');
    assert.equal((changelog.match(/\*\*Sandboxes run only on OpenShell 0\.1\.5 or later\.\*\*/g) ?? []).length, 1);
    assert.match(changelog, /old supervisor.*automatically stops.*stop fails.*reconciliation retries/i);
    assert.doesNotMatch(changelog, /DefenseClaw never stops such a sandbox on its own|package's earlier-daemon preflight/i);
    const guide = page('troubleshooting/sandboxes/setup-and-gateway.mdx');
    assert.match(guide, /automatic stop.*Reconciliation retries a failed stop/i);
    assert.match(guide, /sandbox exec.*runs nothing.*connect.*attempts to stop/i);
  });

  it('explains the automatic stop and remaining risk for a live legacy guest', () => {
    const guide = page('troubleshooting/sandboxes/setup-and-gateway.mdx');
    const legacy = guide.split('### A live legacy guest after upgrade')[1]?.split('## ')[0] ?? '';
    assert.match(legacy, /Docker.*0\.1\.3.*old supervisor.*unversioned.*1\.0\.3/i);
    assert.match(legacy, /old network broker.*bypass.*automatic stop.*old_supervisor/i);
    assert.match(legacy, /stop fails.*remain live.*reconciliation retries a failed stop/i);
    assert.match(legacy, /save or pull.*before an upgrade.*automatic stop can interrupt/i);
    assert.doesNotMatch(legacy, /never stops.*guest|reconciliation never retries/i);
  });

  it('gives precautions because package preinstall does not inspect live sandboxes', () => {
    const troubleshooting = page('troubleshooting/sandboxes/setup-and-gateway.mdx');
    const enterprise = page('enterprise/runtime/sandboxes.mdx');
    const changelog = repoText('CHANGELOG.md');
    for (const text of [troubleshooting, enterprise, changelog]) {
      assert.match(text, /rpm and deb packages and macOS pkg do not check sandbox state before replacing files/i);
      assert.match(text, /save or pull.*work.*stop.*sandbox/i);
      assert.doesNotMatch(text, /sandboxes_running|package.*refuses before replacing files.*sandbox/i);
    }
  });

  it('warns that a failed MicroVM sync still leads to a stop', () => {
    for (const text of [page('reference/sandboxes/cli.mdx'), page('troubleshooting/sandboxes/setup-and-gateway.mdx'), repoText('CHANGELOG.md')]) {
      assert.match(text, /sync fails?.*stop_unflushed.*still proceeds.*writes.*(?:empty|lost)/i);
      assert.match(text, /no separate failed-sync confirmation or loss-acceptance flag/i);
      assert.doesNotMatch(text, /--discard-unsynced/i);
      assert.doesNotMatch(text, /sync fails.{0,100}keeps running|only your explicit `--discard-unsynced` stops/i);
    }
  });

  it('uses the current old-supervisor finding without an invented verify row', () => {
    const troubleshooting = page('troubleshooting/sandboxes/setup-and-gateway.mdx');
    const enterprise = page('enterprise/runtime/sandboxes.mdx');
    const changelog = repoText('CHANGELOG.md');
    assert.match(troubleshooting, /HIGH `old_supervisor` finding.*sandbox status.*warns/i);
    assert.match(enterprise, /activity feed reports `old_supervisor`.*failed stop.*retried/i);
    assert.match(changelog, /HIGH `old_supervisor` finding.*stop fails.*reconciliation retries/i);
    for (const text of [troubleshooting, enterprise, changelog]) {
      assert.doesNotMatch(text, /sandbox_legacy_unprotected|running unprotected: legacy sandbox|Legacy sandboxes.*row/i);
    }
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
      assert.match(text, /On a per-user install.*denies supported calls.*mode `closed` \(the default outside Secure Client\)/i, name);
    }
    for (const name of ['reference/connectors/antigravity.mdx']) {
      const text = page(name);
      assert.ok(!text.includes('A gateway failure lets the call run'), name);
      assert.ok(!text.includes('normal fail-open operation'), name);
      assert.match(text, /On a per-user install, `closed` \(the default outside Secure Client\) denies `PreToolUse`/i, name);
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

describe('1.0.4 operator routes and limits', () => {
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
    const tuiGeneration = tui.split('### Config generation and policy digest')[1]?.split('### ')[0] ?? '';
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
    assert.match(tuiGeneration, /status strip.*authenticated.*`\/status`.*policy\.config_generation/i);
  });

  it('does not promise enrollment for an extension without an engine version', () => {
    const enrollment = page('enterprise/configure/enrollment.mdx');
    assert.match(enrollment, /extension.*engine version.*(?:no engine version|without an engine version).*surface_unverified.*not enrolled/i);
    assert.match(enrollment, /Codex.*Windows.*reported.*not enrolled/i);
    const risk = repoText('docs/ENTERPRISE-THREAT-MODEL.md').split('| R25 |')[1]?.split('| R26 |')[0] ?? '';
    assert.match(risk, /engine version.*surface_unverified.*not enrolled/i);
    assert.doesNotMatch(risk, /enrollment finds an agent only through its CLI install/i);
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

  it('uses the managed Windows administrator route instead of a config-only shell', () => {
    const hooks = page('reference/commands/cli.mdx').split('### Per-user hooks (`enterprise hooks`)')[1]?.split('### ACP')[0] ?? '';
    const envVars = page('reference/configuration/env-vars.mdx');
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
