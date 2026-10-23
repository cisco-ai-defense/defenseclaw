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
  it('names the exact gateway-backed guarded outage and Windows Amp routes', () => {
    const outage = page('enterprise/configure/foreign-hook-guard.mdx').split('## Gateway outages')[1]?.split('## Approve a hook')[0] ?? '';
    assert.match(outage, /foreign_hooks: remove.*default.*gateway-backed.*stopped.*restarting.*no answer.*administrator.*open/i);
    assert.match(outage, /Windows Amp.*local.*plugin.*report.*allow/i);
    assert.doesNotMatch(outage, /(?:earlier|fresh|trusted|published) (?:session )?record.{0,100}(?:allow|run)/i);
  });

  it('states the guarded outage limit without a record-based escape', () => {
    const text = page('enterprise/configure/foreign-hook-guard.mdx');
    assert.match(text, /guarded tool calls are blocked whatever the fail mode, `open` included/i);
    assert.doesNotMatch(text, /(?:earlier|fresh|trusted|published) (?:session )?record.{0,100}(?:allow|run)/i);
  });

  it('keeps the managed guarded outage limit across operator and threat-model pages', () => {
    const outagePages: [string, RegExp][] = [
      ['appendix/coverage-by-layer.mdx', /foreign_hooks: remove.{0,120}guarded calls block during an outage/i],
      ['reference/configuration/fail-modes.mdx', /foreign_hooks: remove.{0,50}this blocks during an outage under `open`/i],
      ['reference/connectors/devin.mdx', /foreign_hooks: remove.{0,130}guarded tool calls block during an outage.{0,50}`open`/i],
      ['enterprise/configure/foreign-hook-guard.mdx', /foreign_hooks: remove.{0,250}guarded tool calls are blocked whatever the fail mode, `open` included/i],
      ['enterprise/configure/reference.mdx', /foreign_hooks: remove.{0,60}guarded calls block during an outage even under `open`/i],
      ['enterprise/operate/reference.mdx', /foreign_hooks: remove.{0,60}guarded calls block during an outage even under `open`/i],
      ['enterprise/operate/lifecycle.mdx', /foreign_hooks: remove.{0,60}guarded calls block during an outage even under `open`/i],
      ['enterprise/plan/threat-model.mdx', /foreign_hooks: remove.{0,60}guarded calls block during an outage.{0,50}`open`/i],
      ['troubleshooting/enterprise/index.mdx', /foreign_hooks: remove.{0,70}guarded calls also block under `open`.{0,70}guards cannot check the session/i],
    ];
    for (const [name, claim] of outagePages) {
      assert.match(page(name), claim, name);
      assert.doesNotMatch(`foreign_hooks: remove ${'unrelated '.repeat(80)} guarded calls block during an outage under \`open\``, claim, name);
    }
    assert.match(repoText('docs/ENTERPRISE-THREAT-MODEL.md'), /R31.*foreign_hooks: remove.*blocks outages/i);
    const changelog = repoText('CHANGELOG.md');
    assert.match(changelog, /Known limits.*foreign_hooks: remove.*guarded connectors.*block tool calls during a gateway outage.*hook_fail_mode: open/i);
    assert.match(page('appendix/coverage-by-layer.mdx'), /On a per-user install or under Secure Client.*Connector limits and failure reporting vary.*Managed standalone behavior is in the next row/i);
    const all = docsText();
    assert.doesNotMatch(all, /(?:fresh|trusted|protected) (?:process and session |session |hook )?records?.{0,100}(?:allow|run).{0,70}(?:outage|gateway.*down)/i);
    assert.doesNotMatch(all, /(?:outage|gateway.*down).{0,100}(?:fresh|trusted|protected) (?:process and session |session |hook )?records?.{0,100}(?:allow|run)/i);
    assert.doesNotMatch(all, /(?:lifts?|lifted) the 1\.0\.3 (?:outage )?limit/i);
    // An unconditional statement about every connector would hide the
    // administrator's outage-only open for connectors without this guard.
    for (const pattern of blanketOutageClaims) assert.doesNotMatch(all, pattern);
    assert.ok(blanketOutageClaims.some((pattern) => pattern.test('Every call checked while the gateway is down is blocked')));
  });

  it('documents the Hermes guard limit in each outage explanation', () => {
    const hermes = page('reference/connectors/hermes.mdx');
    const enterprise = hermes.split('### Enterprise standalone profile')[1]?.split('### OpenShell sandbox')[0] ?? '';
    const failMode = hermes.split('## Fail mode')[1]?.split('## Limits')[0] ?? '';
    const row = hermes.match(/\| Hook fail mode \|[^|]*\|/)?.[0] ?? '';
    const managedRow = hermes.match(/\| Managed standalone \|[^|]*\|/)?.[0] ?? '';
    for (const [name, section] of [['enterprise', enterprise], ['verdict row', row], ['fail mode', failMode]] as const) {
      assert.match(section, /foreign_hooks: remove.{0,260}guard.{0,200}outage.{0,140}block.{0,100}open/i, name);
    }
    assert.match(managedRow, /outage-only `open`.*unguarded call run.*foreign_hooks: remove.*guarded outage calls block under `open`/i);
    assert.doesNotMatch(row, /Only an explicit `open` lets it run/i);
    assert.match(enterprise, /Linux and macOS.*foreign_hooks: remove.*pre_tool_call.*blocked.*administrator.*open/i);
    assert.match(enterprise, /foreign_hooks: report.*allow.*no session exchange.*classified outage.*open/i);
    assert.match(enterprise, /Windows Hermes.*does not run.*foreign-hook guard/i);
  });

  for (const name of ['copilot', 'cursor', 'devin', 'opencode', 'amp', 'claudecode', 'codex']) {
    it(`keeps the managed ${name} fail-mode boundary in its connector page`, () => {
      const failMode = page(`reference/connectors/${name}.mdx`).split('## Fail mode')[1]?.split('## ')[0] ?? '';
      assert.match(failMode, /managed standalone.*foreign_hooks: remove.*guarded tool calls.*gateway outage.*administrator.*open/i);
      assert.match(failMode, /administrator.*open.*classified gateway outage|classified gateway outage.*administrator.*open/i);
      assert.doesNotMatch(failMode, /When the gateway cannot give a usable answer, the hook blocks the events that support a block response unless/i);
      if (name === 'amp') {
        assert.match(failMode, /Windows Amp.*plugin.*blocks.*outage.*every fail mode/i);
        assert.doesNotMatch(page('reference/connectors/amp.mdx'), /Gateway errors honor the configured open or closed hook failure mode/i);
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

  it('keeps one supervisor upgrade entry with manual stop and guarded restart', () => {
    const changelog = repoText('CHANGELOG.md');
    assert.equal((changelog.match(/\*\*Sandboxes run only on OpenShell 0\.1\.5 or later\.\*\*/g) ?? []).length, 1);
    assert.match(changelog, /DefenseClaw never stops such a sandbox on its own.*Your own `sandbox stop` ends it/);
    assert.doesNotMatch(changelog, /DefenseClaw stops it as soon as it sees it|A stop that fails is a second finding/);
    const guide = page('troubleshooting/sandboxes/setup-and-gateway.mdx');
    assert.match(guide, /DefenseClaw closes its egress proxy and withdraws the network rules it added.*does not contain the old broker/i);
    assert.match(guide, /Save its work, then run `defenseclaw sandbox stop <name>` yourself.*reconciliation never retries the stop for you/i);
    assert.match(guide, /`defenseclaw sandbox exec` and `connect` run nothing in it/i);
    assert.doesNotMatch(guide, /DefenseClaw stops it as soon as it sees it|`connect` stops it and starts it again/i);
  });

  it('explains the live legacy guest without promising an automatic stop or containment', () => {
    const guide = page('troubleshooting/sandboxes/setup-and-gateway.mdx');
    const legacy = guide.split('### A live legacy guest after upgrade')[1]?.split('## ')[0] ?? '';
    assert.match(legacy, /Docker.*0\.1\.3.*keep.*supervisor.*upgrade/i);
    assert.match(legacy, /unversioned.*1\.0\.3.*legacy/i);
    assert.match(legacy, /MicroVM.*refuses.*gateway upgrade.*live/i);
    assert.match(legacy, /never stops.*unprotected.*network broker.*not contained/i);
    assert.match(legacy, /withdrawal fails.*retry.*withdrawal.*never.*stop/i);
    assert.match(legacy, /ready.*sandbox stop.*MicroVM.*sync.*after the sync.*lost/i);
    assert.match(legacy, /ended MicroVM.*sandbox delete.*0\.1\.5.*--end-vm/i);
    assert.match(legacy, /restores.*create-time network policy.*old session approvals/i);
    assert.match(legacy, /restor(?:e|ation) fails.*attempts to stop.*new session.*refuses the run/i);
    assert.doesNotMatch(legacy, /automatically stops|reconciliation retries (?:a|the) stop/i);
  });

  it('refuses an earlier daemon package upgrade before a live sandbox is changed', () => {
    const troubleshooting = page('troubleshooting/sandboxes/setup-and-gateway.mdx');
    const enterprise = page('enterprise/runtime/sandboxes.mdx');
    for (const text of [troubleshooting, enterprise]) {
      assert.match(text, /1\.0\.3 or older.*rpm.*deb.*macOS pkg.*refuses before.*changes/i);
      assert.match(text, /running.*starting.*stopping.*completed.*error state.*does not answer/i);
      assert.match(text, /sandbox stop.*sandbox delete.*install.*again/i);
      assert.match(text, /last-package-result\.json.*sandboxes_running/i);
    }
  });

  it('keeps an unsynced MicroVM live until its user accepts the loss', () => {
    const troubleshooting = page('troubleshooting/sandboxes/setup-and-gateway.mdx');
    const cli = page('reference/sandboxes/cli.mdx');
    assert.match(troubleshooting, /sync fails.*keeps running.*--discard-unsynced.*--yes.*does not/i);
    assert.match(cli, /sync fails.*keeps running.*--yes.*does not.*--discard-unsynced.*never stops a MicroVM/i);
    assert.match(cli, /\| `--discard-unsynced` \| switch \|.*Stop a MicroVM whose disk could not be synced first/i);
  });

  it('uses the current legacy-unprotected status and managed verify row', () => {
    const troubleshooting = page('troubleshooting/sandboxes/setup-and-gateway.mdx');
    const enterprise = page('enterprise/runtime/sandboxes.mdx');
    const changelog = repoText('CHANGELOG.md');
    assert.match(troubleshooting, /running unprotected: legacy sandbox.*Unprotected.*row/i);
    assert.match(enterprise, /sandbox_legacy_unprotected.*security_complete.*false.*verify.*fails/i);
    assert.match(changelog, /running unprotected: legacy sandbox.*sandbox status.*sandbox doctor.*managed.*status.*verify/i);
    assert.doesNotMatch(troubleshooting, /legacy sandbox running, not protected by the 1\.0\.4 egress policy/i);
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
