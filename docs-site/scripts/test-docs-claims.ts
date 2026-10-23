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

describe('1.0.4 managed outage and upgrade claims', () => {
  it('keeps the managed guarded outage limit across operator and threat-model pages', () => {
    const outagePages = [
      'appendix/coverage-by-layer.mdx',
      'reference/configuration/fail-modes.mdx',
      'reference/connectors/devin.mdx',
      'enterprise/configure/foreign-hook-guard.mdx',
      'enterprise/configure/reference.mdx',
      'enterprise/operate/reference.mdx',
      'enterprise/operate/lifecycle.mdx',
      'enterprise/plan/threat-model.mdx',
      'troubleshooting/enterprise/index.mdx',
    ];
    for (const name of outagePages) {
      const guidance = page(name);
      assert.match(guidance, /foreign_hooks: remove/i, name);
      assert.match(guidance, /(?:guarded|guard|session).*(?:outage.*block|block.*outage)/i, name);
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
    assert.doesNotMatch(all, /(?:gateway )?outages? always block (?:all|every) (?:managed )?(?:hook|connector|call)/i);
  });

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

  it('identifies the TUI footer generation as the persisted config counter', () => {
    const tui = page('reference/commands/tui.mdx');
    assert.match(tui, /`gen`.*config\.generation\.json.*(?:survives|persists).*gateway restart/i);
    assert.doesNotMatch(tui, /`gen` is the gateway's policy generation|restarts at 1 when the gateway starts/i);
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
