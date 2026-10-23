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

function assertPartialBodyUsesDeliveryMode(hook: string): void {
  // Both hook versions route a truncated body through the effective delivery
  // mode. The newer path also checks a known error status on standalone hosts.
  const readFailure = hook.match(/if readErr != nil \{(?:\s|\/\/[^\n]*\n)*return (failNoAnswer\(opts, sp, failMode\)|failAfterErrorStatus\(opts, sp, failMode, knownStatus\))/);
  assert.ok(readFailure, 'truncated response follows the delivery failure path');
  if (readFailure[1].startsWith('failAfterErrorStatus')) {
    assert.match(hook, /func failAfterErrorStatus[\s\S]*?status == 0 \|\| !managedNativeDecision\(opts\) \{\s*return failNoAnswer\(opts, sp, failMode\)/);
  }
}

function docPages(dir = join(site, 'content/docs'), ext = /\.mdx$/): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? docPages(path, ext) : ext.test(entry.name) ? [path] : [];
  });
}

describe('managed ACP support', () => {
  it('keeps connector route notes consistent with managed enrollment', () => {
    for (const path of docPages()) {
      const text = readFileSync(path, 'utf8').split(/\s+/).join(' ');
      assert.doesNotMatch(text, /ACP editors are not supported in enterprise managed mode/i, path);
    }
    const kiro = page('reference/connectors/kiro.mdx');
    assert.ok(kiro.includes('/docs/features/acp-guard#managed-computers'));
    assert.match(kiro, /managed ACP.*preview/i);
    assert.match(page('get-started/support-matrix.mdx'), /enrollment.*preview/i);
  });
});

describe('managed outage documentation', () => {
  it('links every outage refusal to the capability matrix', () => {
    const text = readFileSync(join(site, 'content/docs/troubleshooting/enterprise/index.mdx'), 'utf8');
    for (const code of ['not_running', 'restarting', 'no_answer']) {
      const row = text.split('\n').find((line) => line.startsWith(`| \`enterprise_managed_gateway_${code}\` |`));
      assert.ok(row, code);
      assert.ok(row.includes('/docs/reference/apis/capability-matrix#gateway-outage'), code);
      assert.doesNotMatch(row, /it allows|allows this|never an allow|hook_fail_mode: open/, code);
    }
    assert.ok(page('appendix/coverage-by-layer.mdx').includes('/docs/reference/apis/capability-matrix#gateway-outage'));
  });

  it('scopes generic fail-mode guidance to delivery failures', () => {
    const guide = page('features/guardrail.mdx');
    const failMode = guide.split('## Fail mode')[1]?.split('## ')[0];
    assert.ok(failMode, 'guardrail fail-mode section');
    assert.match(failMode, /default is `closed`/);
    assert.match(failMode, /administrator's `open` applies only when the gateway is proven not running/i);
    assert.ok(failMode.includes('/docs/reference/apis/capability-matrix#gateway-outage'));
    assert.doesNotMatch(failMode, /authentication failure.*`open` allows/i);
    assert.doesNotMatch(guide, /Observe mode never blocks/i);

    const layers = page('appendix/coverage-by-layer.mdx');
    assert.match(layers, /A hook cannot reach the gateway \| The hook's fail mode decides, in observe and action mode alike/);
    assert.doesNotMatch(layers, /A hook cannot reach the gateway, in observe mode \| Open:/);
    assert.doesNotMatch(layers, /Managed Claude Code and Codex hooks \| Always closed/);
  });

  it('states the Hermes guard boundary on each managed OS', () => {
    const source = readFileSync(join(repo, 'internal/enterprisepolicy/publicpolicy.go'), 'utf8');
    assert.match(source, /ConnectorHermes: true/);
    const scope = source.split('func GuardApplies')[1]?.split('func BuildPublicPolicy')[0];
    assert.match(scope ?? '', /if unixGuardConnectors\[connector\] {\s*return goos != "windows"/);
    const matrix = page('reference/apis/capability-matrix.mdx');
    // The note ends at the next bullet; without it the rest of the page would match.
    const next = '- **A hook must run to deny';
    const guard = matrix.split('**The foreign-hook guard can still block.**')[1];
    assert.ok(guard?.includes(next), 'foreign-hook guard note and the bullet after it');
    const note = guard.split(next)[0];
    assert.match(note, /Hermes on Linux and macOS/);
    assert.match(note, /Windows.*Hermes.*administrator.*proven stopped gateway/i);
  });

  it('keeps an unverified gateway socket or peer closed in every fail mode', () => {
    for (const path of docPages()) {
      const text = readFileSync(path, 'utf8').split(/\s+/).join(' ');
      assert.doesNotMatch(text, /socket trust (has a known limit|exception)|until the socket trust fix/i, path);
      assert.doesNotMatch(text, /socket ownership check fails[^.]*installed fail mode/i, path);
      assert.doesNotMatch(text, /keep the hook mode closed and run `repair`/, path);
    }
    const modes = page('reference/configuration/fail-modes.mdx');
    assert.match(modes, /hooks reject an invalid runtime, an unverified gateway peer or missing or refused credentials in every fail mode/);
    assert.match(modes, /- Another program answers in place of the gateway service\./);
  });

  it('limits managed open to a proven stopped gateway, including restart and no-answer paths', () => {
    const hook = readFileSync(join(repo, 'internal/gateway/connector/hookexec/hookexec.go'), 'utf8');
    const outage = hook.split('func ManagedOutageFailsOpen')[1]?.split('// managedCopilotOpen')[0];
    assert.match(outage ?? '', /return errors\.Is\(err, errManagedGatewayNotRunning\)\s*\}/);
    const restart = hook.split('case errors.Is(cause, errGatewayRestarting):')[1]?.split('case ', 1)[0];
    assert.match(restart ?? '', /return failUnreachable\(opts, sp, "closed", managedGatewayRestartingReason\)/);
    assertPartialBodyUsesDeliveryMode(hook);
    const deadline = readFileSync(join(repo, 'internal/gateway/connector/hookexec/answer_deadline.go'), 'utf8');
    const noAnswer = deadline.split('func noAnswerFailMode')[1]?.split('func failNoAnswer')[0];
    assert.match(noAnswer ?? '', /opts\.ManagedEnterprise\s*\{\s*return "closed"[\s\S]*return failMode/);

    const pages = [
      'reference/configuration/fail-modes.mdx',
      'reference/apis/capability-matrix.mdx',
      'enterprise/operate/lifecycle.mdx',
      'enterprise/operate/reference.mdx',
      'appendix/coverage-by-layer.mdx',
      'enterprise/configure/reference.mdx',
      'features/guardrail.mdx',
    ];
    for (const name of pages) {
      const text = page(name);
      assert.match(text, /administrator(?:'s)? `open` applies only when the gateway is proven not running/i, name);
      assert.ok(text.includes('/docs/reference/apis/capability-matrix#gateway-outage') || name === 'reference/apis/capability-matrix.mdx', name);
    }
    const staleClaims = [
      /administrator(?:'s)? `open` can allow[^.]*still restarting or gives no answer in time/i,
      /restarting[^.]*no.answer[^.]*can follow[^.]*`open`/i,
      /managed standalone[^.]*restarting or unanswered[^.]*allow/i,
    ];
    for (const path of docPages()) {
      const text = readFileSync(path, 'utf8').split(/\s+/).join(' ');
      for (const claim of staleClaims) assert.doesNotMatch(text, claim, path);
    }

    const modes = page('reference/configuration/fail-modes.mdx');
    const matrix = page('reference/apis/capability-matrix.mdx');
    for (const [name, text] of [['fail modes', modes], ['capability matrix', matrix]] as const) {
      assert.match(text, /`enterprise_managed_gateway_restarting`[^.]*`enterprise_managed_gateway_no_answer`[^.]*block[^.]*`open`/i, name);
      assert.match(text, /foreign-hook guard[^.]*gateway[^.]*session[^.]*blocks/i, name);
      assert.match(text, /complete but unusable answers?[^.]*block/i, name);
    }
    const component = readFileSync(join(site, 'components/capability-matrix.tsx'), 'utf8');
    assert.match(component, /Managed standalone, administrator open, proven stopped gateway/);

    const threat = readFileSync(join(repo, 'docs/ENTERPRISE-THREAT-MODEL.md'), 'utf8').split(/\s+/).join(' ');
    assert.match(threat, /administrator(?:'s)? `open` applies only when the gateway is proven not running/i);
  });

  it('distinguishes proven stopped gateways from listener gaps on each OS', () => {
    const unix = readFileSync(join(repo, 'internal/gateway/connector/hookexec/managed_standalone_transport.go'), 'utf8');
    assert.match(unix, /errors\.Is\(err, errStandaloneSocketMissing\) \{[\s\S]*?return nil, standaloneGatewayStoppedError\(err\)/);
    assert.match(unix, /errors\.Is\(err, syscall\.ECONNREFUSED\) \|\| errors\.Is\(err, syscall\.ENOENT\) \{[\s\S]*?return nil, standalonePeerError\("hook socket stopped answering after verification:/);
    const windows = readFileSync(join(repo, 'internal/gateway/connector/hookexec/managed_transport_windows.go'), 'utf8');
    assert.match(windows, /if listening, known := managedEnterpriseListening\(canonicalAddr\); known && !listening \{[\s\S]*?return nil, fmt\.Errorf\("%w: %w: running service has no listener on %s yet",\s*errManagedGatewayPeerUnverified, errGatewayNotConnected/);
    for (const name of ['reference/configuration/fail-modes.mdx', 'reference/apis/capability-matrix.mdx']) {
      const text = page(name);
      assert.match(text, /Linux and macOS[^.]*missing socket in a trusted directory[^.]*gateway[^.]*not running/i, name);
      assert.match(text, /Windows[^.]*stopped service[^.]*no listener[^.]*gateway[^.]*not running/i, name);
      assert.match(text, /refuses a connection[^.]*blocks even under `open`/i, name);
      assert.match(text, /running service with no listener[^.]*blocks even under `open`/i, name);
    }
    for (const name of [
      'enterprise/operate/lifecycle.mdx',
      'enterprise/operate/reference.mdx',
      'enterprise/configure/reference.mdx',
      'appendix/coverage-by-layer.mdx',
    ]) {
      const text = page(name);
      assert.match(text, /Linux and macOS[^.]*refuses a connection[^.]*blocks/i, name);
      assert.match(text, /Windows[^.]*running service with no listener[^.]*blocks/i, name);
    }
  });

  it('distinguishes Secure Client request timeout from a standalone no-answer deadline', () => {
    const deadline = readFileSync(join(repo, 'internal/gateway/connector/hookexec/answer_deadline.go'), 'utf8');
    assert.match(deadline, /if opts\.SecureClient \|\| startedAt\.IsZero\(\) \|\| !bounded \{\s*return time\.Time\{\}/);
    const hook = readFileSync(join(repo, 'internal/gateway/connector/hookexec/hookexec.go'), 'utf8');
    assertPartialBodyUsesDeliveryMode(hook);
    const modes = page('reference/configuration/fail-modes.mdx');
    assert.match(modes, /A managed standalone tool hook blocks when its gateway gives no answer by the deadline, even under administrator `open`/);
    assert.match(modes, /locally spent budgets and calls answered first with HTTP 429 block/);
    assert.match(modes, /Other events use their event-specific outcomes/);
    assert.match(modes, /Secure Client hooks have no separate no-answer deadline and keep their whole request budget/);
    assert.match(modes, /a request that times out before headers follows its effective fail mode/);
    assert.doesNotMatch(modes, /no-answer deadline[^.]*including Secure Client/i);
  });

  it('pins Hermes Secure Client fail-open delivery and its capability row', () => {
    const hook = readFileSync(join(repo, 'internal/gateway/connector/hookexec/hookexec.go'), 'utf8');
    const readFailure = hook.match(/if readErr != nil \{([\s\S]*?)\n\t\}/)?.[1] ?? '';
    assert.match(readFailure, /return (?:failNoAnswer\(opts, sp, failMode\)|failAfterErrorStatus\(opts, sp, failMode, knownStatus\))/);
    if (readFailure.includes('failAfterErrorStatus')) {
      assert.match(hook, /func failAfterErrorStatus[\s\S]*?if status == 0 \|\| !managedNativeDecision\(opts\) \{\s*return failNoAnswer\(opts, sp, failMode\)/);
    }
    assert.match(hook, /blocked := !sp\.failOpenOnly && \(opts\.StrictAvailability \|\| failMode == "closed"\)/);

    const hermes = readFileSync(join(repo, 'internal/gateway/connector/hookexec/managed_hermes.go'), 'utf8');
    assert.match(hermes, /if opts\.ManagedEnterprise && !managedNativeDecision\(opts\) \{\s*return false/);
    const shell = readFileSync(join(repo, 'internal/gateway/connector/hooks/hermes-hook.sh'), 'utf8');
    const shellTransport = shell.split('fail_unreachable() {').pop()?.split('\n}')[0] ?? '';
    assert.match(shellTransport, /defenseclaw_log_hook_delivery_failure hermes hermes-hook/);
    assert.match(shellTransport, /if defenseclaw_should_fail_closed_on_unreachable; then[\s\S]*?exit 2[\s\S]*?fi\s*exit 0/);

    const matrix = JSON.parse(readFileSync(join(site, 'data/capability-matrix.json'), 'utf8'));
    for (const id of ['hermes', 'copilot', 'antigravity']) {
      const row = matrix.connectors.find((connector: { id: string }) => connector.id === id);
      assert.equal(row?.outage.secureClientClosed, 'runs', id);
    }

    const secure = page('reference/configuration/fail-modes.mdx').split('### Secure Client')[1]?.split('### Connector limits')[0] ?? '';
    assert.match(secure, /default `open`[^.]*Hermes tool call[^.]*records the failure/i);
    for (const path of docPages()) {
      assert.doesNotMatch(readFileSync(path, 'utf8').split(/\s+/).join(' '), /a successful response cut off after headers blocks\./i, path);
    }
  });

  it('states Secure Client partial-body delivery on Windows and macOS without a blanket block claim', () => {
    const hook = readFileSync(join(repo, 'internal/gateway/connector/hookexec/hookexec.go'), 'utf8');
    assertPartialBodyUsesDeliveryMode(hook);
    assert.match(hook, /func managedNativeDecision\(opts Options\) bool \{\s*return opts\.ManagedEnterprise && !opts\.SecureClient/);
    const deadline = readFileSync(join(repo, 'internal/gateway/connector/hookexec/answer_deadline.go'), 'utf8');
    assert.match(deadline, /func noAnswerFailMode[\s\S]*?return failMode/);
    const render = readFileSync(join(repo, 'internal/gateway/connector/subprocess.go'), 'utf8');
    assert.match(render, /func shellHookSecureClientDelivery\(opts SetupOpts\) bool \{\s*return shellHookSecureClientProfile\(opts\) && opts\.SecureClientHookDelivery/);
    assert.match(render, /func setupHookFailMode\(opts SetupOpts\) string \{\s*if strings\.TrimSpace\(opts\.HookFailMode\) == "" && opts\.SecureClientHookDelivery && SecureClientDeploymentVerified\(\) \{/);
    const codex = readFileSync(join(repo, 'internal/gateway/connector/hooks/codex-hook.sh'), 'utf8');
    assert.match(codex, /if \[ "\$CURL_STATUS" -ne 0 \]; then\s*fail_unreachable "gateway unreachable"/);
    assert.match(codex, /fail_unreachable\(\)[\s\S]*?if defenseclaw_should_fail_closed_on_unreachable; then\s*exit 2[\s\S]*?exit 0/);
    for (const name of ['claude-code', 'hermes']) {
      const shell = readFileSync(join(repo, `internal/gateway/connector/hooks/${name}-hook.sh`), 'utf8');
      const failure = shell.split('fail_unreachable() {').pop()?.split('\n}')[0] ?? '';
      assert.match(shell, /defenseclaw_await_gateway[^\n]*\|\| fail_unreachable "gateway unreachable"/, name);
      assert.match(failure, /if defenseclaw_should_fail_closed_on_unreachable; then[\s\S]*?exit 2[\s\S]*?exit 0/, name);
    }
    const secure = page('reference/configuration/fail-modes.mdx').split('### Secure Client')[1]?.split('### Connector limits')[0] ?? '';
    assert.match(secure, /Windows native Secure Client[^.]*cut off after headers[^.]*default `open`[^.]*allow/i);
    assert.match(secure, /macOS Secure Client[^.]*shell hooks[^.]*cut off[^.]*default `open`[^.]*allow/i);
    assert.match(secure, /explicit `closed`[^.]*block where the connector can deliver a block/i);
    assert.match(secure, /outside the 1\.0\.4 test scope/i);
    assert.doesNotMatch(secure, /successful response cut off after headers is blocked/);
  });

  it('limits every-mode HTTP 401 and 403 refusals to managed standalone hooks', () => {
    const hook = readFileSync(join(repo, 'internal/gateway/connector/hookexec/hookexec.go'), 'utf8');
    assert.match(hook, /func managedIntegrityFailMode\(opts Options, failMode string\) string \{\s*if managedNativeDecision\(opts\) \{\s*return "closed"\s*\}\s*return failMode/);
    assert.match(hook, /case resp\.StatusCode == http\.StatusUnauthorized \|\| resp\.StatusCode == http\.StatusForbidden:\s*\/\/ An authentication refusal is integrity, not an outage\.\s*return failResponse\(opts, sp, managedIntegrityFailMode\(opts, failMode\)/);
    const modes = page('reference/configuration/fail-modes.mdx');
    const refusals = modes.split('### Refusals that ignore the fail mode')[1]?.split('### Secure Client')[0] ?? '';
    assert.match(refusals, /block in every fail mode on a managed standalone host/);
    const secure = modes.split('### Secure Client')[1]?.split('### Connector limits')[0] ?? '';
    assert.match(secure, /HTTP 401 and 403[^.]*effective fail mode[^.]*default `open`[^.]*allow/i);
    assert.doesNotMatch(modes, /block in every fail mode on a managed computer/);
  });

  it('scopes an unreadable Windows listener table to a stopped service', () => {
    const transport = readFileSync(join(repo, 'internal/gateway/connector/hookexec/managed_transport_windows.go'), 'utf8');
    assert.match(transport, /if listening, known := managedEnterpriseListening\(canonicalAddr\); known && !listening/);
    assert.match(transport.split('func stoppedManagedGatewayError')[1] ?? '', /case !known:/);
    for (const name of ['reference/configuration/fail-modes.mdx', 'reference/apis/capability-matrix.mdx']) {
      const text = page(name);
      assert.match(text, /A stopped Windows service whose listener table cannot be read, or with another listener on its port, blocks\./, name);
      assert.match(text, /A connected listener owned by another process also blocks\./, name);
      assert.match(text, /When the service is running and the listener table cannot be read, the hook dials and verifies the connected peer\./, name);
      assert.doesNotMatch(text, /a running service with no listener(?: or|,) an unreadable listener table/i, name);
    }
  });
});

describe('installed fail mode environment contract', () => {
  it('does not classify the retired fail-mode input as tighten-only', () => {
    const text = page('troubleshooting/enterprise/hooks.mdx');
    const section = text.split('## A `DEFENSECLAW_*` variable or `.env` entry has no effect')[1]?.split('## ')[0];
    assert.ok(section, 'environment troubleshooting section');
    assert.match(section, /`DEFENSECLAW_FAIL_MODE` is not read by 1\.0\.4 hooks/);
    assert.match(section, /`DEFENSECLAW_STRICT_AVAILABILITY` and `DEFENSECLAW_HOOK_MAX_BODY`.*`tighten_only`/);
    assert.doesNotMatch(section, /`DEFENSECLAW_FAIL_MODE`, .*`tighten_only`/);
    assert.ok(section.includes('/docs/reference/apis/capability-matrix#gateway-outage'));
    const truth = page('reference/configuration/source-of-truth.mdx');
    assert.doesNotMatch(truth, /\| `tighten_only` \|[^|]*\|[^|]*DEFENSECLAW_FAIL_MODE/);
    const threat = page('enterprise/plan/threat-model.mdx');
    assert.doesNotMatch(threat, /`DEFENSECLAW_FAIL_MODE`, .*count only when stricter/);

    const managed = page('enterprise/plan/managed-policy.mdx');
    assert.doesNotMatch(managed, /`tighten_only` variables \(`DEFENSECLAW_FAIL_MODE`/);
    assert.match(managed, /`DEFENSECLAW_FAIL_MODE`.*1\.0\.4.*not read/);
    assert.ok(managed.includes('/docs/reference/apis/capability-matrix#gateway-outage'));
  });
});

describe('guardrail setup prompt mapping', () => {
  const source = readFileSync(join(repo, 'cli/defenseclaw/commands/cmd_setup.py'), 'utf8');
  const reference = readFileSync(join(site, 'content/docs/reference/commands/guardrail-setup.mdx'), 'utf8');
  const table = reference.split('## Prompt-flag mapping')[1]?.split('\n## ')[0] ?? '';
  const rows = table.split('\n').filter((line) => line.startsWith('| **'));

  it('names only prompts the wizard asks', () => {
    assert.ok(rows.length > 10, 'prompt-flag rows');
    for (const row of rows) {
      const cell = row.match(/^\| \*\*(.+?)\*\*/)?.[1] ?? '';
      for (const prompt of cell.split(' / ')) {
        assert.ok(source.includes(prompt), `cmd_setup.py has no prompt "${prompt}"`);
      }
    }
  });

  it('maps the action-mode judge picker and the proxy-only judge question', () => {
    assert.ok(source.includes('title="Select action connector(s) for LLM judge."'));
    assert.ok(source.includes('default_selected=_default_batch_judge_labels(judge_targets, gc, display_by_connector)'));
    assert.ok(source.includes('"  Add LLM judge on top of rule scanning?",\n        default=bool(gc.judge.enabled),'));
    const picker = rows.find((row) => row.startsWith('| **Select action connector(s) for LLM judge.**'));
    assert.match(picker ?? '', /none selected on first setup/i);
    assert.match(picker ?? '', /--judge-hook-connectors/);
    const question = rows.find((row) => row.startsWith('| **Add LLM judge on top of rule scanning?**'));
    assert.match(question ?? '', /proxy connectors only/);
  });
});

describe('observe mode scope', () => {
  // Observe mode turns policy verdicts into alerts. A check that cannot
  // complete still follows the hook fail mode (agent_hook.go
  // hookFailedCheckResponse), and the ACP guard can refuse an unchecked frame.
  const unscoped = /\b(never blocks?|blocks? nothing|allows? everything|(?<!\()cannot block|nothing is (stopped|blocked)|logs? only|only logs?|does not block(?! on)|without blocking(?! on))\b/i;

  // Already scoped claims the sweep cannot tell apart: a quoted CLI message
  // (pinned to the source that prints it) and the asset policy's `require`.
  const cliSample = 'The global mode is observe, so connectors that follow it only log';
  const scoped = [cliSample, 'so `require` alone blocks nothing and the CLI says so'];

  it('scopes every observe-mode no-block claim to policy findings', () => {
    assert.ok(readFileSync(join(repo, 'cli/defenseclaw/commands/cmd_guardrail.py'), 'utf8').includes(cliSample));
    const files = [
      ...docPages(),
      ...docPages(join(site, 'components'), /\.tsx?$/),
      ...docPages(join(site, 'data'), /\.(ts|json)$/),
    ];
    const claims: string[] = [];
    for (const path of files) {
      // Blocks end at a blank line, list item, table row or heading; inside a
      // block, a sentence wrapped across lines is read as one line.
      const blocks = readFileSync(path, 'utf8').split(/\n\s*(?=\n|[-*#|>]|\d+\.\s)/);
      for (const clause of blocks.flatMap((block) => block.split(/\s+/).join(' ').split(/[.;|]\s*/))) {
        if (/\bobserv/i.test(clause) && unscoped.test(clause) && !scoped.some((claim) => clause.includes(claim))) {
          claims.push(`${path.slice(site.length + 1)}: ${clause.trim()}`);
        }
      }
    }
    assert.deepEqual(claims, []);
  });

  it('states that hook failures still follow the fail mode', () => {
    for (const name of ['connectors/claudecode.mdx', 'connectors/antigravity.mdx', 'reference/policy/thresholds.mdx', 'how-to/guardrail/turn-on-blocking.mdx']) {
      assert.match(page(name), /does not block on (policy )?(findings|them)/i, name);
      assert.match(page(name), /closed hook|fail mode/i, name);
    }
    assert.match(page('connectors/cursor.mdx'), /managed computer.*administrator's outage mode/i);
    assert.match(page('features/acp-guard.mdx'), /observe mode.*`fail_mode`/i);
  });
});

describe('quarantine publication and cleanup', () => {
  it('distinguishes an unpublished copy from failed source removal', () => {
    const text = page('reference/scanning/scanners.mdx');
    assert.doesNotMatch(text, /Two cases do not end in quarantine storage/);
    assert.match(text, /Before a verified copy is published.*files stay in place/i);
    assert.match(text, /After publication.*verified copy stays in quarantine storage/i);
    assert.match(text, /source.*partly or completely removed/i);
    assert.match(text, /`quarantine failed`.*install block and runtime disable stay/i);
  });

  it('keeps the quarantine-failure audit neutral about the source location', () => {
    const watcher = readFileSync(join(repo, 'internal/watcher/watcher.go'), 'utf8');
    const failure = watcher.split('func (w *InstallWatcher) emitQuarantineFailure')[1]?.split('func quarantineUnmaterialized')[0] ?? '';
    assert.match(failure, /Quarantine failed; inspect the source and quarantine copy/);
    assert.doesNotMatch(failure, /asset stays in place/);
    const scanners = page('reference/scanning/scanners.mdx');
    assert.match(scanners, /After publication.*source may be partly or completely removed/i);
    assert.match(scanners, /Check `skill info` and the quarantine location before recovering the skill/);
  });
});

describe('routed 1.0.4 documentation gaps', () => {
  it('covers every guarded managed connector during an outage on each OS', () => {
    const policy = readFileSync(join(repo, 'internal/enterprisepolicy/publicpolicy.go'), 'utf8');
    const guard = policy.split('var guardConnectors =')[1]?.split('var unixGuardConnectors')[0] ?? '';
    const rows = JSON.parse(readFileSync(join(site, 'data/capability-matrix.json'), 'utf8')).connectors;
    for (const [name, label] of [
      ['cursor', 'Cursor'],
      ['copilot', 'Copilot'],
      ['devin', 'Devin'],
      ['opencode', 'OpenCode'],
    ]) {
      assert.match(guard, new RegExp(`(?:Connector${label}|"${name}"):\\s*true`), name);
      assert.equal(rows.find((row: { id: string }) => row.id === name)?.outage.managedOpen, 'blocks', name);
    }
    assert.match(guard, /"amp":\s*true/);
    const amp = rows.find((row: { id: string }) => row.id === 'amp')?.outage;
    assert.ok(['blocks', 'blocks-linux-macos'].includes(amp?.managedOpen), 'Amp blocks on Linux and macOS');
    if (amp?.managedOpenNoGuard !== undefined) assert.equal(amp.managedOpenNoGuard, 'blocks');
    const matrix = page('reference/apis/capability-matrix.mdx');
    assert.match(matrix, /foreign-hook guard[^.]*Copilot CLI, Cursor, Devin, OpenCode and Amp[^.]*Linux, macOS and Windows/i);
    assert.match(matrix, /Hermes[^.]*Linux and macOS/i);
    assert.doesNotMatch(matrix, /Copilot[^.]*machine-policy route[^.]*follows the administrator's outage mode for that condition/i);
  });

  it('describes managed OpenCode outages under the default guard and per OS without it', () => {
    const plugin = readFileSync(join(repo, 'internal/gateway/connector/hooks/opencode-plugin.js'), 'utf8');
    assert.match(plugin, /defenseclawForeignHookCheck\(event, cwd\)[\s\S]*?if \(!DC_FOREIGN_GUARD\) return Promise\.resolve\(""\)/);
    assert.match(plugin, /function defenseclawForeignHookCheck[\s\S]*?if \(err\) \{\s*fail\(/);
    assert.match(plugin, /DC_FAIL_MODE = "\{\{if (?:and \.Managed \(not \.SecureClient\)|\.ManagedOutageClosed)\}\}closed\{\{else\}\}\{\{\.FailMode\}\}\{\{end\}\}"/);
    const policy = readFileSync(join(repo, 'internal/enterprisepolicy/publicpolicy.go'), 'utf8');
    assert.match(policy, /guardConnectors = map\[string\]bool\{[\s\S]*?"opencode":\s*true/);
    const machinePlugin = readFileSync(join(repo, 'internal/enterprisepolicy/opencode_managed_plugin.js'), 'utf8');
    assert.match(machinePlugin, /"--enterprise-managed"/);
    const hook = readFileSync(join(repo, 'internal/gateway/connector/hookexec/hookexec.go'), 'utf8');
    assert.match(hook, /func ManagedOutageFailsOpen[\s\S]*?return errors\.Is\(err, errManagedGatewayNotRunning\)/);
    const reference = page('enterprise/configure/reference.mdx');
    const managed = reference.split('### Managed OpenCode plugin')[1]?.split('### What DefenseClaw writes')[0] ?? '';
    assert.match(managed, /default foreign-hook guard[^.]*gateway outage blocks[^.]*Linux, macOS and Windows/i);
    assert.match(managed, /`foreign_hooks: report` or `allow`[^.]*machine-policy route[^.]*every OS/i);
    assert.match(managed, /per-user route[^.]*Linux and macOS[^.]*both modes/i);
    assert.ok(managed.includes('/docs/reference/apis/capability-matrix#gateway-outage'));
    assert.doesNotMatch(managed, /It fails closed:.*gateway is unreachable/i);
    const machine = page('enterprise/configure/machine-policy.mdx');
    assert.match(machine, /default foreign-hook guard[^.]*outage blocks on Linux, macOS and Windows/i);
    assert.match(machine, /`foreign_hooks: report` or `allow`[^.]*classified gateway outage[^.]*every OS/i);
    const matrix = JSON.parse(readFileSync(join(site, 'data/capability-matrix.json'), 'utf8'));
    assert.equal(matrix.connectors.find((row: { id: string }) => row.id === 'opencode')?.outage.managedOpen, 'blocks');
    assert.match(page('reference/apis/capability-matrix.mdx'), /Copilot's and OpenCode's machine-policy routes follow the installed mode for a proven stopped gateway on every OS/);
  });

  it('describes ACP adoption and asks operators to inspect extra picker entries', () => {
    const source = readFileSync(join(repo, 'cli/defenseclaw/commands/cmd_acp.py'), 'utf8');
    assert.match(source, /aliases = \[name for name in names if name != _managed_name\(agent\)\]/);
    assert.match(source, /written = aliases or names or \[(?:_managed_name\(agent\)|_free_entry_name\(servers, agent\))\]/);
    const feature = page('features/acp-guard.mdx');
    assert.match(feature, /Fresh `defenseclaw acp setup`[^.]*`DefenseClaw · <agent>`/);
    assert.match(feature, /`defenseclaw setup acp`[^.]*existing direct picker entry in place[^.]*without adding a duplicate for that adopted key/i);
    assert.match(feature, /`acp verify` and inspect the editor's picker[^.]*copied guard/i);
    const howto = page('how-to/agents/guard-an-acp-editor.mdx');
    assert.match(howto, /`acp verify` and inspect the editor's picker[^.]*copied guard[^.]*remove those entries in the editor/i);
  });

  it('explains how setup handles an occupied reserved ACP entry', () => {
    const source = readFileSync(join(repo, 'cli/defenseclaw/commands/cmd_acp.py'), 'utf8');
    const howto = page('how-to/agents/guard-an-acp-editor.mdx');
    if (source.includes('def _free_entry_name(')) {
      assert.match(howto, /reserved[^.]*writes[^.]*`DefenseClaw · <Agent> \(2\)`/i);
      assert.match(howto, /`acp verify` fails until[^.]*delete that entry/i);
    } else {
      assert.match(source, /def _check_reserved_entry[\s\S]*?cannot identify editor entry[\s\S]*?rename that entry/);
      assert.match(howto, /needs to create a reserved entry[^.]*cannot identify as DefenseClaw-owned[^.]*setup refuses/i);
      assert.match(howto, /Rename that entry[^.]*run the same command again/i);
      assert.doesNotMatch(howto, /reserved entry[^.]*selecting one in the picker/i);
    }
  });

  it('states that a stray deployment pin is dropped for per-user config on every OS', () => {
    const go = readFileSync(join(repo, 'internal/managed/pin_guard.go'), 'utf8');
    assert.match(go, /func IgnoreUnmanagedPins[\s\S]*?!underDirectory\(configPath, homeDir\) \|\| declaresManaged\(configPath\)/);
    const python = readFileSync(join(repo, 'cli/defenseclaw/config.py'), 'utf8');
    assert.match(python, /def ignore_unmanaged_deployment_pins[\s\S]*?if declares_managed:\s*return \[\][\s\S]*?os\.environ\.pop\(name, None\)/);
    const vars = page('reference/configuration/env-vars.mdx');
    const pins = vars.split('**The deployment pins cannot be used')[1]?.split('**Settings have a config key')[0] ?? '';
    assert.match(pins, /per-user `config\.yaml`[^.]*Linux, macOS and Windows[^.]*ignore[^.]*shell export/i);
    assert.match(pins, /managed service[^.]*machine-owned config[^.]*pin/i);
    assert.doesNotMatch(pins, /only makes that process's writers refuse changes/);
  });

  it('states Antigravity event binding syntax per OS', () => {
    const source = readFileSync(join(repo, 'internal/gateway/connector/helpers.go'), 'utf8');
    assert.match(source, /func antigravityHookInvocationCommandForEvent[\s\S]*?if goos == "windows"[\s\S]*?windowsNativePowerShellHookCommandForEvent\("antigravity", event/);
    assert.match(source, /return strings\.TrimSpace\(unixCommand\) \+ " " \+ event/);
    const reference = page('reference/connectors/antigravity.mdx');
    assert.match(reference, /Windows[^.]*`--event`[^.]*Linux and macOS[^.]*positional event/i);
    assert.doesNotMatch(reference, /each event's native `--event` binding/);
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
    const matrix = JSON.parse(readFileSync(join(site, 'data/capability-matrix.json'), 'utf8'));
    for (const id of ['copilot', 'antigravity']) {
      const row = matrix.connectors.find((connector: { id: string }) => connector.id === id);
      assert.equal(row?.outage.perUserClosed, 'blocks', id);
      assert.equal(row?.hooks.blocksDeliveryFailures, true, id);
      const text = page(`reference/connectors/${id}.mdx`);
      assert.ok(text.includes('/docs/reference/apis/capability-matrix#gateway-outage'), id);
      assert.doesNotMatch(text, /no fail-closed hook transport|A gateway failure lets the call run|normal fail-open operation/i, id);
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
    assert.ok(page('reference/configuration/fail-modes.mdx').includes('Hooks follow an open fail mode only when your config sets it'));
  });
});
