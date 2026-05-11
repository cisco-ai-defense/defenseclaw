'use client';

import { useMemo, useState } from 'react';
import matrix from '@/data/capability-matrix.json';

// Interactive, non-interactive `defenseclaw setup guardrail` command
// builder. Every knob the operator can pass on the CLI is exposed as
// a form control here. The generated `defenseclaw setup guardrail
// --non-interactive ...` is rendered live below the form with a copy
// button and a notes panel that surfaces validation warnings (e.g.
// remote scanner requires Cisco endpoint, HITL in observe mode is a
// no-op, connectors without native ask downgrade to a TUI confirm).
//
// The component reads the capability matrix shipped at
// `data/capability-matrix.json` for connector metadata so this stays
// in lockstep with the rest of the docs site. Update the JSON; this
// updates with it.

type ConnectorRow = {
  id: string;
  label: string;
  family: 'proxy' | 'hooks';
  toolInspection: string;
  subprocessPolicy: string;
  hooks: {
    canBlock: boolean;
    canAskNative: boolean;
    askEvents: string[];
    blockEvents: string[];
    supportsFailClosed: boolean;
    scope: 'user' | 'workspace';
  };
  hilt: string;
  notes?: string;
};

const CONNECTORS = (matrix as { connectors: ConnectorRow[] }).connectors;

type Mode = 'observe' | 'action';
type ScannerMode = 'local' | 'remote' | 'both';
type DetectionStrategy = 'regex_only' | 'regex_judge' | 'judge_first';
type RulePack = 'default' | 'strict' | 'permissive';
type HitlSeverity = 'high' | 'medium' | 'low' | 'critical';

interface GeneratorState {
  connector: string;
  mode: Mode;
  scannerMode: ScannerMode;
  ciscoEndpoint: string;
  ciscoApiKeyEnv: string;
  ciscoTimeoutMs: string;
  rulePack: RulePack;
  detectionStrategy: DetectionStrategy;
  judgeModel: string;
  judgeApiBase: string;
  judgeApiKeyEnv: string;
  humanApproval: boolean;
  hiltMinSeverity: HitlSeverity;
  port: string;
  blockMessage: string;
  disableRedaction: boolean;
  restart: boolean;
  verify: boolean;
  showAdvanced: boolean;
}

const DEFAULT_STATE: GeneratorState = {
  connector: 'claudecode',
  mode: 'observe',
  scannerMode: 'local',
  ciscoEndpoint: '',
  ciscoApiKeyEnv: 'CISCO_AI_DEFENSE_API_KEY',
  ciscoTimeoutMs: '',
  rulePack: 'default',
  detectionStrategy: 'regex_only',
  judgeModel: 'anthropic/claude-sonnet-4-20250514',
  judgeApiBase: '',
  judgeApiKeyEnv: 'DEFENSECLAW_LLM_KEY',
  humanApproval: false,
  hiltMinSeverity: 'high',
  port: '',
  blockMessage: '',
  disableRedaction: false,
  restart: true,
  verify: true,
  showAdvanced: false,
};

// Quote a value for safe inclusion as a single shell argument. Single
// quotes are bulletproof in POSIX shells; the only character that
// can't appear inside them is `'` itself, which we escape via the
// `'\''` close-reopen idiom. We deliberately do NOT skip quoting when
// the value "looks safe" — keeping every operator-supplied value
// quoted means there is no path where injected metacharacters survive
// the rendered command. The output is for display + copy-paste only;
// the generator never executes any shell.
function shellQuote(value: string): string {
  if (value === '') return "''";
  // Conservative allow-list: bare tokens only when the value is
  // strictly alphanumeric plus a handful of always-safe punctuation
  // (model slugs, env-var names, hostnames, integer ports). Everything
  // else gets the single-quote treatment.
  if (/^[A-Za-z0-9_./:@\-]+$/.test(value)) return value;
  return "'" + value.replace(/'/g, "'\\''") + "'";
}

function buildCommand(s: GeneratorState): { lines: string[]; preExports: string[]; warnings: string[] } {
  const lines: string[] = ['defenseclaw setup guardrail', '--non-interactive'];
  const preExports: string[] = [];
  const warnings: string[] = [];

  const connectorRow = CONNECTORS.find((c) => c.id === s.connector);
  if (connectorRow) {
    lines.push(`--connector ${shellQuote(connectorRow.id)}`);
  }

  lines.push(`--mode ${s.mode}`);

  // Scanner backend.
  lines.push(`--scanner-mode ${s.scannerMode}`);
  if (s.scannerMode === 'remote' || s.scannerMode === 'both') {
    if (s.ciscoEndpoint.trim()) {
      lines.push(`--cisco-endpoint ${shellQuote(s.ciscoEndpoint.trim())}`);
    } else {
      warnings.push(
        'Remote scanner is enabled but no Cisco endpoint is set. The CLI will reject the run unless an endpoint is already in ~/.defenseclaw/config.yaml.',
      );
    }
    if (s.ciscoApiKeyEnv.trim() && s.ciscoApiKeyEnv !== 'CISCO_AI_DEFENSE_API_KEY') {
      lines.push(`--cisco-api-key-env ${shellQuote(s.ciscoApiKeyEnv.trim())}`);
    }
    if (s.ciscoTimeoutMs.trim()) {
      const n = Number(s.ciscoTimeoutMs.trim());
      if (Number.isFinite(n) && n > 0) {
        lines.push(`--cisco-timeout-ms ${n}`);
      }
    }
    const apiKeyEnv = s.ciscoApiKeyEnv.trim() || 'CISCO_AI_DEFENSE_API_KEY';
    preExports.push(`export ${apiKeyEnv}=<your-cisco-ai-defense-api-key>`);
  }

  // Action-mode-only enforcement knobs.
  if (s.mode === 'action') {
    lines.push(`--rule-pack ${s.rulePack}`);
    if (s.blockMessage.trim()) {
      lines.push(`--block-message ${shellQuote(s.blockMessage)}`);
    }
    if (s.humanApproval) {
      lines.push('--human-approval');
      lines.push(`--hilt-min-severity ${s.hiltMinSeverity}`);
    } else {
      lines.push('--no-human-approval');
    }
  } else {
    // Observe mode silently ignores HITL / rule-pack / block-message
    // server-side. Warn here so the operator notices.
    if (s.humanApproval) {
      warnings.push(
        'Human approval (HITL) only fires in action mode. Observe mode logs without blocking, so there is nothing to pause on. The --human-approval flag was omitted.',
      );
    }
    if (s.blockMessage.trim()) {
      warnings.push(
        'Custom block message only applies in action mode. Observe never blocks. The --block-message flag was omitted.',
      );
    }
  }

  // Detection strategy + judge knobs.
  lines.push(`--detection-strategy ${s.detectionStrategy}`);
  if (s.detectionStrategy !== 'regex_only') {
    if (s.judgeModel.trim()) {
      lines.push(`--judge-model ${shellQuote(s.judgeModel.trim())}`);
    } else {
      warnings.push(
        `Detection strategy ${s.detectionStrategy} requires --judge-model. Pick a judge model below or the CLI will fall back to regex_only.`,
      );
    }
    if (s.judgeApiBase.trim()) {
      lines.push(`--judge-api-base ${shellQuote(s.judgeApiBase.trim())}`);
    }
    if (s.judgeApiKeyEnv.trim()) {
      lines.push(`--judge-api-key-env ${shellQuote(s.judgeApiKeyEnv.trim())}`);
    }
    const apiKeyEnv = s.judgeApiKeyEnv.trim() || 'DEFENSECLAW_LLM_KEY';
    preExports.push(`export ${apiKeyEnv}=<your-llm-api-key>`);
  }

  // Advanced knobs.
  if (s.port.trim()) {
    const n = Number(s.port.trim());
    if (Number.isFinite(n) && n > 0 && n <= 65535) {
      lines.push(`--port ${n}`);
    } else {
      warnings.push(`Port ${s.port} is not a valid TCP port. Flag omitted.`);
    }
  }

  if (s.disableRedaction) {
    lines.push('--disable-redaction');
    warnings.push(
      'Redaction is disabled. Sinks will receive UNREDACTED prompts. Only do this inside trusted, single-tenant environments.',
    );
  }

  if (!s.restart) lines.push('--no-restart');
  if (!s.verify) lines.push('--no-verify');

  // Connector-specific HITL notes.
  if (s.mode === 'action' && s.humanApproval && connectorRow) {
    if (!connectorRow.hooks.canAskNative) {
      warnings.push(
        `${connectorRow.label} has no native ask surface. HITL prompts downgrade to a confirm verdict that the operator approves in 'defenseclaw tui' (raw_action preserved in the audit log).`,
      );
    } else if (connectorRow.hooks.askEvents.length > 0) {
      warnings.push(
        `${connectorRow.label} surfaces HITL prompts natively on: ${connectorRow.hooks.askEvents.join(', ')}.`,
      );
    }
  }

  if (s.mode === 'action' && connectorRow && !connectorRow.hooks.supportsFailClosed) {
    warnings.push(
      `${connectorRow.label} does not support fail-closed enforcement. On guardrail failure the request will be allowed through; use 'defenseclaw guardrail fail-mode closed' only on connectors that support it.`,
    );
  }

  return { lines, preExports, warnings };
}

function renderShellScript(preExports: string[], lines: string[]): string {
  const out: string[] = [];
  for (const e of preExports) {
    out.push(e);
  }
  if (preExports.length > 0) out.push('');
  // Join the verb + flags as one logical command with `\` line
  // continuations so the rendered output is a copy-pasteable POSIX
  // shell command, not a list.
  for (let i = 0; i < lines.length; i += 1) {
    const isLast = i === lines.length - 1;
    const indent = i === 0 ? '' : '  ';
    out.push(`${indent}${lines[i]}${isLast ? '' : ' \\'}`);
  }
  return out.join('\n');
}

export function CommandGenerator() {
  const [state, setState] = useState<GeneratorState>(DEFAULT_STATE);
  const [copied, setCopied] = useState(false);

  const built = useMemo(() => buildCommand(state), [state]);
  const script = useMemo(
    () => renderShellScript(built.preExports, built.lines),
    [built],
  );

  const update = <K extends keyof GeneratorState>(key: K, value: GeneratorState[K]) => {
    setState((prev) => ({ ...prev, [key]: value }));
    setCopied(false);
  };

  const onCopy = async () => {
    if (typeof navigator === 'undefined' || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(script);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard can be blocked by the embedding context (e.g.
      // sandboxed iframe). Fail silent — the user can still select +
      // copy the rendered <pre> manually.
    }
  };

  const onReset = () => {
    setState(DEFAULT_STATE);
    setCopied(false);
  };

  const selected = CONNECTORS.find((c) => c.id === state.connector);

  return (
    <div className="not-prose my-6 grid gap-6 rounded-2xl border border-fd-border bg-fd-card/60 p-5 lg:grid-cols-[1.1fr_1fr]">
      <div className="grid gap-6">
        <Section title="Connector" subtitle="Pick the agent framework.">
          <div className="grid gap-2 sm:grid-cols-2">
            {CONNECTORS.map((c) => (
              <ConnectorOption
                key={c.id}
                row={c}
                selected={state.connector === c.id}
                onSelect={() => update('connector', c.id)}
              />
            ))}
          </div>
        </Section>

        <Section
          title="Mode"
          subtitle="observe logs without blocking. action enforces on configured severities."
        >
          <SegmentedControl<Mode>
            name="mode"
            options={[
              { value: 'observe', label: 'observe', hint: 'log only' },
              { value: 'action', label: 'action', hint: 'block on findings' },
            ]}
            value={state.mode}
            onChange={(v) => update('mode', v)}
          />
        </Section>

        <Section title="Scanner backend" subtitle="local is zero-key bundled regex. remote calls Cisco AI Defense. both runs the union.">
          <SegmentedControl<ScannerMode>
            name="scanner-mode"
            options={[
              { value: 'local', label: 'local' },
              { value: 'remote', label: 'remote' },
              { value: 'both', label: 'both' },
            ]}
            value={state.scannerMode}
            onChange={(v) => update('scannerMode', v)}
          />
          {(state.scannerMode === 'remote' || state.scannerMode === 'both') && (
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <Field
                label="Cisco endpoint"
                placeholder="https://aidefense.example.com"
                value={state.ciscoEndpoint}
                onChange={(v) => update('ciscoEndpoint', v)}
              />
              <Field
                label="API key env var"
                placeholder="CISCO_AI_DEFENSE_API_KEY"
                value={state.ciscoApiKeyEnv}
                onChange={(v) => update('ciscoApiKeyEnv', v)}
              />
              <Field
                label="Timeout (ms)"
                placeholder="5000"
                inputMode="numeric"
                value={state.ciscoTimeoutMs}
                onChange={(v) => update('ciscoTimeoutMs', v)}
              />
            </div>
          )}
        </Section>

        <Section
          title="Detection strategy"
          subtitle="regex_only is the zero-key default. The judge variants need an LLM key."
        >
          <SegmentedControl<DetectionStrategy>
            name="detection-strategy"
            options={[
              { value: 'regex_only', label: 'regex_only' },
              { value: 'regex_judge', label: 'regex_judge' },
              { value: 'judge_first', label: 'judge_first' },
            ]}
            value={state.detectionStrategy}
            onChange={(v) => update('detectionStrategy', v)}
          />
          {state.detectionStrategy !== 'regex_only' && (
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <Field
                label="Judge model"
                placeholder="anthropic/claude-sonnet-4-20250514"
                value={state.judgeModel}
                onChange={(v) => update('judgeModel', v)}
              />
              <Field
                label="API key env var"
                placeholder="DEFENSECLAW_LLM_KEY"
                value={state.judgeApiKeyEnv}
                onChange={(v) => update('judgeApiKeyEnv', v)}
              />
              <Field
                label="API base (optional)"
                placeholder="https://bifrost.example.com"
                value={state.judgeApiBase}
                onChange={(v) => update('judgeApiBase', v)}
              />
            </div>
          )}
        </Section>

        <Section
          title="Rule pack"
          subtitle={
            state.mode === 'action'
              ? 'Bundled rule-pack profile. Picks the directory under ~/.defenseclaw/policies/guardrail/.'
              : 'Rule packs only apply when --mode is action.'
          }
        >
          <SegmentedControl<RulePack>
            name="rule-pack"
            options={[
              { value: 'default', label: 'default' },
              { value: 'strict', label: 'strict' },
              { value: 'permissive', label: 'permissive' },
            ]}
            value={state.rulePack}
            onChange={(v) => update('rulePack', v)}
            disabled={state.mode !== 'action'}
          />
        </Section>

        <Section
          title="Human-in-the-Loop (HITL)"
          subtitle={
            state.mode === 'action'
              ? selected?.hooks.canAskNative
                ? `${selected.label} supports native ask. HIGH findings pause inside the agent UI.`
                : selected
                  ? `${selected.label} has no native ask surface — HITL downgrades to a confirm verdict in defenseclaw tui.`
                  : 'Pause risky tool calls and ask for operator approval before they run.'
              : 'HITL only fires in action mode. Switch above to enable.'
          }
        >
          <div className="flex flex-wrap items-center gap-3">
            <Toggle
              label="Enable human approval"
              checked={state.humanApproval}
              onChange={(v) => update('humanApproval', v)}
              disabled={state.mode !== 'action'}
            />
            <SeverityPicker
              value={state.hiltMinSeverity}
              onChange={(v) => update('hiltMinSeverity', v)}
              disabled={state.mode !== 'action' || !state.humanApproval}
            />
          </div>
          {selected && (
            <p className="mt-3 text-xs text-fd-muted-foreground">
              <span className="font-medium text-fd-foreground">{selected.label} HITL:</span>{' '}
              {selected.hilt}
            </p>
          )}
        </Section>

        <Section
          title="Advanced"
          subtitle="Knobs most operators leave untouched."
        >
          <button
            type="button"
            onClick={() => update('showAdvanced', !state.showAdvanced)}
            className="text-sm font-medium text-[var(--brand-cisco-strong)] hover:underline"
            aria-expanded={state.showAdvanced}
          >
            {state.showAdvanced ? 'Hide' : 'Show'} advanced options
          </button>
          {state.showAdvanced && (
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <Field
                label="Gateway port"
                placeholder="4000"
                inputMode="numeric"
                value={state.port}
                onChange={(v) => update('port', v)}
              />
              <Field
                label="Custom block message"
                placeholder="(action mode only)"
                value={state.blockMessage}
                onChange={(v) => update('blockMessage', v)}
                disabled={state.mode !== 'action'}
              />
              <Toggle
                label="Disable redaction (dangerous)"
                checked={state.disableRedaction}
                onChange={(v) => update('disableRedaction', v)}
              />
              <Toggle
                label="Restart gateway after setup"
                checked={state.restart}
                onChange={(v) => update('restart', v)}
              />
              <Toggle
                label="Run connectivity verify"
                checked={state.verify}
                onChange={(v) => update('verify', v)}
              />
            </div>
          )}
        </Section>
      </div>

      <div className="grid gap-4">
        <div className="rounded-xl border border-fd-border bg-fd-card">
          <div className="flex items-center justify-between border-b border-fd-border px-4 py-2">
            <div className="text-xs font-medium text-fd-muted-foreground">
              defenseclaw setup guardrail —{' '}
              <span className="text-fd-foreground">
                {selected?.label ?? state.connector}
              </span>{' '}
              <span className="text-fd-muted-foreground/80">/ {state.mode}</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={onReset}
                className="rounded-md px-2 py-1 text-xs font-medium text-fd-muted-foreground hover:bg-fd-muted hover:text-fd-foreground"
              >
                Reset
              </button>
              <button
                type="button"
                onClick={onCopy}
                className="rounded-md bg-[var(--brand-cisco)]/15 px-2 py-1 text-xs font-medium text-[var(--brand-cisco-strong)] hover:bg-[var(--brand-cisco)]/25"
                aria-live="polite"
              >
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
          </div>
          <pre className="m-0 overflow-x-auto whitespace-pre p-4 font-mono text-[12.5px] leading-6 text-fd-foreground">
            {script}
          </pre>
        </div>

        <div className="rounded-xl border border-fd-border bg-fd-card p-4">
          <h4 className="mb-2 text-sm font-semibold text-fd-foreground">
            Notes & validation
          </h4>
          {built.warnings.length === 0 ? (
            <p className="text-sm text-fd-muted-foreground">
              No warnings. The command above should run cleanly with the
              connector and flags selected.
            </p>
          ) : (
            <ul className="space-y-2 text-sm">
              {built.warnings.map((w, i) => (
                <li
                  key={i}
                  className="flex gap-2 rounded-md border border-[var(--brand-warn)]/40 bg-[var(--brand-warn)]/10 px-3 py-2 text-fd-foreground"
                >
                  <span aria-hidden className="text-[var(--brand-warn)]">
                    ⚠
                  </span>
                  <span>{w}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {selected && (
          <div className="rounded-xl border border-fd-border bg-fd-card p-4">
            <h4 className="mb-2 text-sm font-semibold text-fd-foreground">
              {selected.label} capabilities
            </h4>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
              <Capability label="Family">{selected.family}</Capability>
              <Capability label="Scope">{selected.hooks.scope}</Capability>
              <Capability label="Tool inspection">{selected.toolInspection}</Capability>
              <Capability label="Subprocess policy">{selected.subprocessPolicy}</Capability>
              <Capability label="Native ask">
                {selected.hooks.canAskNative ? 'yes' : 'no — downgrades to confirm'}
              </Capability>
              <Capability label="Fail-closed">
                {selected.hooks.supportsFailClosed ? 'supported' : 'not supported'}
              </Capability>
            </dl>
            <p className="mt-3 text-xs text-fd-muted-foreground">
              See{' '}
              <a
                href={`/docs/connectors/${selected.id}`}
                className="text-[var(--brand-cisco-strong)] hover:underline"
              >
                /docs/connectors/{selected.id}
              </a>{' '}
              for the full per-connector guide.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

function Section({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-xl border border-fd-border bg-fd-card p-4">
      <h3 className="text-sm font-semibold text-fd-foreground">{title}</h3>
      {subtitle && (
        <p className="mt-1 text-xs leading-relaxed text-fd-muted-foreground">
          {subtitle}
        </p>
      )}
      <div className="mt-3">{children}</div>
    </section>
  );
}

function ConnectorOption({
  row,
  selected,
  onSelect,
}: {
  row: ConnectorRow;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={[
        'flex flex-col items-start gap-1 rounded-lg border px-3 py-2 text-left transition-colors',
        selected
          ? 'border-[var(--brand-cisco)] bg-[var(--brand-cisco)]/10'
          : 'border-fd-border bg-fd-card hover:border-[var(--brand-cisco)]/40 hover:bg-fd-muted/40',
      ].join(' ')}
    >
      <div className="flex w-full items-center justify-between gap-2">
        <span className="text-sm font-medium text-fd-foreground">{row.label}</span>
        <span
          className={
            row.family === 'proxy'
              ? 'rounded-full bg-[var(--brand-cisco)]/15 px-2 py-0.5 text-[10px] font-medium text-[var(--brand-cisco-strong)]'
              : 'rounded-full bg-fd-muted px-2 py-0.5 text-[10px] font-medium text-fd-muted-foreground'
          }
        >
          {row.family}
        </span>
      </div>
      <span className="text-[11px] text-fd-muted-foreground">
        {row.hooks.canAskNative ? 'native ask' : 'downgraded confirm'}
        {' · '}
        {row.hooks.supportsFailClosed ? 'fail-closed ok' : 'fail-open only'}
      </span>
    </button>
  );
}

function SegmentedControl<T extends string>({
  name,
  options,
  value,
  onChange,
  disabled,
}: {
  name: string;
  options: Array<{ value: T; label: string; hint?: string }>;
  value: T;
  onChange: (v: T) => void;
  disabled?: boolean;
}) {
  return (
    <div
      role="radiogroup"
      aria-label={name}
      className={[
        'inline-flex flex-wrap rounded-lg border border-fd-border bg-fd-background p-1',
        disabled ? 'opacity-50' : '',
      ].join(' ')}
    >
      {options.map((opt) => {
        const isActive = opt.value === value;
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={isActive}
            disabled={disabled}
            onClick={() => onChange(opt.value)}
            className={[
              'rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              isActive
                ? 'bg-[var(--brand-cisco)]/15 text-[var(--brand-cisco-strong)]'
                : 'text-fd-muted-foreground hover:text-fd-foreground',
              disabled ? 'cursor-not-allowed' : '',
            ].join(' ')}
          >
            {opt.label}
            {opt.hint && (
              <span className="ml-1 text-[10px] text-fd-muted-foreground">
                {opt.hint}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

function Toggle({
  label,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label
      className={[
        'inline-flex items-center gap-2 text-sm',
        disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer',
      ].join(' ')}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="size-4 rounded border-fd-border text-[var(--brand-cisco)] focus:ring-[var(--brand-cisco)]"
      />
      <span className="text-fd-foreground">{label}</span>
    </label>
  );
}

function SeverityPicker({
  value,
  onChange,
  disabled,
}: {
  value: HitlSeverity;
  onChange: (v: HitlSeverity) => void;
  disabled?: boolean;
}) {
  const opts: Array<{ value: HitlSeverity; label: string }> = [
    { value: 'critical', label: 'critical' },
    { value: 'high', label: 'high' },
    { value: 'medium', label: 'medium' },
    { value: 'low', label: 'low' },
  ];
  return (
    <label
      className={[
        'inline-flex items-center gap-2 text-sm',
        disabled ? 'opacity-60' : '',
      ].join(' ')}
    >
      <span className="text-xs text-fd-muted-foreground">Min severity</span>
      <select
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value as HitlSeverity)}
        className="rounded-md border border-fd-border bg-fd-background px-2 py-1 text-xs text-fd-foreground"
      >
        {opts.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  inputMode,
  disabled,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  inputMode?: 'text' | 'numeric' | 'email' | 'url';
  disabled?: boolean;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-xs font-medium text-fd-muted-foreground">{label}</span>
      <input
        type="text"
        value={value}
        disabled={disabled}
        placeholder={placeholder}
        inputMode={inputMode}
        onChange={(e) => onChange(e.target.value)}
        className={[
          'rounded-md border border-fd-border bg-fd-background px-2 py-1.5 text-xs text-fd-foreground placeholder:text-fd-muted-foreground/60',
          'focus:border-[var(--brand-cisco)] focus:outline-none focus:ring-1 focus:ring-[var(--brand-cisco)]',
          disabled ? 'cursor-not-allowed opacity-60' : '',
        ].join(' ')}
      />
    </label>
  );
}

function Capability({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-fd-muted-foreground">{label}</dt>
      <dd className="font-mono text-fd-foreground">{children}</dd>
    </>
  );
}
