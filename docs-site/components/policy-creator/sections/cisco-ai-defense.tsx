// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Editor for the optional Cisco AI Defense lane. Mirrors the
// `cisco_ai_defense:` block in config.yaml that the gateway parses
// in internal/config/config.go. The gateway runs the lane on:
//
//   - the proxy lane (chat prompts + completions) for OpenClaw /
//     ZeptoClaw — scanner_mode = remote | both, and
//   - the hook lane (PreToolUse / PostToolUse / UserPromptSubmit on
//     hook-only connectors like Codex, Claude Code, Cursor, etc.) —
//     gated on scan_hook_surface (defaults to true).
//
// We intentionally never accept a literal API key here; the wizard
// only writes the env-var name. The gateway resolves the key at boot
// via os.Getenv(api_key_env) so secrets never land in policy YAML or
// share-link URLs.

'use client';

import type { CiscoAIDefenseConfig, Policy } from '../types';
import { TextField } from '../ui/text-field';
import { Toggle } from '../ui/toggle';

export function CiscoAIDefenseSection({
  policy,
  onPolicyChange,
}: {
  policy: Policy;
  onPolicyChange: (next: Policy) => void;
}) {
  const aid = policy.cisco_ai_defense;
  const update = (patch: Partial<CiscoAIDefenseConfig>) => {
    onPolicyChange({
      ...policy,
      cisco_ai_defense: { ...policy.cisco_ai_defense, ...patch },
    });
  };

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-fd-border bg-fd-card p-3 text-[12px] leading-5 text-fd-muted-foreground">
        <p>
          Optional · Enterprise second-opinion lane. When the gateway resolves a non-empty
          <code className="mx-1">api_key_env</code>, it forwards prompts and (if{' '}
          <strong>scan_hook_surface</strong> is on) hook-surface tool calls to{' '}
          <a
            href="https://www.cisco.com/site/us/en/products/security/ai-defense/index.html"
            target="_blank"
            rel="noopener noreferrer"
            className="font-medium text-[var(--brand-cisco)] underline-offset-2 hover:underline"
          >
            Cisco AI Defense ↗
          </a>{' '}
          and merges the verdict using strictest-wins semantics. The wizard never accepts a
          literal API key; only the env var name is written to YAML.
        </p>
      </div>

      <Toggle
        label="enable Cisco AI Defense"
        hint="Mostly a documentation toggle — the lane no-ops until api_key_env resolves at gateway boot. Keep off until you have a key provisioned."
        checked={aid.enabled}
        onChange={(v) => update({ enabled: v })}
      />

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-12">
        <div className="sm:col-span-7">
          <TextField
            label="endpoint"
            value={aid.endpoint}
            onChange={(v) => update({ endpoint: v })}
            placeholder="https://us.api.inspect.aidefense.security.cisco.com/api/v1/inspect/chat"
            hint="Leave blank to use the gateway's default endpoint."
          />
        </div>
        <div className="sm:col-span-5">
          <TextField
            label="api_key_env"
            value={aid.api_key_env}
            onChange={(v) => update({ api_key_env: v })}
            placeholder="CISCO_AI_DEFENSE_API_KEY"
            hint="Env var NAME (UPPER_SNAKE). The gateway reads the actual secret via os.Getenv at boot — never paste the literal key here, it would land in YAML and share URLs."
          />
          {aid.api_key_env && !/^[A-Z_][A-Z0-9_]{2,63}$/.test(aid.api_key_env) && (
            <p className="mt-1 text-[10px] leading-snug text-red-500">
              Doesn&apos;t look like an env-var name. Expected
              UPPER_SNAKE matching <code>[A-Z_][A-Z0-9_]+</code>. If you
              pasted an actual API key, clear the field and use the env
              var name the gateway should read instead.
            </p>
          )}
        </div>
      </div>

      <Toggle
        label="scan_hook_surface"
        hint="Default on (matches CiscoAIDefenseConfig.HookSurfaceEnabled). When off, AID only sees proxy-lane traffic. Turning this off is the only knob that lets operators run AID on chat prompts but exclude tool calls."
        checked={aid.scan_hook_surface}
        onChange={(v) => update({ scan_hook_surface: v })}
      />
    </div>
  );
}
