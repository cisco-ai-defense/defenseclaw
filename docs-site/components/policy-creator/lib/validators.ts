// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Browser-side regex + policy validators. Two layers:
//
// 1) Compile-test the pattern with V8 to catch syntax errors and run
//    the operator's "match" / "no-match" examples through it.
// 2) Static lint for RE2 incompatibilities (Go's regexp package, used
//    by the engine, is RE2-based — no lookaround, no backreferences,
//    no possessive quantifiers, no atomic groups) plus a cheap
//    catastrophic-backtracking heuristic and an anchor sanity check.
//
// The full RE2 round-trip (via re2-wasm) is intentionally NOT loaded
// here — v1 of the wizard uses pattern lints that catch every feature
// gap we've actually seen in production rule packs without paying the
// 700KB re2-wasm download. We can layer it in later behind a button.

import type { Policy, RuleDef, ValidationCode, ValidationFinding } from '../types';

// --- Anti-secret-paste heuristics ------------------------------------------
//
// Operators routinely paste literal secrets into env-name fields like
// `secret_env` or `api_key_env` because the form labels them
// generically. The heuristics below catch the most common shapes:
// API key prefixes we recognize, JWTs, and PEM blocks. They're
// intentionally conservative (false-negative-biased over false-
// positive-biased) because a warning on a real env-var name is more
// annoying than a missed warning on a paste.

/**
 * Returns true iff `s` matches the conventional UPPER_SNAKE env-var
 * shape `[A-Z_][A-Z0-9_]{2,63}`. Used by the wizard to flag fields
 * that should be NAMES of env vars, not the values held inside them.
 */
export function looksLikeEnvVarName(s: string): boolean {
  return /^[A-Z_][A-Z0-9_]{2,63}$/.test(s);
}

/**
 * Scans free-form text for inline-secret-shaped tokens. Returns the
 * first match (or null) so the caller can attribute the warning to a
 * specific shape rather than a generic "you have a secret in here"
 * message.
 *
 * Recognized shapes (mirrors gateway's SecretPatterns set):
 *   - "sk-…"  (OpenAI / Anthropic API key prefix)
 *   - "ghp_…" (GitHub PAT)
 *   - "AKIA…" (AWS access key id)
 *   - JWT-shaped three-segment base64 strings
 *   - PEM blocks ("-----BEGIN ... PRIVATE KEY-----")
 *
 * Cross-reference: codeguard-1-hardcoded-credentials. Operators should
 * never store secrets in policy YAML; the gateway reads them from
 * env vars via os.Getenv() so they never reach disk in the rule pack.
 */
export function scanForInlineSecret(text: string): { kind: string } | null {
  // Cheap prefix scans first.
  if (/\bsk-[A-Za-z0-9]{20,}/.test(text)) return { kind: 'OpenAI/Anthropic-style API key' };
  if (/\bghp_[A-Za-z0-9]{36}\b/.test(text)) return { kind: 'GitHub PAT' };
  if (/\bgho_[A-Za-z0-9]{36}\b/.test(text)) return { kind: 'GitHub OAuth token' };
  if (/\bghs_[A-Za-z0-9]{36}\b/.test(text)) return { kind: 'GitHub server token' };
  if (/\bAKIA[0-9A-Z]{16}\b/.test(text)) return { kind: 'AWS access key id' };
  if (/-----BEGIN[A-Z ]*PRIVATE KEY-----/.test(text)) return { kind: 'PEM-encoded private key' };
  if (/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/.test(text)) {
    return { kind: 'JWT-shaped token' };
  }
  return null;
}

/**
 * Mask sensitive content for UI display: keep the first 3 / last 2
 * characters, replace the middle with bullets. Long enough strings
 * still produce a recognizable shape (e.g. "ghp•••••XY") so the
 * operator can confirm we caught the right field without the wizard
 * echoing the whole secret back into the DOM (where it could land
 * in a console screenshot or screen-share).
 */
export function redactForUI(s: string): string {
  if (s.length <= 6) return '••••';
  return `${s.slice(0, 3)}${'•'.repeat(Math.min(8, s.length - 5))}${s.slice(-2)}`;
}

export interface RegexLintResult {
  compiled: boolean;
  error: string | null;
  // Lint findings the wizard renders inline next to the regex input.
  findings: ValidationFinding[];
}

// Translate a Go RE2 pattern to something V8's RegExp can compile.
//
// RE2 supports inline flag groups at the start of a pattern — `(?i)foo`,
// `(?ims)foo` — that V8 rejects with "Invalid group". JS expresses the
// same thing as a separate flags arg to `new RegExp(pattern, flags)`.
//
// We also collapse any *consecutive* leading flag groups (`(?i)(?m)foo`)
// because RE2 treats them as additive. We do NOT touch mid-pattern flag
// scopes like `(?i:foo)` — those are RE2-only and we let the V8 compile
// fail naturally so the operator still sees the lint error.
//
// Returns the translated pattern + the JS flag set so the caller can
// pass both to `new RegExp(...)`.
function toV8(pattern: string, extraFlags: string): { pattern: string; flags: string } {
  let p = pattern;
  const flagSet = new Set(extraFlags.split(''));
  for (;;) {
    const m = p.match(/^\(\?([ims]+)\)/);
    if (!m) break;
    for (const ch of m[1]) flagSet.add(ch);
    p = p.slice(m[0].length);
  }
  return { pattern: p, flags: Array.from(flagSet).join('') };
}

// Patterns Go's regexp/syntax explicitly does not support. Listed by
// order of likelihood so we can give a useful diagnostic on the first
// match. See https://github.com/google/re2/wiki/Syntax for the RE2
// reference and Go's regexp/syntax for the engine's implementation.
const RE2_INCOMPAT: Array<{ probe: RegExp; label: string }> = [
  { probe: /\(\?=|\(\?!|\(\?<=|\(\?<!/, label: 'lookaround (?=, ?!, ?<=, ?<!) is not supported by RE2' },
  { probe: /\\[1-9]/, label: 'backreferences (\\1, \\2 …) are not supported by RE2' },
  { probe: /\(\?>/, label: 'atomic groups (?>) are not supported by RE2' },
  { probe: /[*+?]\+/, label: 'possessive quantifiers (*+, ++, ?+) are not supported by RE2' },
  { probe: /\\k</, label: 'named backreferences (\\k<…>) are not supported by RE2' },
];

const REDOS_ANTIPATTERNS: Array<{ probe: RegExp; label: string }> = [
  // (X+)+, (X*)+, (X+)*  — the classic exponential backtracking shape.
  { probe: /\([^()]*[+*]\)[+*]/, label: 'nested quantifier shape ((..+)+) is prone to catastrophic backtracking' },
  // Disjunction whose alternatives all match the same prefix
  // (a|aa|aaa)+ — secondary check that fires conservatively.
  { probe: /\(([^()|]+\|){2,}[^()]*\)[+*]/, label: 'overlapping alternation under a quantifier may explode on adversarial input' },
];

export function lintRegex(pattern: string): RegexLintResult {
  const findings: ValidationFinding[] = [];
  let compiled = false;
  let error: string | null = null;

  if (!pattern) {
    return {
      compiled: false,
      error: 'pattern is empty',
      findings: [
        {
          level: 'error',
          code: 'REGEX_INVALID',
          message: 'Pattern cannot be empty.',
          location: 'pattern',
        },
      ],
    };
  }

  // 1) Compile in V8 — translate RE2 inline flag groups (`(?i)`, `(?ims)`)
  //    to JS flags first so we don't false-flag valid Go patterns.
  try {
    const v8 = toV8(pattern, '');
    new RegExp(v8.pattern, v8.flags);
    compiled = true;
  } catch (err) {
    error = err instanceof Error ? err.message : String(err);
    findings.push({
      level: 'error',
      code: 'REGEX_INVALID',
      message: error,
      location: 'pattern',
    });
  }

  // 2) RE2 incompatibility lint (always run — even if V8 accepted it,
  //    Go's regexp will still reject lookaround / backrefs).
  for (const probe of RE2_INCOMPAT) {
    if (probe.probe.test(pattern)) {
      findings.push({
        level: 'error',
        code: 'REGEX_RE2_INCOMPAT',
        message: probe.label,
        location: 'pattern',
        fix: 'Re-author without that feature; the engine compiles patterns with Go\'s regexp (RE2).',
      });
    }
  }

  // 3) ReDoS heuristic.
  for (const probe of REDOS_ANTIPATTERNS) {
    if (probe.probe.test(pattern)) {
      findings.push({
        level: 'warning',
        code: 'REGEX_REDOS',
        message: probe.label,
        location: 'pattern',
        fix: 'Tighten the inner quantifier so each character is consumed by exactly one alternative.',
      });
    }
  }

  // 4) Anchor sanity. Patterns intended to bind a token to a known
  //    boundary are far less prone to false positives. We warn (not
  //    error) when neither anchor nor word-boundary appears anywhere.
  if (!/[\^$]|\\b|\\A|\\z/.test(pattern)) {
    findings.push({
      level: 'info',
      code: 'REGEX_ANCHOR_MISSING',
      message: 'Pattern has no anchors (^, $, \\b). It will match anywhere in the input.',
      location: 'pattern',
      fix: 'If the secret/identifier has a known prefix, anchor with ^ or \\b to reduce false positives.',
    });
  }

  return { compiled, error, findings };
}

export interface RegexTestResult {
  text: string;
  expected: 'match' | 'no-match';
  actual: 'match' | 'no-match' | 'error';
  detail?: string;
}

export function testRegex(
  pattern: string,
  flags: string,
  examples: string[],
  counterexamples: string[],
): RegexTestResult[] {
  const out: RegexTestResult[] = [];
  let re: RegExp | null = null;
  try {
    const v8 = toV8(pattern, flags);
    re = new RegExp(v8.pattern, v8.flags);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    for (const text of [...examples, ...counterexamples]) {
      out.push({
        text,
        expected: examples.includes(text) ? 'match' : 'no-match',
        actual: 'error',
        detail,
      });
    }
    return out;
  }

  for (const text of examples) {
    out.push({
      text,
      expected: 'match',
      actual: re.test(text) ? 'match' : 'no-match',
    });
  }
  for (const text of counterexamples) {
    out.push({
      text,
      expected: 'no-match',
      actual: re.test(text) ? 'match' : 'no-match',
    });
  }
  return out;
}

// Validate the entire policy. Used by the bottom bar's "issues" tray
// and the per-section status dots. Order matters: callers iterate the
// returned findings to compute the section status badges.
export function validatePolicy(policy: Policy): ValidationFinding[] {
  const findings: ValidationFinding[] = [];

  if (!policy.name || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(policy.name)) {
    findings.push({
      level: 'error',
      code: 'NAME_INVALID',
      message: 'Policy name must match [a-z0-9][a-z0-9-]{0,63}.',
      location: 'basics.name',
    });
  }

  // Rules: dedupe, validate IDs, lint patterns.
  const seenIds = new Set<string>();
  for (const file of policy.rule_pack.files) {
    for (const rule of file.rules) {
      if (!rule.id) {
        findings.push({
          level: 'error',
          code: 'ID_FORMAT',
          message: `Rule in ${file.filename}.yaml is missing an id.`,
          location: `rules.${file.filename}`,
        });
        continue;
      }
      if (seenIds.has(rule.id)) {
        findings.push({
          level: 'error',
          code: 'ID_DUPLICATE',
          message: `Duplicate rule id "${rule.id}".`,
          location: `rules.${file.filename}.${rule.id}`,
          fix: 'Each rule id must be unique across every rule pack file.',
        });
      } else {
        seenIds.add(rule.id);
      }
      if (!/^[A-Z][A-Z0-9_-]{2,63}$/.test(rule.id)) {
        findings.push({
          level: 'warning',
          code: 'ID_FORMAT',
          message: `Rule id "${rule.id}" should be UPPER_SNAKE_OR_DASH (e.g. SEC-AWS-KEY).`,
          location: `rules.${file.filename}.${rule.id}`,
        });
      }
      const lint = lintRegex(rule.pattern);
      for (const f of lint.findings) {
        findings.push({ ...f, location: `rules.${file.filename}.${rule.id}` });
      }
    }
  }

  // Suppressions: warn on overly broad finding patterns.
  for (const supp of policy.suppressions.finding_suppressions) {
    if (
      !supp.finding_pattern ||
      supp.finding_pattern === '.*' ||
      supp.finding_pattern === '.+' ||
      supp.finding_pattern === '^.*$'
    ) {
      findings.push({
        level: 'warning',
        code: 'SUPP_OVER_BROAD',
        message: `Suppression "${supp.id || '(unnamed)'}" matches every finding. This will silence real signals.`,
        location: `suppressions.finding.${supp.id}`,
        fix: 'Scope the pattern to a finding ID prefix (e.g. ^SEC-AWS-) or specific judge category.',
      });
    }
  }
  for (const tool of policy.suppressions.tool_suppressions) {
    if (
      !tool.tool_pattern ||
      tool.tool_pattern === '.*' ||
      tool.tool_pattern === '.+' ||
      tool.tool_pattern === '^.*$'
    ) {
      findings.push({
        level: 'warning',
        code: 'SUPP_OVER_BROAD',
        message: `Tool suppression matches every tool. This will silence every finding on every tool.`,
        location: `suppressions.tool`,
        fix: 'Scope the regex (e.g. ^(shell|bash)\\.execute$).',
      });
    }
  }

  // Firewall: default-deny with no allow list is a footgun.
  if (
    policy.firewall.default_action === 'deny' &&
    policy.firewall.allowed_domains.length === 0
  ) {
    findings.push({
      level: 'warning',
      code: 'FIREWALL_DEFAULT_DENY_NO_ALLOW',
      message:
        'Firewall default is "deny" but no allowed_domains are configured. Every outbound call from a sandboxed plugin will fail.',
      location: 'firewall.default_action',
      fix: 'Either flip default_action to "allow" with an explicit blocked_destinations list, or add the domains your sandboxed code legitimately needs.',
    });
  }

  // Scanner overrides should not be looser than the base.
  for (const [scanner, overrides] of Object.entries(policy.scanner_overrides)) {
    if (!overrides) continue;
    for (const [sev, triple] of Object.entries(overrides)) {
      const base = policy.skill_actions[sev as keyof typeof policy.skill_actions];
      if (!triple || !base) continue;
      if (base.install === 'block' && triple.install !== 'block') {
        findings.push({
          level: 'warning',
          code: 'SCANNER_OVERRIDE_LOOSER',
          message: `Scanner "${scanner}" allows install at ${sev.toUpperCase()} even though base policy blocks it.`,
          location: `severity-matrix.${scanner}.${sev}.install`,
        });
      }
      if (base.runtime === 'disable' && triple.runtime !== 'disable') {
        findings.push({
          level: 'warning',
          code: 'SCANNER_OVERRIDE_LOOSER',
          message: `Scanner "${scanner}" leaves runtime enabled at ${sev.toUpperCase()} even though base policy disables it.`,
          location: `severity-matrix.${scanner}.${sev}.runtime`,
        });
      }
    }
  }

  // Webhook secrets should reference an env var, not be an inline
  // secret pasted into the form. We apply the same UPPER_SNAKE
  // anti-secret-paste lint as for cisco_ai_defense.api_key_env so a
  // paste-in-haste of "ghp_xxx…" into the secret_env field surfaces
  // an error before the operator downloads + installs the policy.
  for (const wh of policy.webhooks) {
    if (wh.enabled && !wh.secret_env) {
      findings.push({
        level: 'warning',
        code: 'WEBHOOK_SECRET_MISSING',
        message: `Webhook ${wh.url} is enabled but has no secret_env. Inbound deliveries can't be verified.`,
        location: 'webhooks',
        fix: 'Add the env-var name (e.g. SLACK_WEBHOOK_SECRET) so the dispatcher can sign requests.',
      });
    }
    if (wh.secret_env && !looksLikeEnvVarName(wh.secret_env)) {
      findings.push({
        level: 'error',
        code: 'ENV_NAME_LIKELY_SECRET',
        message: `Webhook ${wh.url}: secret_env value "${redactForUI(wh.secret_env)}" doesn't look like an env-var name. It looks like a literal secret pasted into the wrong field.`,
        location: 'webhooks',
        fix: 'Use UPPER_SNAKE_CASE matching [A-Z_][A-Z0-9_]+ — the dispatcher reads the actual secret from os.Getenv() at gateway boot.',
      });
    }
  }

  // Custom Rego must declare a package. We also scan the source for
  // tokens that look like inline secrets (API keys, bearer tokens,
  // PEM blocks); custom Rego is the most common place to accidentally
  // bake one in because operators paste sample test inputs into the
  // rule body during iteration and forget to redact before exporting.
  for (const snippet of policy.custom_rego) {
    if (!snippet.source.includes('package ')) {
      findings.push({
        level: 'error',
        code: 'CUSTOM_REGO_MISSING_PACKAGE',
        message: `Custom Rego snippet "${snippet.name}" must declare a "package defenseclaw.custom.<name>" line.`,
        location: `custom_rego.${snippet.name}`,
      });
    }
    const secretHit = scanForInlineSecret(snippet.source);
    if (secretHit) {
      findings.push({
        level: 'warning',
        code: 'CUSTOM_REGO_LIKELY_SECRET',
        message: `Custom Rego snippet "${snippet.name}" contains text that looks like an inline secret (${secretHit.kind}). Inline secrets land in YAML and get printed by "defenseclaw policy show".`,
        location: `custom_rego.${snippet.name}`,
        fix: 'Replace the literal with a data-driven check (e.g. compare input.token_prefix against a server-side allowlist) and never store the secret in the policy itself.',
      });
    }
  }

  // Session correlator: catch patterns that can never match (no
  // clauses on any of the three match modes), and reject impossible
  // window sizes. Disabled patterns are skipped so an operator
  // parking a draft doesn't drown in errors.
  const seenPatternIds = new Set<string>();
  for (const p of policy.correlator) {
    if (!p.enabled) continue;
    if (seenPatternIds.has(p.id)) {
      findings.push({
        level: 'error',
        code: 'ID_DUPLICATE',
        message: `Correlator pattern id "${p.id}" appears more than once. IDs are the join key for promoted CORR-* findings; duplicates collide in audit logs.`,
        location: `correlator.${p.id}`,
      });
    } else {
      seenPatternIds.add(p.id);
    }
    const allOf = p.all_of?.length ?? 0;
    const seq = p.sequence?.length ?? 0;
    const fp = p.fingerprint_chain?.length ?? 0;
    if (allOf + seq + fp === 0) {
      findings.push({
        level: 'error',
        code: 'CORRELATOR_PATTERN_EMPTY',
        message: `Correlator pattern "${p.id}" has no clauses on any match mode. It will never fire.`,
        location: `correlator.${p.id}`,
        fix: 'Add at least one clause under all_of, sequence, or fingerprint_chain — or disable the pattern.',
      });
    }
    if (!Number.isInteger(p.window_events) || p.window_events <= 0) {
      findings.push({
        level: 'error',
        code: 'CORRELATOR_WINDOW_INVALID',
        message: `Correlator pattern "${p.id}" has window_events=${p.window_events}. Must be a positive integer.`,
        location: `correlator.${p.id}.window_events`,
      });
    } else if (p.window_events > 1000) {
      findings.push({
        level: 'warning',
        code: 'CORRELATOR_WINDOW_INVALID',
        message: `Correlator pattern "${p.id}" window_events=${p.window_events} is very large. The session buffer caps at a few hundred findings; values above that effectively mean "the whole session".`,
        location: `correlator.${p.id}.window_events`,
      });
    }
  }

  // Cisco AI Defense: when the operator enables the lane, demand an
  // env-var-shaped reference (UPPER_SNAKE) — not a literal key value.
  // The wizard never accepts inline secrets, but a paste-in-haste can
  // smuggle one through if we don't lint here.
  const aid = policy.cisco_ai_defense;
  if (aid.enabled || aid.api_key_env || aid.endpoint) {
    if (!aid.api_key_env) {
      findings.push({
        level: 'warning',
        code: 'CISCO_AID_KEY_ENV_MISSING',
        message:
          'Cisco AI Defense block is populated but api_key_env is empty. The gateway will skip the AID lane silently until an env-var name is supplied.',
        location: 'cisco_ai_defense.api_key_env',
        fix: 'Set api_key_env to the env var the gateway should read (e.g. CISCO_AI_DEFENSE_API_KEY).',
      });
    } else if (!looksLikeEnvVarName(aid.api_key_env)) {
      // Prefer the secret-shape detector's message when it fires —
      // it's strictly more informative ("this looks like a real
      // OpenAI key" vs "this isn't UPPER_SNAKE").
      const secretHit = scanForInlineSecret(aid.api_key_env);
      if (secretHit) {
        findings.push({
          level: 'error',
          code: 'ENV_NAME_LIKELY_SECRET',
          message: `Cisco AI Defense api_key_env looks like an inline secret (${secretHit.kind}, masked as "${redactForUI(aid.api_key_env)}"). The wizard expects the NAME of the env var, not the value.`,
          location: 'cisco_ai_defense.api_key_env',
          fix: 'Use UPPER_SNAKE_CASE matching [A-Z_][A-Z0-9_]+ — the gateway reads the actual secret via os.Getenv() at boot.',
        });
      } else {
        findings.push({
          level: 'error',
          code: 'CISCO_AID_KEY_ENV_MISSING',
          message: `Cisco AI Defense api_key_env "${aid.api_key_env}" is not a valid env-var name. The wizard expects the NAME of the env var (e.g. CISCO_AI_DEFENSE_API_KEY), not the key value.`,
          location: 'cisco_ai_defense.api_key_env',
          fix: 'Use UPPER_SNAKE_CASE matching [A-Z_][A-Z0-9_]+ — the gateway looks up the actual secret via os.Getenv() at boot.',
        });
      }
    }
  }

  // --- "Risky configuration" warnings (D5) -------------------------------
  // These are operator-visible mistakes that pass schema validation
  // (everything's a legal value) but produce a policy that does
  // less than the operator expects. We tag them with RISKY_* codes
  // so the playground UI can pin them above the collapsed details
  // bar; they're warnings, not errors, so the operator can still
  // download the install script if they really mean it.

  if (
    policy.firewall.default_action === 'allow' &&
    Array.isArray(policy.firewall.blocked_destinations) &&
    policy.firewall.blocked_destinations.length === 0
  ) {
    findings.push({
      level: 'warning',
      code: 'RISKY_FIREWALL_DEFAULT_ALLOW',
      message:
        'Firewall is in default-allow mode with no explicit blocked_destinations. This means the firewall layer enforces nothing — every outbound destination is allowed. Most production deployments want default-deny with an explicit allow_list.',
      location: 'firewall.default_action',
      fix: "Switch to default_action: 'deny' and list the destinations you actually want to allow under allowed_domains, or document why default-allow is intended.",
    });
  }

  {
    const sa = policy.skill_actions ?? {};
    const sevs = ['critical', 'high', 'medium', 'low', 'info'] as const;
    const allRuntimeEnable = sevs.every(
      (s) => (sa[s]?.runtime ?? 'enable') === 'enable',
    );
    const allInstallNone = sevs.every(
      (s) => (sa[s]?.install ?? 'none') === 'none',
    );
    if (allRuntimeEnable && allInstallNone) {
      findings.push({
        level: 'warning',
        code: 'RISKY_ALL_ACTIONS_ALLOW',
        message:
          'Every severity tier in skill_actions allows runtime AND install with no quarantine. This effectively disables enforcement across the matrix — the gateway will scan but never block.',
        location: 'skill_actions',
        fix: 'Pick at least one (severity, surface) where action != allow/none. The "default" preset blocks runtime + install at HIGH and CRITICAL; that\'s a reasonable floor.',
      });
    }
  }

  for (const snippet of policy.custom_rego) {
    // Identity-allow Rego — `default allow := true` with no other
    // rules — is a footgun. We exempt the "canary" name we ship in
    // dump-install-script.ts so internal test fixtures don't trip
    // the lint. Production policies that genuinely intend a no-op
    // rule can suppress this by adding even a trivial guard like
    // `allow if {input.principal != "anyone"}`.
    if (
      /\bdefault\s+allow\s*:?=\s*true\b/.test(snippet.source) &&
      !/allow\s+(?:if|=)\s*\{/.test(snippet.source) &&
      snippet.name !== 'verify-canary'
    ) {
      findings.push({
        level: 'warning',
        code: 'RISKY_CUSTOM_REGO_IDENTITY_ALLOW',
        message: `Custom Rego snippet "${snippet.name}" sets default allow := true with no overriding rules. It always allows. If you intended a no-op, document that — if you intended to gate something, add at least one allow-if rule.`,
        location: `custom_rego.${snippet.name}`,
      });
    }
  }

  // Mismatched judge / threshold expectation: every judge disabled
  // but the block_threshold suggests the operator still expects
  // judgments to escalate. Most likely a partial config where the
  // operator turned off the judges but forgot to lower
  // block_threshold accordingly.
  if (
    policy.guardrail?.block_threshold !== undefined &&
    policy.guardrail.block_threshold > 0 &&
    Array.isArray(policy.judges) &&
    policy.judges.length > 0 &&
    policy.judges.every((j) => !j.enabled)
  ) {
    findings.push({
      level: 'warning',
      code: 'RISKY_JUDGE_THRESHOLD_MISMATCH',
      message: `guardrail.block_threshold=${policy.guardrail.block_threshold} expects the LLM judges to contribute verdicts, but every judge in policy.judges is disabled. The threshold will only ever be reached by deterministic scanners.`,
      location: 'guardrail.block_threshold',
      fix: 'Either enable at least one judge or document that the threshold is set assuming deterministic-scanner verdicts only.',
    });
  }

  if (Array.isArray(policy.correlator) && policy.correlator.length > 0) {
    const enabledCount = policy.correlator.filter((p) => p.enabled).length;
    if (enabledCount === 0) {
      findings.push({
        level: 'warning',
        code: 'RISKY_CORRELATOR_ALL_DISABLED',
        message: `${policy.correlator.length} session-correlator pattern${policy.correlator.length === 1 ? ' is' : 's are'} configured but every one is disabled. Layer 5 (session correlator) will not fire on this policy.`,
        location: 'correlator',
        fix: 'Enable at least one pattern or remove the disabled set to keep the policy minimal.',
      });
    }
  }

  return findings;
}

/** Codes that should appear in the pinned "risky configuration"
 *  banner rather than only in the expanded validator details. Used
 *  by the Playground header to surface high-impact misconfigurations
 *  the operator might otherwise miss. */
export const RISKY_CONFIG_CODES: ReadonlySet<ValidationCode> = new Set([
  'RISKY_FIREWALL_DEFAULT_ALLOW',
  'RISKY_ALL_ACTIONS_ALLOW',
  'RISKY_CUSTOM_REGO_IDENTITY_ALLOW',
  'RISKY_JUDGE_THRESHOLD_MISMATCH',
  'RISKY_CORRELATOR_ALL_DISABLED',
]);

/** Helper: count findings by level. */
export function summarize(findings: ValidationFinding[]): {
  errors: number;
  warnings: number;
  info: number;
} {
  return findings.reduce(
    (acc, f) => {
      if (f.level === 'error') acc.errors += 1;
      else if (f.level === 'warning') acc.warnings += 1;
      else acc.info += 1;
      return acc;
    },
    { errors: 0, warnings: 0, info: 0 },
  );
}

/** Suggest a unique id by appending a numeric suffix. */
export function uniqueRuleId(base: string, taken: Set<string>): string {
  if (!taken.has(base)) return base;
  let i = 2;
  while (taken.has(`${base}-${i}`)) i += 1;
  return `${base}-${i}`;
}

// Re-export the rule type for the regex-input component's convenience.
export type { RuleDef, ValidationCode };
